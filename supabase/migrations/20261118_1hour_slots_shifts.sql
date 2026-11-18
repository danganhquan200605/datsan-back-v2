-- Migration: 20261118_1hour_slots_shifts.sql
-- Description:
-- 1. Adds ghichu, giadat, phuongthucthanhtoan columns for backwards-compatibility.
-- 2. Seeds 14 1-hour slots (07:00 - 23:00) per field for all 20 fields.
-- 3. Updates create_booking and get_public_availability RPCs.

-- 1. Table Alterations
ALTER TABLE public.datsan ADD COLUMN IF NOT EXISTS ghichu TEXT;
ALTER TABLE public.datsan_khunggio ADD COLUMN IF NOT EXISTS giadat NUMERIC;
ALTER TABLE public.thanhtoan ADD COLUMN IF NOT EXISTS phuongthucthanhtoan VARCHAR;

-- 2. Seed 14 1-hour slots per field
DELETE FROM public.thanhtoan;
DELETE FROM public.datsan_khunggio;
DELETE FROM public.datsan;
DELETE FROM public.khunggio;

DO $$
DECLARE
  v_masan INT;
  v_slots TIME[][] := ARRAY[
    [TIME '07:00:00', TIME '08:00:00'],
    [TIME '08:00:00', TIME '09:00:00'],
    [TIME '09:00:00', TIME '10:00:00'],
    [TIME '10:00:00', TIME '11:00:00'],
    [TIME '13:00:00', TIME '14:00:00'],
    [TIME '14:00:00', TIME '15:00:00'],
    [TIME '15:00:00', TIME '16:00:00'],
    [TIME '16:00:00', TIME '17:00:00'],
    [TIME '17:00:00', TIME '18:00:00'],
    [TIME '18:00:00', TIME '19:00:00'],
    [TIME '19:00:00', TIME '20:00:00'],
    [TIME '20:00:00', TIME '21:00:00'],
    [TIME '21:00:00', TIME '22:00:00'],
    [TIME '22:00:00', TIME '23:00:00']
  ];
  i INT;
BEGIN
  FOR v_masan IN SELECT masan FROM public.san ORDER BY masan LOOP
    FOR i IN 1..14 LOOP
      INSERT INTO public.khunggio (masan, giobatdau, gioketthuc, trangthai)
      VALUES (v_masan, v_slots[i][1], v_slots[i][2], 'TRONG');
    END LOOP;
  END LOOP;
END $$;

-- 3. create_booking RPC
CREATE OR REPLACE FUNCTION public.create_booking(
  p_masan integer,
  p_ngaysudung date,
  p_makhunggio integer[],
  p_dichvu jsonb DEFAULT '{}'::jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_profile_id integer := public.current_nguoidung_id();
  v_role text := public.current_nguoidung_role();
  v_owner_id integer;
  v_rate numeric;
  v_sport text;
  v_football boolean;
  v_badminton boolean;
  v_tennis boolean;
  v_pickleball boolean;
  v_water boolean := coalesce((p_dichvu ->> 'water')::boolean, false);
  v_bibs boolean := coalesce((p_dichvu ->> 'bibs')::boolean, false);
  v_racket_badminton boolean := coalesce((p_dichvu ->> 'racketBadminton')::boolean, false);
  v_shuttlecock boolean := coalesce((p_dichvu ->> 'shuttlecock')::boolean, false);
  v_racket_tennis boolean := coalesce((p_dichvu ->> 'racketTennis')::boolean, false);
  v_hours numeric;
  v_base_total numeric;
  v_extra_total numeric := 0;
  v_total numeric;
  v_booking_id integer;
  v_slot record;
BEGIN
  IF v_profile_id IS NULL OR v_role NOT IN ('KHACHHANG', 'CHUSAN', 'ADMIN') THEN
    RAISE EXCEPTION 'A linked customer account is required to book a field' USING errcode = '42501';
  END IF;

  IF p_ngaysudung < current_date OR coalesce(array_length(p_makhunggio, 1), 0) = 0 THEN
    RAISE EXCEPTION 'Choose a future date and at least one time slot' USING errcode = '22023';
  END IF;

  IF (SELECT count(DISTINCT id) FROM unnest(p_makhunggio) AS id) <> array_length(p_makhunggio, 1) THEN
    RAISE EXCEPTION 'Duplicate time slots are not allowed' USING errcode = '22023';
  END IF;

  SELECT s.machusan, s.giasan, coalesce(l.tenloaisan, '')
  INTO v_owner_id, v_rate, v_sport
  FROM public.san s
  LEFT JOIN public.loaisan l ON l.maloaisan = s.maloaisan
  WHERE s.masan = p_masan AND s.trangthai = 'HOATDONG';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Field is not available' USING errcode = '02000';
  END IF;

  IF v_owner_id = v_profile_id THEN
    RAISE EXCEPTION 'You cannot book your own field' USING errcode = '42501';
  END IF;

  v_football := v_sport ILIKE '%bóng đá%' OR v_sport ILIKE '%bong da%' OR v_sport ILIKE '%football%';
  v_badminton := v_sport ILIKE '%cầu lông%' OR v_sport ILIKE '%cau long%' OR v_sport ILIKE '%badminton%';
  v_tennis := v_sport ILIKE '%tennis%';
  v_pickleball := v_sport ILIKE '%pickleball%';

  IF (v_bibs AND NOT v_football) OR ((v_racket_badminton OR v_shuttlecock) AND NOT v_badminton) OR (v_racket_tennis AND NOT v_tennis) THEN
    RAISE EXCEPTION 'Selected equipment does not match this sport' USING errcode = '22023';
  END IF;

  FOR v_slot IN SELECT unnest(p_makhunggio) AS id ORDER BY id LOOP
    PERFORM pg_advisory_xact_lock(hashtextextended(format('%s:%s:%s', p_masan, p_ngaysudung, v_slot.id), 0));
  END LOOP;

  IF EXISTS (
    SELECT 1 FROM public.datsan d
    JOIN public.datsan_khunggio dk ON dk.madatsan = d.madatsan
    WHERE d.masan = p_masan
      AND d.ngaysudung = p_ngaysudung
      AND dk.makhunggio = ANY(p_makhunggio)
      AND upper(coalesce(d.trangthai, '')) NOT IN ('DAHUY', 'DA_HUY', 'HUY', 'TU_CHOI')
  ) THEN
    RAISE EXCEPTION 'One or more selected slots have just been booked' USING errcode = '23P01';
  END IF;

  SELECT
    sum(round(v_rate * extract(epoch from
      (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau
        else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600))::numeric,
    sum(extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau
      else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600)::numeric
  INTO v_base_total, v_hours
  FROM public.khunggio kg
  WHERE kg.masan = p_masan AND kg.makhunggio = ANY(p_makhunggio)
    AND upper(coalesce(kg.trangthai, 'TRONG')) = 'TRONG';

  IF v_base_total IS NULL OR (
    SELECT count(*) FROM public.khunggio kg
    WHERE kg.masan = p_masan AND kg.makhunggio = ANY(p_makhunggio)
      AND upper(coalesce(kg.trangthai, 'TRONG')) = 'TRONG'
  ) <> array_length(p_makhunggio, 1) THEN
    RAISE EXCEPTION 'A selected slot does not belong to this field or is not available' USING errcode = '22023';
  END IF;

  IF v_water THEN v_extra_total := v_extra_total + CASE WHEN v_football OR v_pickleball THEN 150000 ELSE 90000 END; END IF;
  IF v_bibs THEN v_extra_total := v_extra_total + 50000; END IF;
  IF v_racket_badminton THEN v_extra_total := v_extra_total + 80000 * v_hours; END IF;
  IF v_shuttlecock THEN v_extra_total := v_extra_total + 250000; END IF;
  IF v_racket_tennis THEN v_extra_total := v_extra_total + 100000 * v_hours; END IF;

  v_total := v_base_total + v_extra_total;

  INSERT INTO public.datsan (
    makhachhang, masan, ngaydat, ngaysudung, tongtien, trangthai, ghichu
  )
  VALUES (
    v_profile_id, p_masan, clock_timestamp(), p_ngaysudung, v_total, 'CHOXACNHAN',
    CASE WHEN p_dichvu IS NOT NULL AND p_dichvu <> '{}'::jsonb THEN 'Dịch vụ: ' || p_dichvu::text ELSE NULL END
  )
  RETURNING madatsan INTO v_booking_id;

  INSERT INTO public.datsan_khunggio (madatsan, makhunggio, giaapdung, giadat)
  SELECT
    v_booking_id, kg.makhunggio,
    round(v_rate * extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau
      else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600),
    round(v_rate * extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau
      else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600)
  FROM public.khunggio kg
  WHERE kg.masan = p_masan AND kg.makhunggio = ANY(p_makhunggio);

  INSERT INTO public.thanhtoan (madatsan, phuongthuc, phuongthucthanhtoan, sotien, trangthai)
  VALUES (v_booking_id, 'TIEN_MAT', 'TIEN_MAT', v_total, 'CHO_THANH_TOAN');

  RETURN jsonb_build_object(
    'madatsan', v_booking_id,
    'booking_id', v_booking_id,
    'tongtien', v_total,
    'total_amount', v_total,
    'base_amount', v_base_total,
    'extra_amount', v_extra_total,
    'status', 'CHOXACNHAN',
    'success', true
  );
END;
$$;

REVOKE ALL ON FUNCTION public.create_booking(integer, date, integer[], jsonb) FROM public, anon;
GRANT EXECUTE ON FUNCTION public.create_booking(integer, date, integer[], jsonb) TO authenticated;

-- 4. get_public_availability RPC
CREATE OR REPLACE FUNCTION public.get_public_availability(p_date date, p_masan integer DEFAULT null)
RETURNS TABLE (masan integer, ngaysudung date, trangthai text, makhunggio integer)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT d.masan, d.ngaysudung, coalesce(d.trangthai, ''), dk.makhunggio
  FROM public.datsan d
  JOIN public.datsan_khunggio dk ON dk.madatsan = d.madatsan
  JOIN public.san s ON s.masan = d.masan AND s.trangthai = 'HOATDONG'
  WHERE d.ngaysudung = p_date
    AND (p_masan IS NULL OR d.masan = p_masan)
    AND upper(coalesce(d.trangthai, '')) NOT IN ('DAHUY', 'DA_HUY', 'HUY', 'TU_CHOI');
$$;

REVOKE ALL ON FUNCTION public.get_public_availability(date, integer) FROM public;
GRANT EXECUTE ON FUNCTION public.get_public_availability(date, integer) TO anon, authenticated;

-- 5. Reload Schema
NOTIFY pgrst, 'reload schema';
