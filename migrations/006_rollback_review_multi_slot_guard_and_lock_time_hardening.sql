-- migrations/006_rollback_review_multi_slot_guard_and_lock_time_hardening.sql
-- Rollback for Migration 006: Khôi phục RLS Policy danhgia và RPC create_booking về trạng thái Migration 005.
-- Bảo đảm không làm mất hoặc xóa bất kỳ dữ liệu booking, sân hay đánh giá hiện hữu nào.

-- 1. Khôi phục RLS Policy danhgia_insert về Migration 005
DROP POLICY IF EXISTS danhgia_insert ON public.danhgia;
CREATE POLICY danhgia_insert ON public.danhgia FOR INSERT TO authenticated
WITH CHECK (
  makhachhang = (SELECT public.current_nguoidung_id())
  AND EXISTS (
    SELECT 1 FROM public.datsan d
    JOIN public.datsan_khunggio dk ON dk.madatsan = d.madatsan
    JOIN public.khunggio kg ON kg.makhunggio = dk.makhunggio
    WHERE d.madatsan = danhgia.madatsan
      AND d.makhachhang = (SELECT public.current_nguoidung_id())
      AND UPPER(COALESCE(d.trangthai, '')) IN ('HOAN_THANH', 'HOANTHANH')
      AND (d.ngaysudung + kg.gioketthuc) <= ((now() AT TIME ZONE 'Asia/Ho_Chi_Minh'))
      AND UPPER(COALESCE(d.trangthai, '')) NOT IN ('DAHUY', 'DA_HUY', 'HUY', 'TU_CHOI')
  )
);

-- 2. Khôi phục RPC create_booking về phiên bản Migration 005
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
  v_now_vn timestamp := (now() AT TIME ZONE 'Asia/Ho_Chi_Minh');
  v_today_vn date := v_now_vn::date;
  v_time_vn time := v_now_vn::time;
  v_min_start time;
  v_max_end time;
BEGIN
  IF v_profile_id IS NULL OR v_role NOT IN ('KHACHHANG', 'CHUSAN', 'ADMIN') THEN
    RAISE EXCEPTION 'A linked customer account is required to book a field' USING errcode = '42501';
  END IF;

  -- TASK 01: Chặn ngày quá khứ
  IF p_ngaysudung < v_today_vn OR coalesce(array_length(p_makhunggio, 1), 0) = 0 THEN
    RAISE EXCEPTION 'Không thể đặt sân trong ngày quá khứ. Vui lòng chọn ngày hợp lệ.' USING errcode = '22023';
  END IF;

  -- TASK 01: Nếu đặt cho ngày hôm nay, mọi khung giờ phải có giobatdau > thời gian hiện tại
  IF p_ngaysudung = v_today_vn THEN
    IF EXISTS (
      SELECT 1 FROM public.khunggio kg
      WHERE kg.masan = p_masan
        AND kg.makhunggio = ANY(p_makhunggio)
        AND kg.giobatdau <= v_time_vn
    ) THEN
      RAISE EXCEPTION 'Khung giờ đặt sân đã qua hoặc đang diễn ra. Chỉ được đặt khung giờ có thời gian bắt đầu lớn hơn thời gian hiện tại.' USING errcode = '22023';
    END IF;
  END IF;

  IF (SELECT count(DISTINCT id) FROM unnest(p_makhunggio) AS id) <> array_length(p_makhunggio, 1) THEN
    RAISE EXCEPTION 'Duplicate time slots are not allowed' USING errcode = '22023';
  END IF;

  SELECT s.machusan, coalesce(s.giacoban, 0), coalesce(l.tenloaisan, '')
  INTO v_owner_id, v_rate, v_sport
  FROM public.san s
  LEFT JOIN public.loaisan l ON l.maloaisan = s.maloaisan
  WHERE s.masan = p_masan AND upper(coalesce(s.trangthai, 'HOATDONG')) = 'HOATDONG';

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
    sum(coalesce(nullif(kg.giatien, 0), round(v_rate * extract(epoch from
      (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau
        else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600)))::numeric,
    sum(extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau
      else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600)::numeric,
    min(kg.giobatdau),
    max(kg.gioketthuc)
  INTO v_base_total, v_hours, v_min_start, v_max_end
  FROM public.khunggio kg
  WHERE kg.masan = p_masan AND kg.makhunggio = ANY(p_makhunggio)
    AND upper(coalesce(kg.trangthai, 'HOATDONG')) IN ('HOATDONG', 'TRONG');

  IF v_base_total IS NULL OR (
    SELECT count(*) FROM public.khunggio kg
    WHERE kg.masan = p_masan AND kg.makhunggio = ANY(p_makhunggio)
      AND upper(coalesce(kg.trangthai, 'HOATDONG')) IN ('HOATDONG', 'TRONG')
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
    makhachhang, masan, ngaydat, ngaysudung, giobatdau, gioketthuc, tongtien, tiencoc, trangthai, ghichu
  )
  VALUES (
    v_profile_id, p_masan, v_today_vn, p_ngaysudung, v_min_start, v_max_end, v_total, 0, 'CHOXACNHAN',
    CASE WHEN p_dichvu IS NOT NULL AND p_dichvu <> '{}'::jsonb THEN 'Dịch vụ: ' || p_dichvu::text ELSE NULL END
  )
  RETURNING madatsan INTO v_booking_id;

  INSERT INTO public.datsan_khunggio (madatsan, makhunggio, giatien)
  SELECT
    v_booking_id, kg.makhunggio,
    coalesce(nullif(kg.giatien, 0), round(v_rate * extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau
      else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600))
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

-- Làm mới PostgREST schema cache
NOTIFY pgrst, 'reload schema';
