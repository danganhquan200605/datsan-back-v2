-- migrations/production_005_006_combined.sql
-- Production-specific migration combining 005 & 006 hardening features
-- Adapts to Production schema: san.giasan, khunggio without giatien, datsan without giobatdau/gioketthuc/tiencoc
-- datsan_khunggio(madatsan, makhunggio, giaapdung, giadat), danhgia without masan

-- =====================================================================
-- 0. VERIFY PRODUCTION ENVIRONMENT (SAFETY GATE)
-- =====================================================================
-- This migration is designed for Production schema (ckrmfyuymuvaiymfxvhj)
-- DO NOT run on Staging (fllbhjovifmzyfjubifx)

-- 1. Thêm Unique Index chống đánh giá trùng lặp cho mỗi đơn đặt sân
CREATE UNIQUE INDEX IF NOT EXISTS idx_danhgia_madatsan_unique ON public.danhgia(madatsan);

-- 2. CẬP NHẬT RLS POLICY cho bảng danhgia
-- Bảo vệ đa khung giờ: TẤT CẢ khung giờ phải kết thúc trước khi cho đánh giá
-- Production danhgia không có cột masan
DROP POLICY IF EXISTS danhgia_insert ON public.danhgia;
CREATE POLICY danhgia_insert ON public.danhgia FOR INSERT TO authenticated
WITH CHECK (
  makhachhang = (SELECT public.current_nguoidung_id())
  AND EXISTS (
    SELECT 1 FROM public.datsan d
    WHERE d.madatsan = danhgia.madatsan
      AND d.makhachhang = (SELECT public.current_nguoidung_id())
      AND UPPER(COALESCE(d.trangthai, '')) IN ('HOAN_THANH', 'HOANTHANH')
      AND UPPER(COALESCE(d.trangthai, '')) NOT IN ('DAHUY', 'DA_HUY', 'HUY', 'TU_CHOI')
      -- Đơn phải có ít nhất 1 khung giờ liên kết
      AND EXISTS (
        SELECT 1 FROM public.datsan_khunggio dk
        WHERE dk.madatsan = d.madatsan
      )
      -- BẢO VỆ ĐA KHUNG GIỜ: KHÔNG CÓ BẤT KỲ khung giờ nào chưa kết thúc
      AND NOT EXISTS (
        SELECT 1 FROM public.datsan_khunggio dk
        JOIN public.khunggio kg ON kg.makhunggio = dk.makhunggio
        WHERE dk.madatsan = d.madatsan
          AND (d.ngaysudung + kg.gioketthuc) > (clock_timestamp() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      )
  )
);

-- Giữ nguyên RLS read policy hiện có (nếu có)
DROP POLICY IF EXISTS danhgia_read ON public.danhgia;
CREATE POLICY danhgia_read ON public.danhgia FOR SELECT TO authenticated
USING (
  makhachhang = (SELECT public.current_nguoidung_id()) 
  OR (SELECT public.current_nguoidung_role()) = 'ADMIN'
  OR EXISTS (
    SELECT 1 FROM public.datsan d
    JOIN public.san s ON s.masan = d.masan
    WHERE d.madatsan = danhgia.madatsan
      AND s.machusan = (SELECT public.current_nguoidung_id())
  )
);

-- RLS cho thanhtoan (giữ nguyên read policy)
DROP POLICY IF EXISTS thanhtoan_read ON public.thanhtoan;
CREATE POLICY thanhtoan_read ON public.thanhtoan FOR SELECT TO authenticated
USING (
  EXISTS (
    SELECT 1 FROM public.datsan d
    WHERE d.madatsan = thanhtoan.madatsan
      AND (
        d.makhachhang = (SELECT public.current_nguoidung_id())
        OR EXISTS (
          SELECT 1 FROM public.san s
          WHERE s.masan = d.masan AND s.machusan = (SELECT public.current_nguoidung_id())
        )
        OR (SELECT public.current_nguoidung_role()) = 'ADMIN'
      )
  )
);

-- GRANT quyền
GRANT SELECT, INSERT ON public.danhgia TO authenticated;
GRANT ALL ON public.danhgia TO postgres, service_role;
GRANT SELECT ON public.thanhtoan TO authenticated;
GRANT ALL ON public.thanhtoan TO postgres, service_role;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'danhgia_madanhgia_seq') THEN
    GRANT USAGE, SELECT ON SEQUENCE public.danhgia_madanhgia_seq TO authenticated;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'thanhtoan_mathanhtoan_seq') THEN
    GRANT USAGE, SELECT ON SEQUENCE public.thanhtoan_mathanhtoan_seq TO authenticated;
  END IF;
END $$;

-- =====================================================================
-- 3. CẬP NHẬT RPC CREATE_BOOKING CHO PRODUCTION
-- Production schema:
--   san: giasan (not giacoban)
--   khunggio: NO giatien, trangthai='TRONG'
--   datsan: NO giobatdau, gioketthuc, tiencoc, created_at, updated_at
--   datsan_khunggio: (madatsan, makhunggio, giaapdung, giadat)
-- =====================================================================
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

  -- Pre-lock and Post-lock clock times (Asia/Ho_Chi_Minh UTC+7)
  v_now_pre timestamp := (clock_timestamp() AT TIME ZONE 'Asia/Ho_Chi_Minh');
  v_today_pre date := v_now_pre::date;
  v_time_pre time := v_now_pre::time;

  v_now_post timestamp;
  v_today_post date;
  v_time_post time;
BEGIN
  IF v_profile_id IS NULL OR v_role NOT IN ('KHACHHANG', 'CHUSAN', 'ADMIN') THEN
    RAISE EXCEPTION 'A linked customer account is required to book a field' USING errcode = '42501';
  END IF;

  -- 1. PRE-LOCK FAST GUARD: Chặn ngày quá khứ
  IF p_ngaysudung < v_today_pre OR coalesce(array_length(p_makhunggio, 1), 0) = 0 THEN
    RAISE EXCEPTION 'Không thể đặt sân trong ngày quá khứ. Vui lòng chọn ngày hợp lệ.' USING errcode = '22023';
  END IF;

  -- 1. PRE-LOCK: Chặn slot bắt đầu <= thời gian hiện tại (đặt cho hôm nay)
  IF p_ngaysudung = v_today_pre THEN
    IF EXISTS (
      SELECT 1 FROM public.khunggio kg
      WHERE kg.masan = p_masan
        AND kg.makhunggio = ANY(p_makhunggio)
        AND kg.giobatdau <= v_time_pre
    ) THEN
      RAISE EXCEPTION 'Khung giờ đặt sân đã qua hoặc đang diễn ra. Chỉ được đặt khung giờ có thời gian bắt đầu lớn hơn thời gian hiện tại.' USING errcode = '22023';
    END IF;
  END IF;

  IF (SELECT count(DISTINCT id) FROM unnest(p_makhunggio) AS id) <> array_length(p_makhunggio, 1) THEN
    RAISE EXCEPTION 'Duplicate time slots are not allowed' USING errcode = '22023';
  END IF;

  -- Production: san.giasan (not giacoban), loaisan
  SELECT s.machusan, coalesce(s.giasan, 0), coalesce(l.tenloaisan, '')
  INTO v_owner_id, v_rate, v_sport
  FROM public.san s
  LEFT JOIN public.loaisan l ON l.maloaisan = s.maloaisan
  WHERE s.masan = p_masan AND upper(coalesce(s.trangthai, 'HOATDONG')) IN ('HOATDONG', 'TRONG');

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

  -- 2. ACQUIRE ADVISORY LOCKS (theo thứ tự ID tăng dần để ngăn deadlock)
  FOR v_slot IN SELECT unnest(p_makhunggio) AS id ORDER BY id LOOP
    PERFORM pg_advisory_xact_lock(hashtextextended(format('%s:%s:%s', p_masan, p_ngaysudung, v_slot.id), 0));
  END LOOP;

  -- 3. POST-LOCK TIME GUARD: Đọc lại đồng hồ thực tế sau khi lấy được lock
  v_now_post := (clock_timestamp() AT TIME ZONE 'Asia/Ho_Chi_Minh');
  v_today_post := v_now_post::date;
  v_time_post := v_now_post::time;

  IF p_ngaysudung < v_today_post THEN
    RAISE EXCEPTION 'Không thể đặt sân trong ngày quá khứ. Vui lòng chọn ngày hợp lệ.' USING errcode = '22023';
  END IF;

  IF p_ngaysudung = v_today_post THEN
    IF EXISTS (
      SELECT 1 FROM public.khunggio kg
      WHERE kg.masan = p_masan
        AND kg.makhunggio = ANY(p_makhunggio)
        AND kg.giobatdau <= v_time_post
    ) THEN
      RAISE EXCEPTION 'Khung giờ đặt sân đã bắt đầu trong thời gian chờ khóa giao dịch. Không thể tiếp tục đặt khung giờ này.' USING errcode = '22023';
    END IF;
  END IF;

  -- 4. CONFLICT GUARD: Kiểm tra slot chưa bị đặt
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

  -- 5. SLOT CALCULATION
  -- Production khunggio has NO giatien, so use san.giasan as hourly rate
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

  -- 6. INSERT BOOKING
  -- Production datsan: NO giobatdau, gioketthuc, tiencoc, created_at, updated_at
  INSERT INTO public.datsan (
    makhachhang, masan, ngaydat, ngaysudung, tongtien, trangthai, ghichu
  )
  VALUES (
    v_profile_id, p_masan, v_today_post, p_ngaysudung, v_total, 'CHOXACNHAN',
    CASE WHEN p_dichvu IS NOT NULL AND p_dichvu <> '{}'::jsonb THEN 'Dịch vụ: ' || p_dichvu::text ELSE NULL END
  )
  RETURNING madatsan INTO v_booking_id;

  -- 7. INSERT SLOT LINKS
  -- Production datsan_khunggio: (madatsan, makhunggio, giaapdung, giadat)
  INSERT INTO public.datsan_khunggio (madatsan, makhunggio, giaapdung, giadat)
  SELECT
    v_booking_id, kg.makhunggio,
    round(v_rate * extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau
      else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600),
    round(v_rate * extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau
      else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600)
  FROM public.khunggio kg
  WHERE kg.masan = p_masan AND kg.makhunggio = ANY(p_makhunggio);

  -- 8. INSERT PAYMENT RECORD
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
