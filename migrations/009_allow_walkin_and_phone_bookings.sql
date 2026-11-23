-- ============================================================================
-- DATSANONLINE — MIGRATION 009: ALLOW WALKIN / PHONE BOOKINGS & ATOMIC OPERATIONS
-- ============================================================================

-- 1. Cho phép makhachhang có giá trị NULL cho đơn đặt qua điện thoại / khách vãng lai
ALTER TABLE public.datsan ALTER COLUMN makhachhang DROP NOT NULL;

-- 2. Thêm cột metadata JSONB cho bảng thongbao để hỗ trợ deep linking
ALTER TABLE public.thongbao ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;

-- 3. Tạo index hỗ trợ tìm kiếm metadata và makhachhang
CREATE INDEX IF NOT EXISTS idx_datsan_makhachhang ON public.datsan(makhachhang);
CREATE INDEX IF NOT EXISTS idx_thongbao_metadata ON public.thongbao USING gin (metadata);

-- ============================================================================
-- 4. RPC CREATE_PHONE_BOOKING: ĐẶT SÂN QUA ĐIỆN THOẠI ATOMIC & CHỐNG XUNG ĐỘT
-- ============================================================================
CREATE OR REPLACE FUNCTION public.create_phone_booking(
  p_masan INT,
  p_ngaysudung DATE,
  p_makhunggio INT[],
  p_customer_name TEXT,
  p_customer_phone TEXT,
  p_note TEXT DEFAULT '',
  p_caller_id INT DEFAULT NULL,
  p_caller_role TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_caller_id INT := coalesce(p_caller_id, public.current_nguoidung_id());
  v_caller_role TEXT := coalesce(p_caller_role, public.current_nguoidung_role());
  v_court_owner INT;
  v_court_name TEXT;
  v_rate NUMERIC := 0;
  v_has_giasan BOOLEAN := false;
  v_has_giaapdung BOOLEAN := false;
  v_slot_count INT;
  v_slot RECORD;
  v_total_minutes INT := 0;
  v_base_total NUMERIC := 0;
  v_total NUMERIC := 0;
  v_booking_id INT;
  v_makhachhang INT := NULL;
  v_clean_phone TEXT;
  v_std_phone TEXT;
  v_meta JSONB;
  v_now_vn TIMESTAMP := (clock_timestamp() AT TIME ZONE 'Asia/Ho_Chi_Minh');
  v_today_vn DATE := v_now_vn::DATE;
  v_time_vn TIME := v_now_vn::TIME;
BEGIN
  -- 1. Quyền gọi: Phải là CHUSAN hoặc ADMIN
  IF v_caller_role NOT IN ('CHUSAN', 'ADMIN') THEN
    RAISE EXCEPTION 'Chỉ chủ sân hoặc quản trị viên mới có quyền tạo đơn đặt sân qua điện thoại.' USING errcode = '42501';
  END IF;

  -- 2. Kiểm tra tính hợp lệ cơ bản
  IF p_masan IS NULL OR p_masan <= 0 THEN
    RAISE EXCEPTION 'Mã sân không hợp lệ.' USING errcode = '22023';
  END IF;
  v_slot_count := coalesce(array_length(p_makhunggio, 1), 0);
  IF v_slot_count = 0 OR v_slot_count > 14 THEN
    RAISE EXCEPTION 'Vui lòng chọn từ 1 đến 14 khung giờ thi đấu.' USING errcode = '22023';
  END IF;
  IF (SELECT count(DISTINCT id) FROM unnest(p_makhunggio) AS id) <> v_slot_count THEN
    RAISE EXCEPTION 'Khung giờ thi đấu không được trùng lặp.' USING errcode = '22023';
  END IF;
  IF p_customer_name IS NULL OR length(trim(p_customer_name)) < 2 THEN
    RAISE EXCEPTION 'Vui lòng nhập họ tên khách hàng (tối thiểu 2 ký tự).' USING errcode = '22023';
  END IF;
  v_clean_phone := regexp_replace(p_customer_phone, '[\s.-]', '', 'g');
  IF NOT (v_clean_phone ~ '^(0|\+84)[35789][0-9]{8}$') THEN
    RAISE EXCEPTION 'Số điện thoại khách hàng không đúng định dạng Việt Nam.' USING errcode = '22023';
  END IF;
  v_std_phone := CASE WHEN v_clean_phone LIKE '+84%' THEN '0' || substring(v_clean_phone FROM 4) ELSE v_clean_phone END;

  -- 3. Kiểm tra ngày không nằm trong quá khứ
  IF p_ngaysudung < v_today_vn THEN
    RAISE EXCEPTION 'Không thể tạo đơn đặt sân trong ngày quá khứ.' USING errcode = '22023';
  END IF;

  -- 4. Kiểm tra sự tồn tại và quyền sở hữu sân (hỗ trợ cả giasan và giacoban)
  SELECT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'san' AND column_name = 'giasan'
  ) INTO v_has_giasan;

  IF v_has_giasan THEN
    EXECUTE 'SELECT machusan, tensan, coalesce(giasan, 0) FROM public.san WHERE masan = $1'
      INTO v_court_owner, v_court_name, v_rate USING p_masan;
  ELSE
    EXECUTE 'SELECT machusan, tensan, coalesce(giacoban, 0) FROM public.san WHERE masan = $1'
      INTO v_court_owner, v_court_name, v_rate USING p_masan;
  END IF;

  IF v_court_name IS NULL THEN
    RAISE EXCEPTION 'Không tìm thấy thông tin sân thể thao.' USING errcode = '02000';
  END IF;
  IF v_caller_role <> 'ADMIN' AND v_court_owner <> v_caller_id THEN
    RAISE EXCEPTION 'Bạn chỉ có quyền tạo đơn cho sân thuộc quyền quản lý của mình.' USING errcode = '42501';
  END IF;
  IF v_rate <= 0 THEN
    RAISE EXCEPTION 'Giá thuê sân chưa được cấu hình hợp lệ trên hệ thống.' USING errcode = '22023';
  END IF;

  -- 5. ACQUIRE TRANSACTION ADVISORY LOCKS (theo thứ tự slot id tăng dần để chống deadlock)
  FOR v_slot IN SELECT unnest(p_makhunggio) AS id ORDER BY id LOOP
    PERFORM pg_advisory_xact_lock(hashtextextended(format('%s:%s:%s', p_masan, p_ngaysudung, v_slot.id), 0));
  END LOOP;

  -- 6. Sau khi lấy được lock: Kiểm tra khung giờ quá khứ nếu là hôm nay
  IF p_ngaysudung = v_today_vn THEN
    IF EXISTS (
      SELECT 1 FROM public.khunggio kg
      WHERE kg.masan = p_masan
        AND kg.makhunggio = ANY(p_makhunggio)
        AND kg.giobatdau <= v_time_vn
    ) THEN
      RAISE EXCEPTION 'Khung giờ đặt sân đã qua hoặc đang diễn ra. Chỉ được đặt khung giờ có thời gian bắt đầu trong tương lai.' USING errcode = '22023';
    END IF;
  END IF;

  -- 7. CONFLICT GUARD: Kiểm tra slot chưa bị đặt
  IF EXISTS (
    SELECT 1 FROM public.datsan d
    JOIN public.datsan_khunggio dk ON dk.madatsan = d.madatsan
    WHERE d.masan = p_masan
      AND d.ngaysudung = p_ngaysudung
      AND dk.makhunggio = ANY(p_makhunggio)
      AND upper(coalesce(d.trangthai, '')) NOT IN ('DAHUY', 'DA_HUY', 'HUY', 'TU_CHOI')
  ) THEN
    RAISE EXCEPTION 'Một hoặc nhiều khung giờ đã được đặt trước đó bởi khách hàng khác. Vui lòng chọn khung giờ trống.' USING errcode = '23P01';
  END IF;

  -- 8. Tính tổng thời lượng và giá Authoritative từ database
  SELECT
    coalesce(sum(extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 60), 0)::INT,
    coalesce(sum(round(v_rate * extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600)), 0)::NUMERIC
  INTO v_total_minutes, v_base_total
  FROM public.khunggio kg
  WHERE kg.masan = p_masan AND kg.makhunggio = ANY(p_makhunggio);

  IF v_total_minutes = 0 OR (
    SELECT count(*) FROM public.khunggio kg WHERE kg.masan = p_masan AND kg.makhunggio = ANY(p_makhunggio)
  ) <> v_slot_count THEN
    RAISE EXCEPTION 'Một hoặc nhiều khung giờ không hợp lệ trên sân này.' USING errcode = '22023';
  END IF;

  -- 9. Giới hạn tối đa 120 phút cho tiền mặt
  IF v_total_minutes > 120 THEN
    RAISE EXCEPTION 'Đặt sân tiền mặt chỉ áp dụng tối đa 2 giờ (120 phút). Đơn yêu cầu có thời lượng % phút.', v_total_minutes USING errcode = '22023';
  END IF;

  v_total := v_base_total;

  -- 10. Tra cứu khách hàng theo số điện thoại (nếu có tài khoản)
  SELECT manguoidung INTO v_makhachhang
  FROM public.nguoidung
  WHERE regexp_replace(sodienthoai, '[\s.-]', '', 'g') = v_std_phone
     OR regexp_replace(sodienthoai, '[\s.-]', '', 'g') = ('+84' || substring(v_std_phone FROM 2))
  LIMIT 1;

  -- 11. Chuẩn bị metadata
  v_meta := jsonb_build_object(
    'bookingSource', 'PHONE',
    'customerName', trim(p_customer_name),
    'customerPhone', v_std_phone,
    'note', trim(coalesce(p_note, '')),
    'paymentMethod', 'TIEN_MAT',
    'paymentStatus', 'UNPAID',
    'commissionRate', 0.1,
    'commissionAmount', round(v_total * 0.1),
    'commissionStatus', 'CHO_XAC_NHAN_TRAN',
    'createdBy', v_caller_id,
    'createdRole', v_caller_role,
    'createdAt', v_now_vn::TEXT
  );

  -- 12. INSERT ĐƠN ĐẶT SÂN (Chỉ dùng các cột chuẩn Production: makhachhang, masan, ngaydat, ngaysudung, tongtien, trangthai, ghichu)
  INSERT INTO public.datsan (
    makhachhang, masan, ngaydat, ngaysudung, tongtien, trangthai, ghichu
  )
  VALUES (
    v_makhachhang, p_masan, v_today_vn, p_ngaysudung, v_total, 'CHO_THI_DAU', v_meta::TEXT
  )
  RETURNING madatsan INTO v_booking_id;

  -- 13. INSERT DATSAN_KHUNGGIO (Hỗ trợ cấu trúc Production giaapdung/giadat hoặc Staging giatien)
  SELECT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'datsan_khunggio' AND column_name = 'giaapdung'
  ) INTO v_has_giaapdung;

  IF v_has_giaapdung THEN
    FOR v_slot IN 
      SELECT kg.makhunggio,
             round(v_rate * extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600) AS price
      FROM public.khunggio kg
      WHERE kg.masan = p_masan AND kg.makhunggio = ANY(p_makhunggio)
    LOOP
      EXECUTE 'INSERT INTO public.datsan_khunggio (madatsan, makhunggio, giaapdung, giadat) VALUES ($1, $2, $3, $4)'
        USING v_booking_id, v_slot.makhunggio, v_slot.price, v_slot.price;
    END LOOP;
  ELSE
    FOR v_slot IN 
      SELECT kg.makhunggio,
             coalesce(nullif(kg.giatien, 0), round(v_rate * extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600)) AS price
      FROM public.khunggio kg
      WHERE kg.masan = p_masan AND kg.makhunggio = ANY(p_makhunggio)
    LOOP
      EXECUTE 'INSERT INTO public.datsan_khunggio (madatsan, makhunggio, giatien) VALUES ($1, $2, $3)'
        USING v_booking_id, v_slot.makhunggio, v_slot.price;
    END LOOP;
  END IF;

  -- 14. INSERT THANHTOAN
  INSERT INTO public.thanhtoan (madatsan, phuongthuc, phuongthucthanhtoan, sotien, trangthai)
  VALUES (v_booking_id, 'TIEN_MAT', 'TIEN_MAT', v_total, 'CHO_THANH_TOAN');

  RETURN jsonb_build_object(
    'success', true,
    'madatsan', v_booking_id,
    'booking_id', v_booking_id,
    'booking', jsonb_build_object(
      'madatsan', v_booking_id,
      'masan', p_masan,
      'makhachhang', v_makhachhang,
      'ngaydat', v_today_vn,
      'ngaysudung', p_ngaysudung,
      'tongtien', v_total,
      'trangthai', 'CHO_THI_DAU',
      'ghichu', v_meta::TEXT,
      'meta', v_meta,
      'nguon_dat', 'PHONE',
      'phuongthuctt', 'TIEN_MAT'
    ),
    'tongtien', v_total,
    'total_amount', v_total,
    'duration_minutes', v_total_minutes,
    'message', format('Đã tạo đơn đặt sân qua điện thoại #%s thành công cho khách hàng %s.', v_booking_id, p_customer_name)
  );
END;
$$;

-- ============================================================================
-- 5. RPC CANCEL_PENDING_BOOKING_ATOMIC: HỦY ĐƠN CHỜ THANH TOÁN ATOMIC
-- ============================================================================
CREATE OR REPLACE FUNCTION public.cancel_pending_booking_atomic(
  p_madatsan INT,
  p_caller_id INT DEFAULT NULL,
  p_caller_role TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_booking RECORD;
  v_status TEXT;
BEGIN
  -- 1. Khóa bản ghi datsan bằng SELECT FOR UPDATE
  SELECT b.madatsan, b.makhachhang, b.trangthai, b.ghichu, b.masan
  INTO v_booking
  FROM public.datsan b
  WHERE b.madatsan = p_madatsan
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'code', 'NOT_FOUND', 'message', 'Không tìm thấy đơn đặt sân');
  END IF;

  -- 2. Kiểm tra quyền sở hữu
  IF p_caller_role <> 'ADMIN' AND p_caller_id IS NOT NULL THEN
    IF coalesce(v_booking.makhachhang, 0) <> p_caller_id THEN
      IF NOT EXISTS (SELECT 1 FROM public.san s WHERE s.masan = v_booking.masan AND s.machusan = p_caller_id) THEN
        RETURN jsonb_build_object('success', false, 'code', 'FORBIDDEN', 'message', 'Bạn không có quyền thao tác trên đơn đặt sân này');
      END IF;
    END IF;
  END IF;

  v_status := upper(coalesce(v_booking.trangthai, ''));

  -- 3. Idempotent check
  IF v_status IN ('DA_HUY', 'DAHUY') THEN
    RETURN jsonb_build_object(
      'success', true,
      'code', 'ALREADY_CANCELLED',
      'status', 'DA_HUY',
      'message', 'Đơn đặt sân đã ở trạng thái hủy trước đó.'
    );
  END IF;

  IF v_status NOT IN ('CHO_THANH_TOAN', 'CHOXACNHAN', 'CHO_THI_DAU') THEN
    RETURN jsonb_build_object(
      'success', false,
      'code', 'INVALID_STATUS',
      'message', 'Chỉ có thể hủy đơn đặt sân đang chờ thanh toán hoặc chờ xác nhận.'
    );
  END IF;

  -- 4. Xóa liên kết slot giải phóng khung giờ
  DELETE FROM public.datsan_khunggio
  WHERE madatsan = p_madatsan;

  -- 5. Cập nhật trạng thái datsan
  UPDATE public.datsan
  SET trangthai = 'DA_HUY'
  WHERE madatsan = p_madatsan;

  -- 6. Cập nhật thanhtoan nếu có
  UPDATE public.thanhtoan
  SET trangthai = 'DA_HUY'
  WHERE madatsan = p_madatsan;

  RETURN jsonb_build_object(
    'success', true,
    'code', 'CANCELLED_SUCCESS',
    'status', 'DA_HUY',
    'message', 'Đã hủy đơn đặt sân và giải phóng khung giờ thành công trong cùng transaction.'
  );
END;
$$;

-- ============================================================================
-- 6. RPC SWITCH_BOOKING_PAYMENT_METHOD_ATOMIC: ĐỔI PHƯƠNG THỨC TT ATOMIC
-- ============================================================================
CREATE OR REPLACE FUNCTION public.switch_booking_payment_method_atomic(
  p_madatsan INT,
  p_target_method TEXT,
  p_caller_id INT DEFAULT NULL,
  p_caller_role TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_booking RECORD;
  v_status TEXT;
  v_meta JSONB;
  v_duration_minutes INT := 0;
  v_new_status TEXT;
  v_new_method TEXT := upper(p_target_method);
BEGIN
  -- 1. Khóa bản ghi datsan
  SELECT b.madatsan, b.makhachhang, b.trangthai, b.ghichu, b.masan, b.ngaysudung, s.machusan, s.tensan
  INTO v_booking
  FROM public.datsan b
  JOIN public.san s ON s.masan = b.masan
  WHERE b.madatsan = p_madatsan
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'code', 'NOT_FOUND', 'message', 'Không tìm thấy đơn đặt sân');
  END IF;

  -- 2. Kiểm tra quyền sở hữu
  IF p_caller_role <> 'ADMIN' AND p_caller_id IS NOT NULL THEN
    IF coalesce(v_booking.makhachhang, 0) <> p_caller_id AND coalesce(v_booking.machusan, 0) <> p_caller_id THEN
      RETURN jsonb_build_object('success', false, 'code', 'FORBIDDEN', 'message', 'Bạn không có quyền thao tác trên đơn đặt sân này');
    END IF;
  END IF;

  v_status := upper(coalesce(v_booking.trangthai, ''));
  IF v_status IN ('DA_THANH_TOAN', 'HOAN_THANH', 'HOANTHANH') THEN
    RETURN jsonb_build_object('success', false, 'code', 'ALREADY_PAID', 'message', 'Đơn đặt sân đã được thanh toán hoặc hoàn thành, không thể đổi phương thức.');
  END IF;
  IF v_status IN ('DA_HUY', 'DAHUY') THEN
    RETURN jsonb_build_object('success', false, 'code', 'ALREADY_CANCELLED', 'message', 'Đơn đặt sân đã bị hủy, không thể đổi phương thức.');
  END IF;

  BEGIN
    v_meta := v_booking.ghichu::jsonb;
  EXCEPTION WHEN OTHERS THEN
    v_meta := '{}'::jsonb;
  END;

  IF (v_meta ->> 'paymentStatus') = 'PAID' THEN
    RETURN jsonb_build_object('success', false, 'code', 'ALREADY_PAID', 'message', 'Đơn đặt sân đã ghi nhận thanh toán tiền mặt, không thể đổi phương thức.');
  END IF;

  IF v_new_method = 'TIEN_MAT' THEN
    SELECT coalesce(sum(
      extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau
        else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 60
    ), 0)::INT
    INTO v_duration_minutes
    FROM public.datsan_khunggio dk
    JOIN public.khunggio kg ON kg.makhunggio = dk.makhunggio
    WHERE dk.madatsan = p_madatsan;

    IF v_duration_minutes > 120 THEN
      RETURN jsonb_build_object(
        'success', false,
        'code', 'ERR_CASH_DURATION_LIMIT',
        'message', format('Thanh toán tiền mặt chỉ áp dụng cho đơn đặt sân tối đa 2 giờ (120 phút). Đơn hiện tại có thời lượng %s phút.', v_duration_minutes)
      );
    END IF;

    v_new_status := 'CHO_THI_DAU';
    v_meta := v_meta || jsonb_build_object(
      'paymentMethod', 'TIEN_MAT',
      'paymentStatus', 'UNPAID',
      'commissionStatus', 'CHO_XAC_NHAN_TRAN'
    );
  ELSIF v_new_method = 'QR' THEN
    v_new_status := 'CHO_THANH_TOAN';
    v_meta := v_meta || jsonb_build_object(
      'paymentMethod', 'QR',
      'commissionStatus', 'CHO_THANH_TOAN'
    );
  ELSE
    RETURN jsonb_build_object('success', false, 'code', 'INVALID_METHOD', 'message', 'Phương thức thanh toán không hợp lệ');
  END IF;

  -- 3. Cập nhật datsan
  UPDATE public.datsan
  SET trangthai = v_new_status,
      ghichu = v_meta::text
  WHERE madatsan = p_madatsan;

  -- 4. Cập nhật thanhtoan
  UPDATE public.thanhtoan
  SET phuongthuc = v_new_method,
      phuongthucthanhtoan = v_new_method
  WHERE madatsan = p_madatsan;

  -- 5. Thông báo chủ sân nếu chuyển sang tiền mặt
  IF v_new_method = 'TIEN_MAT' AND v_booking.machusan IS NOT NULL THEN
    INSERT INTO public.thongbao (manguoidung, tieude, noidung, loaithongbao, metadata)
    VALUES (
      v_booking.machusan,
      '🔔 Đơn đặt sân chuyển sang tiền mặt',
      format('Khách hàng vừa chuyển đơn #%s tại %s sang hình thức thanh toán 100%% tiền mặt tại sân.', p_madatsan, coalesce(v_booking.tensan, 'sân')),
      'BOOKING',
      jsonb_build_object('bookingId', p_madatsan, 'date', v_booking.ngaysudung, 'role', 'CHUSAN')
    );
  END IF;

  RETURN jsonb_build_object(
    'success', true,
    'bookingId', p_madatsan,
    'status', v_new_status,
    'paymentMethod', v_new_method,
    'booking', jsonb_build_object(
      'madatsan', p_madatsan,
      'trangthai', v_new_status,
      'phuongthuctt', v_new_method
    ),
    'message', CASE WHEN v_new_method = 'TIEN_MAT' THEN 'Đã chuyển sang hình thức thanh toán tiền mặt tại sân thành công.' ELSE 'Đã chuyển sang phương thức quét mã QR trực tuyến.' END
  );
END;
$$;

-- ============================================================================
-- 7. CẤP QUYỀN VÀ REFRESH SCHEMA CACHE
-- ============================================================================
GRANT EXECUTE ON FUNCTION public.create_phone_booking TO authenticated, service_role, postgres;
GRANT EXECUTE ON FUNCTION public.cancel_pending_booking_atomic TO authenticated, service_role, postgres;
GRANT EXECUTE ON FUNCTION public.switch_booking_payment_method_atomic TO authenticated, service_role, postgres;

NOTIFY pgrst, 'reload schema';
