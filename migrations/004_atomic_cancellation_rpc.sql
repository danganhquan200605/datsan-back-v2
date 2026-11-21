-- ============================================================================
-- MIGRATION: 004_atomic_cancellation_rpc.sql
-- TARGET: DATSANONLINE FINANCIAL ENGINE & BOOKING SUBSYSTEM
-- PURPOSE: Atomic booking cancellation & slot release within a single PostgreSQL transaction
-- VERSION: 2.2.0
-- ============================================================================

CREATE OR REPLACE FUNCTION public.cancel_booking_atomic(
  p_madatsan INT,
  p_ghichu TEXT,
  p_expected_status TEXT DEFAULT 'CHO_THANH_TOAN'
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_updated_rows INT;
BEGIN
  -- 1. Optimistic locking on datsan: Only transition if status matches expected status
  UPDATE public.datsan
  SET trangthai = 'DA_HUY',
      ghichu = p_ghichu
  WHERE madatsan = p_madatsan
    AND trangthai = p_expected_status;

  GET DIAGNOSTICS v_updated_rows = ROW_COUNT;

  IF v_updated_rows = 0 THEN
    RETURN jsonb_build_object(
      'success', false,
      'code', 'CONCURRENT_CONFLICT',
      'message', 'Đơn đặt sân đã được xử lý hoặc thay đổi trạng thái bởi một yêu cầu khác.'
    );
  END IF;

  -- 2. Delete slot linkages from datsan_khunggio to release slots
  DELETE FROM public.datsan_khunggio
  WHERE madatsan = p_madatsan;

  -- 3. Update payment records in thanhtoan if present
  UPDATE public.thanhtoan
  SET trangthai = 'DA_HUY'
  WHERE madatsan = p_madatsan;

  RETURN jsonb_build_object(
    'success', true,
    'code', 'SIMULATE_FAILURE_CANCELLED',
    'status', 'DA_HUY',
    'message', 'Đơn đặt sân đã được hủy và khung giờ thi đấu đã được giải phóng thành công trong cùng transaction.'
  );
EXCEPTION WHEN OTHERS THEN
  RAISE EXCEPTION 'Lỗi khi hủy đơn đặt sân: %', SQLERRM;
END;
$$;
