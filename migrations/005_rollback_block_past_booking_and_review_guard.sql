-- migrations/005_rollback_block_past_booking_and_review_guard.sql
-- Rollback for Migration 005

DROP INDEX IF EXISTS idx_danhgia_madatsan_unique;

-- Khôi phục policy cũ
DROP POLICY IF EXISTS danhgia_insert ON public.danhgia;
CREATE POLICY danhgia_insert ON public.danhgia FOR INSERT TO authenticated
WITH CHECK (
  makhachhang = (SELECT public.current_nguoidung_id())
  AND EXISTS (
    SELECT 1 FROM public.datsan d
    WHERE d.madatsan = danhgia.madatsan
      AND d.makhachhang = (SELECT public.current_nguoidung_id())
      AND d.trangthai = 'HOANTHANH'
  )
);
