-- ============================================================================
-- DATSANONLINE — MIGRATION 009: ALLOW WALKIN / PHONE BOOKINGS & NOTIF METADATA
-- ============================================================================

-- 1. Cho phép makhachhang có giá trị NULL cho đơn đặt qua điện thoại / khách vãng lai
ALTER TABLE public.datsan ALTER COLUMN makhachhang DROP NOT NULL;

-- 2. Thêm cột metadata JSONB cho bảng thongbao để hỗ trợ deep linking
ALTER TABLE public.thongbao ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;

-- 3. Tạo index hỗ trợ tìm kiếm metadata và makhachhang
CREATE INDEX IF NOT EXISTS idx_datsan_makhachhang ON public.datsan(makhachhang);
CREATE INDEX IF NOT EXISTS idx_thongbao_metadata ON public.thongbao USING gin (metadata);

-- ============================================================================
-- ROLLBACK SCRIPT (IF NEEDED):
-- ALTER TABLE public.datsan ALTER COLUMN makhachhang SET NOT NULL;
-- ALTER TABLE public.thongbao DROP COLUMN IF EXISTS metadata;
-- ============================================================================
