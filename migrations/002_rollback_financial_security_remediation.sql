-- ============================================================================
-- ROLLBACK SCRIPT: 002_rollback_financial_security_remediation.sql
-- TARGET: DATSANONLINE FINANCIAL ENGINE
-- SAFETY RULE: DO NOT DROP TABLES OR PURGE FINANCIAL DATA.
-- ============================================================================

BEGIN;

-- 1. XÓA BỎ POLICIES RLS NẾU CẦN REVERT
DROP POLICY IF EXISTS p_kyquy_select ON kyquy;
DROP POLICY IF EXISTS p_kyquy_mutation ON kyquy;
DROP POLICY IF EXISTS p_kyquy_gd_select ON kyquy_giaodich;
DROP POLICY IF EXISTS p_kyquy_gd_insert ON kyquy_giaodich;
DROP POLICY IF EXISTS p_kyquy_gd_update ON kyquy_giaodich;
DROP POLICY IF EXISTS p_ledger_select ON kyquy_ledger;
DROP POLICY IF EXISTS p_ledger_write ON kyquy_ledger;
DROP POLICY IF EXISTS p_hoantien_select ON hoantien;
DROP POLICY IF EXISTS p_hoantien_customer_update ON hoantien;
DROP POLICY IF EXISTS p_audit_select ON financial_audit_log;
DROP POLICY IF EXISTS p_audit_insert ON financial_audit_log;

-- 2. TẮT RLS TRÊN CÁC BẢNG NẾU REVERT VỀ KIẾN TRÚC BAN ĐẦU
ALTER TABLE kyquy DISABLE ROW LEVEL SECURITY;
ALTER TABLE kyquy_giaodich DISABLE ROW LEVEL SECURITY;
ALTER TABLE kyquy_ledger DISABLE ROW LEVEL SECURITY;
ALTER TABLE hoantien DISABLE ROW LEVEL SECURITY;
ALTER TABLE financial_audit_log DISABLE ROW LEVEL SECURITY;

-- 3. XÓA CÁC INDEX BỔ SUNG
DROP INDEX IF EXISTS idx_hoantien_hanxuly_trangthai;
DROP INDEX IF EXISTS idx_hoantien_machusan_trangthai;
DROP INDEX IF EXISTS idx_kyquy_machusan_sodu;
DROP INDEX IF EXISTS idx_audit_actor;

-- 4. PHỤC HỒI RÀNG BUỘC TRẠNG THÁI V1
ALTER TABLE hoantien DROP CONSTRAINT IF EXISTS ck_hoantien_trangthai;
ALTER TABLE hoantien ADD CONSTRAINT ck_hoantien_trangthai CHECK (
  trangthai IN ('CHO_HOAN', 'OWNER_BAO_DA_CHUYEN', 'CHO_DOI_SOAT', 'DA_HOAN', 'QUA_HAN', 'TRANH_CHAP', 'DA_GIAI_QUYET')
);

ALTER TABLE kyquy_ledger DROP CONSTRAINT IF EXISTS ck_kyquy_ledger_loai;
ALTER TABLE kyquy_ledger ADD CONSTRAINT ck_kyquy_ledger_loai CHECK (
  loai_butdoan IN ('NOP_KY_QUY', 'HOAN_KY_QUY', 'KHAU_TRU_BOI_THUONG', 'DIEU_CHINH')
);

-- LƯU Ý BẢO TOÀN DỮ LIỆU:
-- Các cột (giaitrinh_owner, phuckhao_owner, ...) KHÔNG BỊ DROP để bảo vệ dữ liệu đã phát sinh trong thời gian chạy v2.
-- Nếu cần dọn dẹp triệt để trên môi trường test, có thể ALTER TABLE hoantien DROP COLUMN thủ công.

COMMIT;
