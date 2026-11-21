-- ============================================================================
-- MIGRATION: 002_financial_security_remediation.sql
-- TARGET: DATSANONLINE FINANCIAL ENGINE
-- PURPOSE: Remediate BUG-SEC-01, GAP-FIN-01, ARCH-SEC-01, GAP-FIN-02
-- VERSION: 2.0.0
-- ============================================================================

BEGIN;

-- 1. BỔ SUNG CỘT QUẢN LÝ TRANH CHẤP & GIẢI TRÌNH CHO BẢNG HOÀN TIỀN
ALTER TABLE hoantien 
  ADD COLUMN IF NOT EXISTS giaitrinh_owner TEXT,
  ADD COLUMN IF NOT EXISTS thoigian_giaitrinh TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS bangchung_giaitrinh_url TEXT,
  ADD COLUMN IF NOT EXISTS ketluan_admin VARCHAR(64),
  ADD COLUMN IF NOT EXISTS lydo_ketluan TEXT,
  ADD COLUMN IF NOT EXISTS nguoi_duyet_phu INT,
  ADD COLUMN IF NOT EXISTS phuckhao_owner TEXT,
  ADD COLUMN IF NOT EXISTS thoigian_phuckhao TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS magiaodich_chi_tra VARCHAR(128),
  ADD COLUMN IF NOT EXISTS thoigian_chi_tra TIMESTAMPTZ;

-- 2. CẬP NHẬT RÀNG BUỘC TRẠNG THÁI HOÀN TIỀN (QUY TRÌNH TRANH CHẤP ĐA BƯỚC)
ALTER TABLE hoantien DROP CONSTRAINT IF EXISTS ck_hoantien_trangthai;
ALTER TABLE hoantien ADD CONSTRAINT ck_hoantien_trangthai CHECK (
  trangthai IN (
    'CHO_HOAN',
    'OWNER_BAO_DA_CHUYEN',
    'CHO_DOI_SOAT',
    'DA_HOAN',
    'QUA_HAN',
    'DANG_XAC_MINH_GIAI_TRINH',
    'KHAU_TRU_BOI_THUONG',
    'TRANH_CHAP',
    'PHUC_KHAO_KHAU_TRU',
    'BOI_HOAN_HOAN_TAT',
    'DA_GIAI_QUYET'
  )
);

-- 3. CẬP NHẬT RÀNG BUỘC LOẠI BÚT TOÁN TRONG SỔ CÁI KÝ QUỸ
ALTER TABLE kyquy_ledger DROP CONSTRAINT IF EXISTS ck_kyquy_ledger_loai;
ALTER TABLE kyquy_ledger ADD CONSTRAINT ck_kyquy_ledger_loai CHECK (
  loai_butdoan IN (
    'NOP_KY_QUY',
    'HOAN_KY_QUY',
    'KHAU_TRU_BOI_THUONG',
    'BO_SUNG_KY_QUY',
    'DIEU_CHINH'
  )
);

-- 4. BỔ SUNG INDEXES TỐI ƯU TRUY VẤN TÀI CHÍNH & QUÁ HẠN 24H
CREATE INDEX IF NOT EXISTS idx_hoantien_hanxuly_trangthai ON hoantien(han_xuly, trangthai);
CREATE INDEX IF NOT EXISTS idx_hoantien_machusan_trangthai ON hoantien(machusan, trangthai);
CREATE INDEX IF NOT EXISTS idx_kyquy_machusan_sodu ON kyquy(machusan, sodu_hientai);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON financial_audit_log(actor_id, actor_role);

-- 5. KÍCH HOẠT ROW LEVEL SECURITY (RLS) TRÊN 5 BẢNG TÀI CHÍNH
ALTER TABLE kyquy ENABLE ROW LEVEL SECURITY;
ALTER TABLE kyquy_giaodich ENABLE ROW LEVEL SECURITY;
ALTER TABLE kyquy_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE hoantien ENABLE ROW LEVEL SECURITY;
ALTER TABLE financial_audit_log ENABLE ROW LEVEL SECURITY;

-- 6. POLICIES CHO SUPABASE / POSTGRESQL (Độc lập và bảo vệ dữ liệu nhạy cảm)

-- 6.1. Bảng kyquy: Owner chỉ xem của mình; Admin/Service role xem toàn quyền
DROP POLICY IF EXISTS p_kyquy_select ON kyquy;
CREATE POLICY p_kyquy_select ON kyquy
  FOR SELECT
  USING (
    machusan = NULLIF(current_setting('app.current_user_id', true), '')::int
    OR current_setting('app.current_user_role', true) IN ('ADMIN', 'service_role')
  );

DROP POLICY IF EXISTS p_kyquy_mutation ON kyquy;
CREATE POLICY p_kyquy_mutation ON kyquy
  FOR ALL
  USING (
    current_setting('app.current_user_role', true) IN ('ADMIN', 'service_role')
  );

-- 6.2. Bảng kyquy_giaodich: Owner chỉ xem/tạo của mình; Admin xem và duyệt
DROP POLICY IF EXISTS p_kyquy_gd_select ON kyquy_giaodich;
CREATE POLICY p_kyquy_gd_select ON kyquy_giaodich
  FOR SELECT
  USING (
    machusan = NULLIF(current_setting('app.current_user_id', true), '')::int
    OR current_setting('app.current_user_role', true) IN ('ADMIN', 'service_role')
  );

DROP POLICY IF EXISTS p_kyquy_gd_insert ON kyquy_giaodich;
CREATE POLICY p_kyquy_gd_insert ON kyquy_giaodich
  FOR INSERT
  WITH CHECK (
    machusan = NULLIF(current_setting('app.current_user_id', true), '')::int
    OR current_setting('app.current_user_role', true) IN ('ADMIN', 'service_role')
  );

DROP POLICY IF EXISTS p_kyquy_gd_update ON kyquy_giaodich;
CREATE POLICY p_kyquy_gd_update ON kyquy_giaodich
  FOR UPDATE
  USING (
    current_setting('app.current_user_role', true) IN ('ADMIN', 'service_role')
  );

-- 6.3. Bảng kyquy_ledger: Tuyệt đối bất biến (Chỉ service_role/backend được ghi)
DROP POLICY IF EXISTS p_ledger_select ON kyquy_ledger;
CREATE POLICY p_ledger_select ON kyquy_ledger
  FOR SELECT
  USING (
    machusan = NULLIF(current_setting('app.current_user_id', true), '')::int
    OR current_setting('app.current_user_role', true) IN ('ADMIN', 'service_role')
  );

DROP POLICY IF EXISTS p_ledger_write ON kyquy_ledger;
CREATE POLICY p_ledger_write ON kyquy_ledger
  FOR INSERT
  WITH CHECK (
    current_setting('app.current_user_role', true) = 'service_role'
  );

-- 6.4. Bảng hoantien: Khách chỉ xem đơn của mình; Chủ sân xem đơn của sân mình; Admin xem tất cả
DROP POLICY IF EXISTS p_hoantien_select ON hoantien;
CREATE POLICY p_hoantien_select ON hoantien
  FOR SELECT
  USING (
    makhachhang = NULLIF(current_setting('app.current_user_id', true), '')::int
    OR machusan = NULLIF(current_setting('app.current_user_id', true), '')::int
    OR current_setting('app.current_user_role', true) IN ('ADMIN', 'service_role')
  );

DROP POLICY IF EXISTS p_hoantien_customer_update ON hoantien;
CREATE POLICY p_hoantien_customer_update ON hoantien
  FOR UPDATE
  USING (
    makhachhang = NULLIF(current_setting('app.current_user_id', true), '')::int
    OR machusan = NULLIF(current_setting('app.current_user_id', true), '')::int
    OR current_setting('app.current_user_role', true) IN ('ADMIN', 'service_role')
  );

-- 6.5. Bảng financial_audit_log: Chỉ Admin/service_role đọc, chỉ service_role ghi, KHÔNG AI ĐƯỢC XÓA/SỬA
DROP POLICY IF EXISTS p_audit_select ON financial_audit_log;
CREATE POLICY p_audit_select ON financial_audit_log
  FOR SELECT
  USING (
    current_setting('app.current_user_role', true) IN ('ADMIN', 'service_role')
  );

DROP POLICY IF EXISTS p_audit_insert ON financial_audit_log;
CREATE POLICY p_audit_insert ON financial_audit_log
  FOR INSERT
  WITH CHECK (
    current_setting('app.current_user_role', true) = 'service_role'
  );

COMMIT;
