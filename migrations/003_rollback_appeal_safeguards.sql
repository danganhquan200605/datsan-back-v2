-- ============================================================================
-- ROLLBACK MIGRATION: 003_rollback_appeal_safeguards.sql
-- TARGET: DATSANONLINE FINANCIAL ENGINE
-- PURPOSE: Safely revert constraint changes back to v2.0.0 without dropping
--          columns, tables or existing financial records
-- VERSION: 2.1.0-down
-- ============================================================================

BEGIN;

-- 1. DROP INDEXES CREATED IN 003
DROP INDEX IF EXISTS idx_hoantien_hanphuckhao;
DROP INDEX IF EXISTS idx_kyquy_sodutamgiu;

-- 2. REVERT CONSTRAINTS TO MIGRATION 002 DEFINITIONS
ALTER TABLE kyquy DROP CONSTRAINT IF EXISTS ck_kyquy_trangthai;
ALTER TABLE kyquy ADD CONSTRAINT ck_kyquy_trangthai CHECK (
  trangthai IN ('CHUA_KY_QUY', 'CHO_THANH_TOAN', 'CHO_XAC_MINH', 'DA_KY_QUY', 'THIEU_KY_QUY', 'DANG_HOAN_TRA', 'DA_HOAN_TRA', 'TRANH_CHAP')
);

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

-- NOTE: Cột sodu_tamgiu, han_phuckhao, thoigian_quyetdinh_sobo, quyetdinh_sobo
-- CỐ TÌNH ĐƯỢC GIỮ LẠI (KHÔNG DROP) để bảo vệ toàn vẹn dữ liệu kế toán và nhật ký!

COMMIT;
