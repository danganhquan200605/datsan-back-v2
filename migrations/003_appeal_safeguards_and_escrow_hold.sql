-- ============================================================================
-- MIGRATION: 003_appeal_safeguards_and_escrow_hold.sql
-- TARGET: DATSANONLINE FINANCIAL ENGINE
-- PURPOSE: Implement 48h Appeal Window, Escrow Hold State, Overturn Capability,
--          Financial Consistency Tracking & Reconciliation Guardrails
-- VERSION: 2.1.0
-- ============================================================================

BEGIN;

-- 1. BỔ SUNG CỘT TẠM GIỮ KÝ QUỸ TRONG BẢNG KYQUY VÀ CẬP NHẬT RÀNG BUỘC TRẠNG THÁI
ALTER TABLE kyquy 
  ADD COLUMN IF NOT EXISTS sodu_tamgiu NUMERIC(12,2) NOT NULL DEFAULT 0.00;

ALTER TABLE kyquy DROP CONSTRAINT IF EXISTS ck_kyquy_trangthai;
ALTER TABLE kyquy ADD CONSTRAINT ck_kyquy_trangthai CHECK (
  trangthai IN (
    'CHUA_KY_QUY',
    'CHO_THANH_TOAN',
    'CHO_XAC_MINH',
    'DA_KY_QUY',
    'THIEU_KY_QUY',
    'TAM_GIU_KY_QUY',
    'DANG_HOAN_TRA',
    'DA_HOAN_TRA',
    'TRANH_CHAP'
  )
);

-- 2. BỔ SUNG CỘT QUẢN LÝ QUYẾT ĐỊNH SƠ BỘ & HẠN PHÚC KHẢO 48H TRONG BẢNG HOANTIEN
ALTER TABLE hoantien 
  ADD COLUMN IF NOT EXISTS han_phuckhao TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS thoigian_quyetdinh_sobo TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS quyetdinh_sobo VARCHAR(64),
  ADD COLUMN IF NOT EXISTS bangchung_chi_tra_url TEXT;

-- 3. CẬP NHẬT RÀNG BUỘC TRẠNG THÁI HOÀN TIỀN (CHUẨN HÓA CÁC BƯỚC TẠM GIỮ & KHẤU TRỪ)
ALTER TABLE hoantien DROP CONSTRAINT IF EXISTS ck_hoantien_trangthai;
ALTER TABLE hoantien ADD CONSTRAINT ck_hoantien_trangthai CHECK (
  trangthai IN (
    'CHO_HOAN',
    'OWNER_BAO_DA_CHUYEN',
    'CHO_DOI_SOAT',
    'DA_HOAN',
    'QUA_HAN',
    'DANG_XAC_MINH_GIAI_TRINH',
    'TAM_GIU_KY_QUY',
    'PHUC_KHAO_KHAU_TRU',
    'KHAU_TRU_CHINH_THUC',
    'DAO_QUYET_DINH_SO_BO',
    'BOI_HOAN_HOAN_TAT',
    'TRANH_CHAP',
    'DA_GIAI_QUYET',
    'KHAU_TRU_BOI_THUONG' -- Backward compatibility v2.0
  )
);

-- 4. CẬP NHẬT RÀNG BUỘC LOẠI BÚT TOÁN TRONG SỔ CÁI KÝ QUỸ
ALTER TABLE kyquy_ledger DROP CONSTRAINT IF EXISTS ck_kyquy_ledger_loai;
ALTER TABLE kyquy_ledger ADD CONSTRAINT ck_kyquy_ledger_loai CHECK (
  loai_butdoan IN (
    'NOP_KY_QUY',
    'HOAN_KY_QUY',
    'TAM_GIU_KY_QUY',
    'GIAI_TOA_TAM_GIU',
    'KHAU_TRU_CHINH_THUC',
    'BO_SUNG_KY_QUY',
    'DIEU_CHINH',
    'KHAU_TRU_BOI_THUONG' -- Backward compatibility v2.0
  )
);

-- 5. BỔ SUNG INDEXES TỐI ƯU TRUY VẤN HẠN PHÚC KHẢO VÀ TẠM GIỮ
CREATE INDEX IF NOT EXISTS idx_hoantien_hanphuckhao ON hoantien(han_phuckhao, trangthai);
CREATE INDEX IF NOT EXISTS idx_kyquy_sodutamgiu ON kyquy(machusan, sodu_tamgiu);

COMMIT;
