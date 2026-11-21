-- MIGRATION: 001_owner_deposit_and_customer_cancellation.sql
-- TARGET: LOCAL TESTBED DATABASE (datsan_local_testbed)
-- GOAL: Implement Feature 01 (Owner Security Deposit) & Feature 02 (Customer Self-Cancellation & Refund)

BEGIN;

-- 1. BẢNG TÀI KHOẢN KÝ QUỸ CHỦ SÂN (Owner Security Deposit)
CREATE TABLE IF NOT EXISTS kyquy (
  makyquy SERIAL PRIMARY KEY,
  machusan INT NOT NULL UNIQUE,
  sotien_yeucau NUMERIC(12,2) NOT NULL DEFAULT 1000000.00,
  sotien_dadoisoat NUMERIC(12,2) NOT NULL DEFAULT 0.00,
  sodu_hientai NUMERIC(12,2) NOT NULL DEFAULT 0.00,
  trangthai VARCHAR(50) NOT NULL DEFAULT 'CHUA_KY_QUY',
  is_legacy BOOLEAN NOT NULL DEFAULT FALSE,
  thoigian_xacnhan TIMESTAMPTZ,
  nguoi_xacnhan INT,
  ghichu TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT ck_kyquy_trangthai CHECK (
    trangthai IN ('CHUA_KY_QUY', 'CHO_THANH_TOAN', 'CHO_XAC_MINH', 'DA_KY_QUY', 'THIEU_KY_QUY', 'DANG_HOAN_TRA', 'DA_HOAN_TRA', 'TRANH_CHAP')
  )
);

CREATE INDEX IF NOT EXISTS idx_kyquy_machusan ON kyquy(machusan);
CREATE INDEX IF NOT EXISTS idx_kyquy_trangthai ON kyquy(trangthai);

-- 2. BẢNG GIAO DỊCH NỘP KÝ QUỸ (Deposit Payment Transactions via VietQR)
CREATE TABLE IF NOT EXISTS kyquy_giaodich (
  magiaodich SERIAL PRIMARY KEY,
  ma_yeucau VARCHAR(64) NOT NULL UNIQUE,
  machusan INT NOT NULL,
  sotien NUMERIC(12,2) NOT NULL,
  noidung_chuyenkhoan VARCHAR(128) NOT NULL UNIQUE,
  phuongthuc VARCHAR(32) NOT NULL DEFAULT 'VIETQR',
  trangthai VARCHAR(32) NOT NULL DEFAULT 'CHO_XAC_MINH',
  magiaodich_nganhang VARCHAR(128),
  thoigian_thanhtoan TIMESTAMPTZ,
  nguoi_xacminh INT,
  thoigian_xacminh TIMESTAMPTZ,
  bangchung_url TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT ck_kyquy_giaodich_trangthai CHECK (
    trangthai IN ('CHO_THANH_TOAN', 'CHO_XAC_MINH', 'THANH_CONG', 'TU_CHOI', 'HUY')
  )
);

CREATE INDEX IF NOT EXISTS idx_kyquy_gd_machusan ON kyquy_giaodich(machusan);
CREATE INDEX IF NOT EXISTS idx_kyquy_gd_noidung ON kyquy_giaodich(noidung_chuyenkhoan);

-- 3. SỔ GIAO DỊCH BẤT BIẾN KÝ QUỸ (Immutable Deposit Financial Ledger)
CREATE TABLE IF NOT EXISTS kyquy_ledger (
  mabutdoan SERIAL PRIMARY KEY,
  machusan INT NOT NULL,
  magiaodich INT REFERENCES kyquy_giaodich(magiaodich) ON DELETE SET NULL,
  loai_butdoan VARCHAR(32) NOT NULL,
  sotien_thaydoi NUMERIC(12,2) NOT NULL,
  sodu_sau NUMERIC(12,2) NOT NULL,
  lydo TEXT NOT NULL,
  actor_id INT NOT NULL,
  actor_role VARCHAR(32) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT ck_kyquy_ledger_loai CHECK (
    loai_butdoan IN ('NOP_KY_QUY', 'HOAN_KY_QUY', 'KHAU_TRU_BOI_THUONG', 'DIEU_CHINH')
  )
);

CREATE INDEX IF NOT EXISTS idx_kyquy_ledger_machusan ON kyquy_ledger(machusan);

-- 4. BẢNG QUẢN LÝ YÊU CẦU HOÀN TIỀN CỦA KHÁCH HÀNG (Refund Requests)
CREATE TABLE IF NOT EXISTS hoantien (
  mahoantien SERIAL PRIMARY KEY,
  madatsan INT NOT NULL UNIQUE,
  makhachhang INT NOT NULL,
  machusan INT NOT NULL,
  sotien_canhoan NUMERIC(12,2) NOT NULL,
  sotien_dahoan NUMERIC(12,2) NOT NULL DEFAULT 0.00,
  lydo_huy TEXT,
  trangthai VARCHAR(32) NOT NULL DEFAULT 'CHO_HOAN',
  nganhang_nhan VARCHAR(64),
  sotaikhoan_nhan VARCHAR(64),
  chutaikhoan_nhan VARCHAR(128),
  han_xuly TIMESTAMPTZ NOT NULL,
  thoigian_owner_chuyen TIMESTAMPTZ,
  magiaodich_owner VARCHAR(128),
  bangchung_chuyen_url TEXT,
  thoigian_xacnhan_hoan TIMESTAMPTZ,
  nguoi_xacnhan_hoan INT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT ck_hoantien_trangthai CHECK (
    trangthai IN ('CHO_HOAN', 'OWNER_BAO_DA_CHUYEN', 'CHO_DOI_SOAT', 'DA_HOAN', 'QUA_HAN', 'TRANH_CHAP', 'DA_GIAI_QUYET')
  )
);

CREATE INDEX IF NOT EXISTS idx_hoantien_madatsan ON hoantien(madatsan);
CREATE INDEX IF NOT EXISTS idx_hoantien_makhachhang ON hoantien(makhachhang);
CREATE INDEX IF NOT EXISTS idx_hoantien_machusan ON hoantien(machusan);
CREATE INDEX IF NOT EXISTS idx_hoantien_trangthai ON hoantien(trangthai);

-- 5. BẢNG AUDIT LOG TÀI CHÍNH BẤT BIẾN (Financial Audit Trail)
CREATE TABLE IF NOT EXISTS financial_audit_log (
  log_id SERIAL PRIMARY KEY,
  actor_id INT NOT NULL,
  actor_role VARCHAR(32) NOT NULL,
  action VARCHAR(64) NOT NULL,
  entity_type VARCHAR(64) NOT NULL,
  entity_id VARCHAR(64) NOT NULL,
  old_values JSONB,
  new_values JSONB,
  reason TEXT,
  ip_address VARCHAR(64),
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_entity ON financial_audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON financial_audit_log(created_at);

COMMIT;
