# MIGRATION RECONCILIATION DOCUMENTATION: PRODUCTION (ckrmfyuymuvaiymfxvhj)

**Environment:** Supabase Production (`ckrmfyuymuvaiymfxvhj`)  
**Applied Script:** `migrations/production_005_006_combined.sql`  
**Rollback Script:** `migrations/production_005_006_rollback.sql`  
**Verification Date:** 22/11/2026 16:00 (UTC+7)  
**Database Status:** ACTIVE & VERIFIED (Zero data loss, 15/15 tables match baseline)

---

## 1. APPLIED PRODUCTION OBJECTS SUMMARY

1. **Unique Index `idx_danhgia_madatsan_unique`:**
   - Table: `public.danhgia(madatsan)`
   - Verified via `pg_indexes`. Enforces 1-review-per-booking.

2. **RLS Policy `danhgia_insert`:**
   - Table: `public.danhgia`
   - Command: `INSERT`
   - Roles: `authenticated`
   - With Check:
     - `makhachhang = current_nguoidung_id()`
     - `d.madatsan = danhgia.madatsan AND d.makhachhang = current_nguoidung_id()`
     - `upper(d.trangthai) IN ('HOAN_THANH', 'HOANTHANH')`
     - `upper(d.trangthai) NOT IN ('DAHUY', 'DA_HUY', 'HUY', 'TU_CHOI')`
     - `EXISTS (SELECT 1 FROM datsan_khunggio dk WHERE dk.madatsan = d.madatsan)`
     - Multi-slot end-time check:
       `NOT EXISTS (SELECT 1 FROM datsan_khunggio dk JOIN khunggio kg ON kg.makhunggio = dk.makhunggio WHERE dk.madatsan = d.madatsan AND (d.ngaysudung + kg.gioketthuc) > clock_timestamp() AT TIME ZONE 'Asia/Ho_Chi_Minh')`
     - Verified: NO self-reference to `danhgia`, NO recursion.

3. **RPC `public.create_booking`:**
   - Parameters: `p_masan integer, p_ngaysudung date, p_makhunggio integer[], p_dichvu jsonb DEFAULT '{}'::jsonb`
   - Security: `SECURITY DEFINER`
   - Features:
     - Pre-lock clock time check (`clock_timestamp() AT TIME ZONE 'Asia/Ho_Chi_Minh'`)
     - Sorted advisory transaction locking (`pg_advisory_xact_lock`)
     - Post-lock clock time check (prevents lock wait delay bypass)
     - Schema adaptation: uses `s.giasan`, handles `khunggio` without `giatien`, inserts `datsan_khunggio(madatsan, makhunggio, giaapdung, giadat)`
     - Automatic creation of `thanhtoan` record with status `CHO_THANH_TOAN`
   - Routine Privileges: Granted to `authenticated`, `postgres`, `service_role`. Revoked from `PUBLIC`, `anon`.

---

## 2. PRODUCTION vs STAGING SCHEMA MATRIX

| Component | Staging (`fllbhjovifmzyfjubifx`) | Production (`ckrmfyuymuvaiymfxvhj`) |
|---|---|---|
| `san` price column | `giacoban` | `giasan` |
| `khunggio` rate | `giatien` column present | NO `giatien` column; uses `s.giasan` |
| `khunggio` status | `'HOATDONG'` | `'TRONG'` |
| `datsan_khunggio` columns | `(madatsan, makhunggio, giatien)` | `(madatsan, makhunggio, giaapdung, giadat)` |
| `datsan` columns | 13 columns (has `giobatdau`, `gioketthuc`, `tiencoc`, timestamps) | 8 columns (`madatsan, makhachhang, masan, ngaydat, ngaysudung, tongtien, trangthai, ghichu`) |
| `danhgia` columns | 7 columns (has `masan`) | 6 columns (`madanhgia, madatsan, makhachhang, sosao, noidung, ngaydanhgia`) |
| `thanhtoan` columns | Has `magiaodich, ngaythanhtoan` | Has `thoigianthanhtoan`, NO `magiaodich` |
| Review RLS Policy | `danhgia_insert` | `danhgia_insert` (matched & active) |
