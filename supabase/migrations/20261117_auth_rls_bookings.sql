-- DatSan V2 auth, row security, and booking RPCs.
-- Apply only after reviewing the production impact: this Supabase project is shared with the legacy app.

alter table public.nguoidung
  add column if not exists auth_user_id uuid references auth.users(id) on delete set null;

create unique index if not exists nguoidung_auth_user_id_key
  on public.nguoidung(auth_user_id) where auth_user_id is not null;

create or replace function public.current_nguoidung_id()
returns integer
language sql stable security definer
set search_path = ''
as $$
  select u.manguoidung
  from public.nguoidung u
  where u.auth_user_id = (select auth.uid())
    and (u.trangthai is null or upper(u.trangthai) = 'HOATDONG')
  limit 1;
$$;

create or replace function public.current_nguoidung_role()
returns text
language sql stable security definer
set search_path = ''
as $$
  select upper(u.vaitro)
  from public.nguoidung u
  where u.auth_user_id = (select auth.uid())
    and (u.trangthai is null or upper(u.trangthai) = 'HOATDONG')
  limit 1;
$$;

create or replace function public.ensure_current_nguoidung()
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_phone text := auth.jwt() ->> 'phone';
  v_digits text;
  v_local_phone text;
  v_count integer;
  v_profile public.nguoidung%rowtype;
begin
  if v_uid is null or coalesce(v_phone, '') = '' then
    raise exception 'A verified phone session is required' using errcode = '42501';
  end if;

  select * into v_profile from public.nguoidung where auth_user_id = v_uid;
  if found then
    if v_profile.trangthai is not null and upper(v_profile.trangthai) <> 'HOATDONG' then
      raise exception 'This account is not active' using errcode = '42501';
    end if;
    return jsonb_build_object(
      'MaNguoiDung', v_profile.manguoidung,
      'TenDangNhap', v_profile.tendangnhap,
      'HoTen', v_profile.hoten,
      'Sdt', v_profile.sodienthoai,
      'Email', v_profile.email,
      'VaiTro', v_profile.vaitro
    );
  end if;

  v_digits := regexp_replace(v_phone, '\D', '', 'g');
  v_local_phone := case when v_digits like '84%' then '0' || substr(v_digits, 3) else v_digits end;
  select count(*) into v_count
  from public.nguoidung u
  where regexp_replace(u.sodienthoai, '\D', '', 'g') in (v_digits, regexp_replace(v_local_phone, '\D', '', 'g'));

  if v_count > 1 then
    raise exception 'More than one account matches this phone number; an administrator must resolve the duplicate' using errcode = '23505';
  elsif v_count = 1 then
    update public.nguoidung u set auth_user_id = v_uid
    where regexp_replace(u.sodienthoai, '\D', '', 'g') in (v_digits, regexp_replace(v_local_phone, '\D', '', 'g'))
      and u.auth_user_id is null
    returning * into v_profile;
    if not found then
      raise exception 'This phone number is already linked to another Auth account' using errcode = '23505';
    end if;
  else
    insert into public.nguoidung (auth_user_id, tendangnhap, sodienthoai, hoten, vaitro, trangthai)
    values (v_uid, 'otp_' || replace(v_uid::text, '-', ''), v_local_phone,
      'Khách hàng ' || right(v_local_phone, 4), 'KHACHHANG', 'HOATDONG')
    returning * into v_profile;
  end if;

  if v_profile.trangthai is not null and upper(v_profile.trangthai) <> 'HOATDONG' then
    raise exception 'This account is not active' using errcode = '42501';
  end if;

  return jsonb_build_object(
    'MaNguoiDung', v_profile.manguoidung,
    'TenDangNhap', v_profile.tendangnhap,
    'HoTen', v_profile.hoten,
    'Sdt', v_profile.sodienthoai,
    'Email', v_profile.email,
    'VaiTro', v_profile.vaitro
  );
end;
$$;

create or replace function public.get_public_availability(p_date date, p_masan integer default null)
returns table (masan integer, ngaysudung date, trangthai text, makhunggio integer)
language sql stable security definer
set search_path = ''
as $$
  select d.masan, d.ngaysudung, coalesce(d.trangthai, ''), dk.makhunggio
  from public.datsan d
  join public.datsan_khunggio dk on dk.madatsan = d.madatsan
  join public.san s on s.masan = d.masan and s.trangthai = 'HOATDONG'
  where d.ngaysudung = p_date
    and (p_masan is null or d.masan = p_masan)
    and upper(coalesce(d.trangthai, '')) not in ('DAHUY', 'DA_HUY', 'HUY');
$$;

create or replace function public.create_booking(
  p_masan integer,
  p_ngaysudung date,
  p_makhunggio integer[],
  p_dichvu jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_profile_id integer := public.current_nguoidung_id();
  v_role text := public.current_nguoidung_role();
  v_owner_id integer;
  v_rate numeric;
  v_sport text;
  v_football boolean;
  v_badminton boolean;
  v_tennis boolean;
  v_pickleball boolean;
  v_water boolean := coalesce((p_dichvu ->> 'water')::boolean, false);
  v_bibs boolean := coalesce((p_dichvu ->> 'bibs')::boolean, false);
  v_racket_badminton boolean := coalesce((p_dichvu ->> 'racketBadminton')::boolean, false);
  v_shuttlecock boolean := coalesce((p_dichvu ->> 'shuttlecock')::boolean, false);
  v_racket_tennis boolean := coalesce((p_dichvu ->> 'racketTennis')::boolean, false);
  v_hours numeric;
  v_base_total numeric;
  v_extra_total numeric := 0;
  v_total numeric;
  v_booking_id integer;
  v_slot record;
begin
  if v_profile_id is null or v_role not in ('KHACHHANG', 'CHUSAN') then
    raise exception 'A linked customer account is required to book a field' using errcode = '42501';
  end if;
  if p_ngaysudung < current_date or coalesce(array_length(p_makhunggio, 1), 0) = 0 then
    raise exception 'Choose a future date and at least one time slot' using errcode = '22023';
  end if;
  if (select count(distinct id) from unnest(p_makhunggio) as id) <> array_length(p_makhunggio, 1) then
    raise exception 'Duplicate time slots are not allowed' using errcode = '22023';
  end if;

  select s.machusan, s.giasan, lower(coalesce(l.tenloaisan, ''))
  into v_owner_id, v_rate, v_sport
  from public.san s join public.loaisan l on l.maloaisan = s.maloaisan
  where s.masan = p_masan and s.trangthai = 'HOATDONG';
  if not found then raise exception 'Field is not available' using errcode = 'P0002'; end if;
  if v_owner_id = v_profile_id then raise exception 'You cannot book your own field' using errcode = '42501'; end if;

  v_football := v_sport like '%bóng đá%' or v_sport like '%sân 5%' or v_sport like '%sân 7%' or v_sport like '%sân 11%';
  v_badminton := v_sport like '%cầu lông%';
  v_tennis := v_sport like '%tennis%';
  v_pickleball := v_sport like '%pickleball%' or v_sport like '%pick%';
  if (v_bibs and not v_football) or ((v_racket_badminton or v_shuttlecock) and not v_badminton) or (v_racket_tennis and not v_tennis) then
    raise exception 'Selected equipment does not match this sport' using errcode = '22023';
  end if;

  -- Serialize bookings by field/date/slot so simultaneous requests cannot claim the same slot.
  for v_slot in select unnest(p_makhunggio) as id order by id loop
    perform pg_advisory_xact_lock(hashtextextended(format('%s:%s:%s', p_masan, p_ngaysudung, v_slot.id), 0));
  end loop;

  if exists (
    select 1 from public.datsan d join public.datsan_khunggio dk on dk.madatsan = d.madatsan
    where d.masan = p_masan and d.ngaysudung = p_ngaysudung
      and dk.makhunggio = any(p_makhunggio)
      and upper(coalesce(d.trangthai, '')) not in ('DAHUY', 'DA_HUY', 'HUY')
  ) then raise exception 'One or more selected slots have just been booked' using errcode = '23P01'; end if;

  select sum(round(v_rate * extract(epoch from
    (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau
      else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600))::numeric,
    sum(extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau
      else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600)::numeric
  into v_base_total, v_hours
  from public.khunggio kg
  where kg.masan = p_masan and kg.makhunggio = any(p_makhunggio)
    and upper(coalesce(kg.trangthai, 'TRONG')) = 'TRONG';
  if v_base_total is null or (select count(*) from public.khunggio kg where kg.masan=p_masan and kg.makhunggio=any(p_makhunggio)
    and upper(coalesce(kg.trangthai, 'TRONG')) = 'TRONG') <> array_length(p_makhunggio,1) then
    raise exception 'A selected slot does not belong to this field' using errcode = '22023';
  end if;

  if v_water then v_extra_total := v_extra_total + case when v_football or v_pickleball then 150000 else 90000 end; end if;
  if v_bibs then v_extra_total := v_extra_total + 50000; end if;
  if v_racket_badminton then v_extra_total := v_extra_total + 80000 * v_hours; end if;
  if v_shuttlecock then v_extra_total := v_extra_total + 250000; end if;
  if v_racket_tennis then v_extra_total := v_extra_total + 100000 * v_hours; end if;
  v_total := v_base_total + v_extra_total;

  insert into public.datsan (makhachhang, masan, ngaysudung, tongtien, trangthai)
  values (v_profile_id, p_masan, p_ngaysudung, v_total, 'CHOXACNHAN')
  returning madatsan into v_booking_id;

  insert into public.datsan_khunggio (madatsan, makhunggio, giaapdung)
  select v_booking_id, kg.makhunggio,
    round(v_rate * extract(epoch from (case when kg.gioketthuc > kg.giobatdau then kg.gioketthuc - kg.giobatdau
      else kg.gioketthuc - kg.giobatdau + interval '24 hours' end)) / 3600)
  from public.khunggio kg where kg.masan = p_masan and kg.makhunggio = any(p_makhunggio)
    and upper(coalesce(kg.trangthai, 'TRONG')) = 'TRONG';

  return jsonb_build_object('madatsan', v_booking_id, 'tongtien', v_total);
end;
$$;

create or replace function public.guard_profile_update()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if (select public.current_nguoidung_role()) = 'ADMIN' then return new; end if;
  if old.auth_user_id is distinct from (select auth.uid())
    or new.manguoidung is distinct from old.manguoidung
    or new.auth_user_id is distinct from old.auth_user_id
    or new.vaitro is distinct from old.vaitro
    or new.sodienthoai is distinct from old.sodienthoai then
    raise exception 'Users can update only their own name and email' using errcode = '42501';
  end if;
  return new;
end;
$$;

create or replace function public.guard_field_update()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if (select public.current_nguoidung_role()) = 'ADMIN' then return new; end if;
  if old.machusan is distinct from (select public.current_nguoidung_id())
    or new.machusan is distinct from old.machusan
    or new.masan is distinct from old.masan
    or new.trangthai is distinct from old.trangthai then
    raise exception 'Field owner cannot transfer or approve a field' using errcode = '42501';
  end if;
  return new;
end;
$$;

create or replace function public.guard_booking_update()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if (select public.current_nguoidung_role()) = 'ADMIN' then return new; end if;
  if not exists (select 1 from public.san s where s.masan=old.masan and s.machusan=(select public.current_nguoidung_id()))
    or new.madatsan is distinct from old.madatsan
    or new.makhachhang is distinct from old.makhachhang
    or new.masan is distinct from old.masan
    or new.ngaydat is distinct from old.ngaydat
    or new.ngaysudung is distinct from old.ngaysudung
    or new.tongtien is distinct from old.tongtien
    or (old.trangthai = 'CHOXACNHAN' and coalesce(new.trangthai, '') not in ('DACANCOC','DAHUY','DA_HUY'))
    or (old.trangthai = 'DACANCOC' and coalesce(new.trangthai, '') not in ('HOANTHANH','DAHUY','DA_HUY'))
    or coalesce(old.trangthai, '') not in ('CHOXACNHAN','DACANCOC') then
    raise exception 'Field owner may update booking status only' using errcode = '42501';
  end if;
  return new;
end;
$$;

drop trigger if exists nguoidung_guard_profile_update on public.nguoidung;
create trigger nguoidung_guard_profile_update before update on public.nguoidung
  for each row execute function public.guard_profile_update();
drop trigger if exists san_guard_field_update on public.san;
create trigger san_guard_field_update before update on public.san
  for each row execute function public.guard_field_update();
drop trigger if exists datsan_guard_booking_update on public.datsan;
create trigger datsan_guard_booking_update before update on public.datsan
  for each row execute function public.guard_booking_update();

-- Remove the legacy policies that granted every operation to the public role.
do $$
declare p record;
begin
  for p in select schemaname, tablename, policyname from pg_policies
    where (schemaname = 'public' and tablename = any(array[
      'bookings','danhgia','datsan','datsan_khunggio','fields','khunggio',
      'loaisan','nguoidung','san','thanhtoan','thongbao','users','vitri'
    ]))
       or (schemaname = 'storage' and tablename = 'objects')
  loop
    execute format('drop policy %I on %I.%I', p.policyname, p.schemaname, p.tablename);
  end loop;
end $$;

alter table public.loaisan enable row level security;
alter table public.vitri enable row level security;
alter table public.san enable row level security;
alter table public.datsan enable row level security;
alter table public.datsan_khunggio enable row level security;
alter table public.khunggio enable row level security;
alter table public.nguoidung enable row level security;
alter table public.danhgia enable row level security;
alter table public.bookings enable row level security;
alter table public.fields enable row level security;
alter table public.thanhtoan enable row level security;
alter table public.thongbao enable row level security;
alter table public.users enable row level security;

create policy loaisan_read on public.loaisan for select to anon, authenticated using (true);
create policy vitri_read on public.vitri for select to anon, authenticated using (true);
create policy vitri_insert on public.vitri for insert to authenticated
  with check ((select public.current_nguoidung_role()) in ('KHACHHANG','CHUSAN','ADMIN'));
create policy san_read on public.san for select to anon, authenticated
  using (trangthai = 'HOATDONG' or machusan = (select public.current_nguoidung_id()) or (select public.current_nguoidung_role()) = 'ADMIN');
create policy san_insert on public.san for insert to authenticated
  with check ((select public.current_nguoidung_role()) = 'ADMIN' or
    (machusan = (select public.current_nguoidung_id()) and coalesce(trangthai, 'CHO_DUYET') = 'CHO_DUYET'));
create policy san_update on public.san for update to authenticated
  using (machusan = (select public.current_nguoidung_id()) or (select public.current_nguoidung_role()) = 'ADMIN')
  with check (machusan = (select public.current_nguoidung_id()) or (select public.current_nguoidung_role()) = 'ADMIN');
create policy san_delete_admin on public.san for delete to authenticated
  using ((select public.current_nguoidung_role()) = 'ADMIN');

create policy khunggio_read on public.khunggio for select to anon, authenticated
  using (exists (select 1 from public.san s where s.masan = khunggio.masan));
create policy khunggio_insert on public.khunggio for insert to authenticated
  with check (exists (select 1 from public.san s where s.masan = khunggio.masan and
    (s.machusan = (select public.current_nguoidung_id()) or (select public.current_nguoidung_role()) = 'ADMIN')));
create policy khunggio_update on public.khunggio for update to authenticated
  using (exists (select 1 from public.san s where s.masan = khunggio.masan and
    (s.machusan = (select public.current_nguoidung_id()) or (select public.current_nguoidung_role()) = 'ADMIN')))
  with check (exists (select 1 from public.san s where s.masan = khunggio.masan and
    (s.machusan = (select public.current_nguoidung_id()) or (select public.current_nguoidung_role()) = 'ADMIN')));
create policy khunggio_delete on public.khunggio for delete to authenticated
  using (exists (select 1 from public.san s where s.masan = khunggio.masan and
    (s.machusan = (select public.current_nguoidung_id()) or (select public.current_nguoidung_role()) = 'ADMIN')));

create policy nguoidung_read on public.nguoidung for select to authenticated
  using (auth_user_id = (select auth.uid()) or (select public.current_nguoidung_role()) = 'ADMIN' or exists (
    select 1 from public.datsan d join public.san s on s.masan = d.masan
    where d.makhachhang = nguoidung.manguoidung and s.machusan = (select public.current_nguoidung_id())
  ));
create policy nguoidung_update_self on public.nguoidung for update to authenticated
  using (auth_user_id = (select auth.uid())) with check (auth_user_id = (select auth.uid()));
create policy nguoidung_update_admin on public.nguoidung for update to authenticated
  using ((select public.current_nguoidung_role()) = 'ADMIN')
  with check ((select public.current_nguoidung_role()) = 'ADMIN');

create policy datsan_read on public.datsan for select to authenticated
  using (makhachhang = (select public.current_nguoidung_id()) or
    exists (select 1 from public.san s where s.masan = datsan.masan and s.machusan = (select public.current_nguoidung_id())) or
    (select public.current_nguoidung_role()) = 'ADMIN');
create policy datsan_update_owner_admin on public.datsan for update to authenticated
  using (exists (select 1 from public.san s where s.masan = datsan.masan and s.machusan = (select public.current_nguoidung_id())) or
    (select public.current_nguoidung_role()) = 'ADMIN')
  with check (exists (select 1 from public.san s where s.masan = datsan.masan and s.machusan = (select public.current_nguoidung_id())) or
    (select public.current_nguoidung_role()) = 'ADMIN');

create policy datsan_khunggio_read on public.datsan_khunggio for select to authenticated
  using (exists (select 1 from public.datsan d where d.madatsan = datsan_khunggio.madatsan));
create policy danhgia_read on public.danhgia for select to authenticated
  using (makhachhang = (select public.current_nguoidung_id()) or (select public.current_nguoidung_role()) = 'ADMIN');
create policy danhgia_insert on public.danhgia for insert to authenticated
  with check (makhachhang = (select public.current_nguoidung_id()) and exists (
    select 1 from public.datsan d where d.madatsan = danhgia.madatsan and d.makhachhang = (select public.current_nguoidung_id())
      and d.trangthai = 'HOANTHANH'));

-- Storage paths are scoped as fields/<manguoidung>/<filename>.
create policy san_images_public_read on storage.objects for select to anon, authenticated
  using (bucket_id = 'san-images');
create policy san_images_user_upload on storage.objects for insert to authenticated
  with check (bucket_id = 'san-images' and name like 'fields/' || (select public.current_nguoidung_id())::text || '/%');
create policy san_images_user_update on storage.objects for update to authenticated
  using (bucket_id = 'san-images' and name like 'fields/' || (select public.current_nguoidung_id())::text || '/%')
  with check (bucket_id = 'san-images' and name like 'fields/' || (select public.current_nguoidung_id())::text || '/%');
create policy san_images_user_delete on storage.objects for delete to authenticated
  using (bucket_id = 'san-images' and name like 'fields/' || (select public.current_nguoidung_id())::text || '/%');

revoke all on function public.current_nguoidung_id() from public;
revoke all on function public.current_nguoidung_role() from public;
grant execute on function public.current_nguoidung_id() to anon, authenticated;
grant execute on function public.current_nguoidung_role() to anon, authenticated;
revoke all on function public.ensure_current_nguoidung() from public, anon;
grant execute on function public.ensure_current_nguoidung() to authenticated;
revoke all on function public.guard_profile_update() from public, anon, authenticated;
revoke all on function public.guard_field_update() from public, anon, authenticated;
revoke all on function public.guard_booking_update() from public, anon, authenticated;
revoke all on function public.get_public_availability(date, integer) from public;
grant execute on function public.get_public_availability(date, integer) to anon, authenticated;
revoke all on function public.create_booking(integer, date, integer[], jsonb) from public, anon;
grant execute on function public.create_booking(integer, date, integer[], jsonb) to authenticated;

revoke all on table public.bookings, public.fields, public.thanhtoan, public.thongbao, public.users,
  public.loaisan, public.vitri, public.san, public.datsan, public.datsan_khunggio, public.khunggio,
  public.nguoidung, public.danhgia from anon, authenticated;
grant select on public.loaisan, public.vitri, public.san, public.khunggio to anon, authenticated;
grant select, insert, update, delete on public.san, public.khunggio, public.vitri to authenticated;
grant select, update on public.datsan to authenticated;
grant select on public.datsan_khunggio to authenticated;
grant insert, select on public.danhgia to authenticated;
grant select (manguoidung, tendangnhap, email, sodienthoai, hoten, vaitro, trangthai) on public.nguoidung to authenticated;
grant update (hoten, email, vaitro, trangthai) on public.nguoidung to authenticated;

do $$
declare item record; sequence_name text;
begin
  for item in select * from (values
    ('san','masan'), ('vitri','mavitri'), ('khunggio','makhunggio'), ('danhgia','madanhgia')
  ) as generated_keys(table_name, column_name)
  loop
    sequence_name := pg_get_serial_sequence('public.' || item.table_name, item.column_name);
    if sequence_name is not null then
      execute format('grant usage, select on sequence %s to authenticated', sequence_name::regclass);
    end if;
  end loop;
end $$;

