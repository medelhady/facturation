-- إدارة المستخدمين من داخل الموقع (إضافة / إيقاف / تفعيل)
-- شغّل هذا الملف مرة واحدة في Supabase > SQL Editor
create extension if not exists pgcrypto;

create table if not exists app_admins (user_id uuid primary key references auth.users(id) on delete cascade);
alter table app_admins enable row level security;

-- أول مستخدم تم إنشاؤه يصبح مدير المستخدمين
insert into app_admins select id from auth.users order by created_at limit 1 on conflict do nothing;

create or replace function _assert_admin() returns void language plpgsql security definer set search_path = public, auth as $$
begin
  if not exists (select 1 from app_admins where user_id = auth.uid()) then
    raise exception 'not allowed';
  end if;
end $$;

create or replace function admin_list_users()
returns table(id uuid, email text, banned boolean, is_admin boolean, created_at timestamptz)
language plpgsql security definer set search_path = public, auth as $$
begin
  perform _assert_admin();
  return query select u.id, u.email::text, (u.banned_until is not null and u.banned_until > now()),
    exists(select 1 from app_admins a where a.user_id = u.id), u.created_at
    from auth.users u order by u.created_at;
end $$;

create or replace function admin_create_user(p_email text, p_password text)
returns void language plpgsql security definer set search_path = public, auth, extensions as $$
declare uid uuid := gen_random_uuid();
begin
  perform _assert_admin();
  if length(p_password) < 6 then raise exception 'password too short'; end if;
  if exists (select 1 from auth.users where email = lower(p_email)) then raise exception 'exists'; end if;
  insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
    confirmation_token, recovery_token, email_change, email_change_token_new)
  values ('00000000-0000-0000-0000-000000000000', uid, 'authenticated', 'authenticated', lower(p_email),
    extensions.crypt(p_password, extensions.gen_salt('bf')), now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');
  insert into auth.identities (id, user_id, identity_data, provider, provider_id, last_sign_in_at, created_at, updated_at)
  values (gen_random_uuid(), uid, jsonb_build_object('sub', uid::text, 'email', lower(p_email), 'email_verified', true),
    'email', uid::text, now(), now(), now());
end $$;

create or replace function admin_set_ban(p_id uuid, p_ban boolean)
returns void language plpgsql security definer set search_path = public, auth as $$
begin
  perform _assert_admin();
  if p_id = auth.uid() then raise exception 'cannot change self'; end if;
  update auth.users set banned_until = case when p_ban then 'infinity'::timestamptz else null end where id = p_id;
  if p_ban then delete from auth.sessions where user_id = p_id; end if;
end $$;

create or replace function am_i_admin() returns boolean language sql security definer set search_path = public as $$
  select exists (select 1 from app_admins where user_id = auth.uid())
$$;
revoke all on function am_i_admin() from public, anon;
grant execute on function am_i_admin() to authenticated;

-- نقل صلاحية المدير إلى مستخدم آخر (المدير الحالي يفقدها)
create or replace function admin_transfer(p_id uuid)
returns void language plpgsql security definer set search_path = public, auth as $$
begin
  perform _assert_admin();
  if p_id = auth.uid() then raise exception 'already admin'; end if;
  if not exists (select 1 from auth.users where id = p_id and (banned_until is null or banned_until < now())) then raise exception 'invalid user'; end if;
  delete from app_admins where user_id is not null;
  insert into app_admins values (p_id);
end $$;

revoke all on function admin_transfer(uuid) from public, anon;
grant execute on function admin_transfer(uuid) to authenticated;

revoke all on function admin_list_users(), admin_create_user(text,text), admin_set_ban(uuid,boolean) from public, anon;
grant execute on function admin_list_users(), admin_create_user(text,text), admin_set_ban(uuid,boolean) to authenticated;
