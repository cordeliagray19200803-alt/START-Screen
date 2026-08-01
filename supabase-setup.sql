-- ============================================================
-- 緊急医療情報アプリ：個人情報保護強化版
-- Supabase SQL Editorで一度だけ実行してください。
-- 医療情報本文はEdge Functionで暗号化してから保存します。
-- ブラウザからテーブルを直接読み書きする権限は与えません。
-- ============================================================

create extension if not exists pgcrypto;

-- 旧試作版の匿名公開関数を無効化します。
drop function if exists public.get_public_medical_profile(uuid);
do $$
begin
  if to_regclass('public.medical_profiles') is not null then
    execute 'alter table public.medical_profiles enable row level security';
    execute 'revoke all on table public.medical_profiles from anon, authenticated';
  end if;
end $$;

create table if not exists public.secure_medical_profiles (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null unique references auth.users(id) on delete cascade,

  -- 本人用データ：AES-256-GCM暗号文
  private_ciphertext text not null,
  private_iv text not null,

  -- 救急表示用に本人が許可した項目だけを暗号化
  public_ciphertext text not null,
  public_iv text not null,

  -- 公開リンクの秘密トークンは平文保存しません。
  public_token_hash text not null unique,
  public_token_ciphertext text not null,
  public_token_iv text not null,
  public_enabled boolean not null default true,

  consent_version text not null,
  consent_accepted_at timestamptz not null,
  revision bigint not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.consent_records (
  id bigint generated always as identity primary key,
  owner_id uuid not null,
  profile_id uuid not null references public.secure_medical_profiles(id) on delete cascade,
  consent_version text not null,
  sensitive_data_consent boolean not null,
  emergency_display_consent boolean not null,
  accepted_at timestamptz not null default now()
);

-- 監査記録には医療情報本文、氏名、メールアドレス、電話番号を保存しません。
create table if not exists public.security_audit (
  id bigint generated always as identity primary key,
  owner_id uuid,
  profile_id uuid,
  event_type text not null,
  result text not null default 'success',
  ip_hash text not null,
  user_agent_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.emergency_access_log (
  id bigint generated always as identity primary key,
  profile_id uuid not null references public.secure_medical_profiles(id) on delete cascade,
  ip_hash text not null,
  user_agent_hash text not null,
  result text not null default 'success',
  accessed_at timestamptz not null default now()
);

create table if not exists public.emergency_rate_limits (
  profile_id uuid not null references public.secure_medical_profiles(id) on delete cascade,
  ip_hash text not null,
  window_start timestamptz not null,
  request_count integer not null default 1,
  primary key (profile_id, ip_hash, window_start)
);

create index if not exists idx_secure_profiles_public_hash
  on public.secure_medical_profiles(public_token_hash)
  where public_enabled = true;
create index if not exists idx_audit_owner_created
  on public.security_audit(owner_id, created_at desc);
create index if not exists idx_access_profile_created
  on public.emergency_access_log(profile_id, accessed_at desc);

-- 全テーブルでRLSを有効化し、ブラウザからの直接アクセスを禁止します。
alter table public.secure_medical_profiles enable row level security;
alter table public.consent_records enable row level security;
alter table public.security_audit enable row level security;
alter table public.emergency_access_log enable row level security;
alter table public.emergency_rate_limits enable row level security;

revoke all on table public.secure_medical_profiles from anon, authenticated;
revoke all on table public.consent_records from anon, authenticated;
revoke all on table public.security_audit from anon, authenticated;
revoke all on table public.emergency_access_log from anon, authenticated;
revoke all on table public.emergency_rate_limits from anon, authenticated;

-- service_roleはEdge Function内だけで使用します。
grant all on table public.secure_medical_profiles to service_role;
grant all on table public.consent_records to service_role;
grant all on table public.security_audit to service_role;
grant all on table public.emergency_access_log to service_role;
grant all on table public.emergency_rate_limits to service_role;
grant usage, select on all sequences in schema public to service_role;

-- 一定時間内の公開アクセス数を原子的に計数します。
create or replace function public.check_emergency_rate_limit(
  p_profile_id uuid,
  p_ip_hash text,
  p_limit integer default 60,
  p_window_seconds integer default 600
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_window timestamptz;
  v_count integer;
begin
  if p_limit < 1 or p_limit > 300 then
    raise exception 'invalid limit';
  end if;
  if p_window_seconds < 60 or p_window_seconds > 3600 then
    raise exception 'invalid window';
  end if;

  v_window := to_timestamp(
    floor(extract(epoch from now()) / p_window_seconds) * p_window_seconds
  );

  insert into public.emergency_rate_limits(profile_id, ip_hash, window_start, request_count)
  values(p_profile_id, p_ip_hash, v_window, 1)
  on conflict(profile_id, ip_hash, window_start)
  do update set request_count = public.emergency_rate_limits.request_count + 1
  returning request_count into v_count;

  -- 古いレート制限記録は自動的に掃除します。
  delete from public.emergency_rate_limits
  where window_start < now() - interval '2 hours';

  return v_count <= p_limit;
end;
$$;

revoke all on function public.check_emergency_rate_limit(uuid,text,integer,integer) from public, anon, authenticated;
grant execute on function public.check_emergency_rate_limit(uuid,text,integer,integer) to service_role;

-- 監査ログは90日、公開アクセスログは30日で削除する運用を推奨します。
-- Supabase Cronを使う場合の例：
-- delete from public.security_audit where created_at < now() - interval '90 days';
-- delete from public.emergency_access_log where accessed_at < now() - interval '30 days';
