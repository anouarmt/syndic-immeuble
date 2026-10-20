-- Registre du Syndic : schéma Supabase (tables préfixées syndic_), accès par code
-- Aucun accès direct aux tables : le site passe uniquement par les fonctions ci-dessous,
-- qui vérifient le code (code administrateur, code de gestion ou code de lecture de l'immeuble).
-- Les codes sont stockés chiffrés (bcrypt, extension pgcrypto). Prérequis : extension pgcrypto dans le schéma "extensions".

create table if not exists public.syndic_immeubles (
  id uuid primary key default gen_random_uuid(),
  owner uuid references auth.users(id) on delete set null,
  nom text not null default '',
  data jsonb not null default '{}'::jsonb,
  code_gestion text,
  code_lecture text,
  created_at timestamptz not null default now()
);
create table if not exists public.syndic_docs (
  id uuid primary key default gen_random_uuid(),
  immeuble_id uuid not null references public.syndic_immeubles(id) on delete cascade,
  col text not null check (col in ('etages','apparts','paiements','depenses')),
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
create table if not exists public.syndic_admin (id integer primary key default 1 check (id = 1), code_hash text not null);
create table if not exists public.syndic_echecs (at timestamptz not null default now());
create index if not exists syndic_docs_imm_col on public.syndic_docs (immeuble_id, col);
create index if not exists syndic_echecs_at on public.syndic_echecs (at);

alter table public.syndic_immeubles enable row level security;
alter table public.syndic_docs enable row level security;
alter table public.syndic_admin enable row level security;
alter table public.syndic_echecs enable row level security;
revoke all on public.syndic_immeubles, public.syndic_docs, public.syndic_admin, public.syndic_echecs from anon, authenticated;

-- Blocage après 30 codes faux en 15 minutes
create or replace function public.syndic_bloque() returns boolean
language sql stable security definer set search_path = '' as $fn$
  select (select count(*) from public.syndic_echecs e where e.at > now() - interval '15 minutes') >= 30;
$fn$;

-- Droit donné par un code sur un immeuble : admin, gestion, lecture ou null
create or replace function public.syndic_droit(p_code text, p_imm uuid) returns text
language sql stable security definer set search_path = '' as $fn$
  select case
    when public.syndic_bloque() or length(coalesce(p_code, '')) < 6 then null
    when exists (select 1 from public.syndic_admin a where a.code_hash = extensions.crypt(p_code, a.code_hash)) then 'admin'
    when exists (select 1 from public.syndic_immeubles i where i.id = p_imm and i.code_gestion is not null and i.code_gestion = extensions.crypt(p_code, i.code_gestion)) then 'gestion'
    when exists (select 1 from public.syndic_immeubles i where i.id = p_imm and i.code_lecture is not null and i.code_lecture = extensions.crypt(p_code, i.code_lecture)) then 'lecture'
  end;
$fn$;

-- Un code est libre s'il fait 6 caractères ou plus et n'est utilisé nulle part
create or replace function public.syndic_code_libre(p_code text) returns boolean
language sql stable security definer set search_path = '' as $fn$
  select length(coalesce(p_code, '')) >= 6
    and not exists (select 1 from public.syndic_admin a where a.code_hash = extensions.crypt(p_code, a.code_hash))
    and not exists (select 1 from public.syndic_immeubles i where (i.code_gestion is not null and i.code_gestion = extensions.crypt(p_code, i.code_gestion)) or (i.code_lecture is not null and i.code_lecture = extensions.crypt(p_code, i.code_lecture)));
$fn$;

-- Ouvre un code : renvoie le rôle et les immeubles accessibles, ou une erreur (code / bloque)
create or replace function public.syndic_ouvrir(p_code text) returns jsonb
language sql volatile security definer set search_path = '' as $fn$
  with blk as (select public.syndic_bloque() as b),
  adm as (
    select exists (select 1 from public.syndic_admin a where a.code_hash = extensions.crypt(p_code, a.code_hash)) as ok
    from blk where not blk.b and length(coalesce(p_code, '')) >= 6
  ),
  hit as (
    select i.id, i.nom,
      case when i.code_gestion is not null and i.code_gestion = extensions.crypt(p_code, i.code_gestion) then 'gestion' else 'lecture' end as role
    from public.syndic_immeubles i cross join blk
    where not blk.b and length(coalesce(p_code, '')) >= 6
      and ((i.code_gestion is not null and i.code_gestion = extensions.crypt(p_code, i.code_gestion))
        or (i.code_lecture is not null and i.code_lecture = extensions.crypt(p_code, i.code_lecture)))
    limit 1
  ),
  echec as (
    insert into public.syndic_echecs (at)
    select now() where not exists (select 1 from hit) and not coalesce((select ok from adm), false)
    returning 1
  )
  select case
    when (select b from blk) then jsonb_build_object('erreur', 'bloque')
    when coalesce((select ok from adm), false) then jsonb_build_object('role', 'admin', 'immeubles',
      coalesce((select jsonb_agg(jsonb_build_object('id', i.id, 'nom', i.nom) order by i.created_at) from public.syndic_immeubles i), '[]'::jsonb))
    when exists (select 1 from hit) then jsonb_build_object('role', (select role from hit), 'immeubles',
      jsonb_build_array((select jsonb_build_object('id', id, 'nom', nom) from hit)))
    else jsonb_build_object('erreur', 'code')
  end
  from (select count(*) from echec) f;
$fn$;

-- Charge un immeuble complet (configuration + étages, lots, paiements, dépenses)
create or replace function public.syndic_charger(p_code text, p_imm uuid) returns jsonb
language sql stable security definer set search_path = '' as $fn$
  with d as (select public.syndic_droit(p_code, p_imm) as r)
  select case when (select r from d) is null then null else jsonb_build_object(
    'role', (select r from d),
    'immeuble', (select jsonb_build_object('id', i.id, 'nom', i.nom, 'data', i.data, 'lecture', i.code_lecture is not null) from public.syndic_immeubles i where i.id = p_imm),
    'docs', coalesce((select jsonb_agg(jsonb_build_object('id', x.id, 'col', x.col, 'data', x.data)) from public.syndic_docs x where x.immeuble_id = p_imm), '[]'::jsonb)
  ) end;
$fn$;

create or replace function public.syndic_doc_ajouter(p_code text, p_imm uuid, p_col text, p_data jsonb) returns uuid
language sql volatile security definer set search_path = '' as $fn$
  insert into public.syndic_docs (immeuble_id, col, data)
  select p_imm, p_col, coalesce(p_data, '{}'::jsonb) where public.syndic_droit(p_code, p_imm) in ('admin', 'gestion')
  returning id;
$fn$;

create or replace function public.syndic_doc_modifier(p_code text, p_imm uuid, p_id uuid, p_data jsonb) returns uuid
language sql volatile security definer set search_path = '' as $fn$
  update public.syndic_docs set data = coalesce(p_data, '{}'::jsonb), updated_at = now()
  where id = p_id and immeuble_id = p_imm and public.syndic_droit(p_code, p_imm) in ('admin', 'gestion')
  returning id;
$fn$;

create or replace function public.syndic_doc_supprimer(p_code text, p_imm uuid, p_id uuid) returns uuid
language sql volatile security definer set search_path = '' as $fn$
  delete from public.syndic_docs
  where id = p_id and immeuble_id = p_imm and public.syndic_droit(p_code, p_imm) in ('admin', 'gestion')
  returning id;
$fn$;

create or replace function public.syndic_config_modifier(p_code text, p_imm uuid, p_nom text, p_data jsonb) returns uuid
language sql volatile security definer set search_path = '' as $fn$
  update public.syndic_immeubles set nom = coalesce(p_nom, ''), data = coalesce(p_data, '{}'::jsonb)
  where id = p_imm and public.syndic_droit(p_code, p_imm) in ('admin', 'gestion')
  returning id;
$fn$;

create or replace function public.syndic_imm_creer(p_admin text, p_nom text, p_gestion text, p_lecture text) returns uuid
language sql volatile security definer set search_path = '' as $fn$
  insert into public.syndic_immeubles (nom, data, code_gestion, code_lecture)
  select coalesce(p_nom, ''), jsonb_build_object('debut', to_char(now(), 'YYYY') || '-01', 'cotisationDefaut', 0, 'soldeInitial', 0),
         extensions.crypt(p_gestion, extensions.gen_salt('bf')),
         case when coalesce(p_lecture, '') = '' then null else extensions.crypt(p_lecture, extensions.gen_salt('bf')) end
  where exists (select 1 from public.syndic_admin a where a.code_hash = extensions.crypt(p_admin, a.code_hash))
    and not public.syndic_bloque()
    and public.syndic_code_libre(p_gestion)
    and (coalesce(p_lecture, '') = '' or (public.syndic_code_libre(p_lecture) and p_lecture <> p_gestion))
  returning id;
$fn$;

-- Remplace les codes d'un immeuble (gestion ou admin). p_lecture : null = inchangé, '' = désactivé
create or replace function public.syndic_codes_modifier(p_code text, p_imm uuid, p_gestion text, p_lecture text) returns uuid
language sql volatile security definer set search_path = '' as $fn$
  update public.syndic_immeubles set
    code_gestion = case when coalesce(p_gestion, '') = '' then code_gestion else extensions.crypt(p_gestion, extensions.gen_salt('bf')) end,
    code_lecture = case when p_lecture is null then code_lecture when p_lecture = '' then null else extensions.crypt(p_lecture, extensions.gen_salt('bf')) end
  where id = p_imm
    and public.syndic_droit(p_code, p_imm) in ('admin', 'gestion')
    and (coalesce(p_gestion, '') = '' or public.syndic_code_libre(p_gestion))
    and (coalesce(p_lecture, '') = '' or (public.syndic_code_libre(p_lecture) and p_lecture is distinct from p_gestion))
  returning id;
$fn$;

create or replace function public.syndic_imm_supprimer(p_admin text, p_imm uuid) returns uuid
language sql volatile security definer set search_path = '' as $fn$
  delete from public.syndic_immeubles
  where id = p_imm and public.syndic_droit(p_admin, p_imm) = 'admin'
  returning id;
$fn$;

create or replace function public.syndic_admin_modifier(p_ancien text, p_nouveau text) returns boolean
language sql volatile security definer set search_path = '' as $fn$
  with u as (
    update public.syndic_admin set code_hash = extensions.crypt(p_nouveau, extensions.gen_salt('bf'))
    where id = 1 and code_hash = extensions.crypt(p_ancien, code_hash) and not public.syndic_bloque()
      and length(coalesce(p_nouveau, '')) >= 8 and public.syndic_code_libre(p_nouveau)
    returning 1
  )
  select exists (select 1 from u);
$fn$;

revoke all on function public.syndic_bloque(), public.syndic_droit(text, uuid), public.syndic_code_libre(text) from public, anon, authenticated;
revoke all on function public.syndic_ouvrir(text), public.syndic_charger(text, uuid), public.syndic_doc_ajouter(text, uuid, text, jsonb), public.syndic_doc_modifier(text, uuid, uuid, jsonb), public.syndic_doc_supprimer(text, uuid, uuid), public.syndic_config_modifier(text, uuid, text, jsonb), public.syndic_imm_creer(text, text, text, text), public.syndic_codes_modifier(text, uuid, text, text), public.syndic_imm_supprimer(text, uuid), public.syndic_admin_modifier(text, text) from public;
grant execute on function public.syndic_ouvrir(text), public.syndic_charger(text, uuid), public.syndic_doc_ajouter(text, uuid, text, jsonb), public.syndic_doc_modifier(text, uuid, uuid, jsonb), public.syndic_doc_supprimer(text, uuid, uuid), public.syndic_config_modifier(text, uuid, text, jsonb), public.syndic_imm_creer(text, text, text, text), public.syndic_codes_modifier(text, uuid, text, text), public.syndic_imm_supprimer(text, uuid), public.syndic_admin_modifier(text, text) to anon, authenticated;

-- Code administrateur initial (à remplacer depuis Paramètres) :
-- insert into public.syndic_admin (id, code_hash) values (1, extensions.crypt('VOTRE-CODE', extensions.gen_salt('bf')));
