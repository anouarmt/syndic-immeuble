-- Registre du Syndic : schéma Supabase (tables préfixées syndic_)
-- Rôles : propriétaire de l'immeuble (owner), gestionnaire (lecture + écriture), lecteur (lecture seule)

create table if not exists public.syndic_immeubles (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null default auth.uid() references auth.users(id) on delete cascade,
  nom text not null default '',
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.syndic_membres (
  immeuble_id uuid not null references public.syndic_immeubles(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  email text not null default '',
  role text not null check (role in ('gestionnaire','lecteur')),
  created_at timestamptz not null default now(),
  primary key (immeuble_id, user_id)
);

create table if not exists public.syndic_invitations (
  immeuble_id uuid not null references public.syndic_immeubles(id) on delete cascade,
  email text not null,
  role text not null check (role in ('gestionnaire','lecteur')),
  created_at timestamptz not null default now(),
  primary key (immeuble_id, email)
);

create table if not exists public.syndic_docs (
  id uuid primary key default gen_random_uuid(),
  immeuble_id uuid not null references public.syndic_immeubles(id) on delete cascade,
  col text not null check (col in ('etages','apparts','paiements','depenses')),
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
create index if not exists syndic_docs_imm_col on public.syndic_docs (immeuble_id, col);
create index if not exists syndic_membres_user on public.syndic_membres (user_id);
create index if not exists syndic_immeubles_owner on public.syndic_immeubles (owner);

-- Rôle de l'utilisateur connecté sur un immeuble : 'owner', 'gestionnaire', 'lecteur' ou null
create or replace function public.syndic_role(imm uuid)
returns text language sql stable security definer set search_path = '' as $$
  select case
    when exists (select 1 from public.syndic_immeubles i where i.id = imm and i.owner = (select auth.uid())) then 'owner'
    else (select m.role from public.syndic_membres m where m.immeuble_id = imm and m.user_id = (select auth.uid()))
  end;
$$;

-- Accepte les invitations en attente pour l'e-mail du compte connecté
create or replace function public.syndic_accepter_invitations()
returns integer language sql volatile security definer set search_path = '' as $fn$
  with me as (
    select (select auth.uid()) as uid,
           lower(coalesce(nullif(current_setting('request.jwt.claims', true), '')::json ->> 'email', '')) as em
  ),
  ins as (
    insert into public.syndic_membres (immeuble_id, user_id, email, role)
    select i.immeuble_id, me.uid, me.em, i.role
    from public.syndic_invitations i cross join me
    where me.uid is not null and me.em <> '' and lower(i.email) = me.em
      and not exists (select 1 from public.syndic_immeubles x where x.id = i.immeuble_id and x.owner = me.uid)
    on conflict (immeuble_id, user_id) do update set role = excluded.role, email = excluded.email
    returning 1
  ),
  purge as (
    delete from public.syndic_invitations i using me
    where me.uid is not null and me.em <> '' and lower(i.email) = me.em
    returning 1
  )
  select (select count(*) from ins)::integer + 0 * (select count(*) from purge)::integer;
$fn$;

revoke all on function public.syndic_role(uuid) from public, anon;
revoke all on function public.syndic_accepter_invitations() from public, anon;
grant execute on function public.syndic_role(uuid) to authenticated;
grant execute on function public.syndic_accepter_invitations() to authenticated;

alter table public.syndic_immeubles enable row level security;
alter table public.syndic_membres enable row level security;
alter table public.syndic_invitations enable row level security;
alter table public.syndic_docs enable row level security;

-- Immeubles
create policy syndic_imm_select on public.syndic_immeubles for select to authenticated
  using (owner = (select auth.uid()) or public.syndic_role(id) is not null);
create policy syndic_imm_insert on public.syndic_immeubles for insert to authenticated
  with check (owner = (select auth.uid()));
create policy syndic_imm_update on public.syndic_immeubles for update to authenticated
  using (public.syndic_role(id) in ('owner','gestionnaire'))
  with check (public.syndic_role(id) in ('owner','gestionnaire'));
create policy syndic_imm_delete on public.syndic_immeubles for delete to authenticated
  using (owner = (select auth.uid()));

-- Membres : visibles par les membres de l'immeuble, gérés par le propriétaire ; chacun peut se retirer
create policy syndic_mem_select on public.syndic_membres for select to authenticated
  using (public.syndic_role(immeuble_id) is not null);
create policy syndic_mem_update on public.syndic_membres for update to authenticated
  using (public.syndic_role(immeuble_id) = 'owner') with check (public.syndic_role(immeuble_id) = 'owner');
create policy syndic_mem_delete on public.syndic_membres for delete to authenticated
  using (public.syndic_role(immeuble_id) = 'owner' or user_id = (select auth.uid()));

-- Invitations : gérées par le propriétaire
create policy syndic_inv_select on public.syndic_invitations for select to authenticated
  using (public.syndic_role(immeuble_id) = 'owner');
create policy syndic_inv_insert on public.syndic_invitations for insert to authenticated
  with check (public.syndic_role(immeuble_id) = 'owner');
create policy syndic_inv_update on public.syndic_invitations for update to authenticated
  using (public.syndic_role(immeuble_id) = 'owner') with check (public.syndic_role(immeuble_id) = 'owner');
create policy syndic_inv_delete on public.syndic_invitations for delete to authenticated
  using (public.syndic_role(immeuble_id) = 'owner');

-- Données (étages, lots, paiements, dépenses)
create policy syndic_docs_select on public.syndic_docs for select to authenticated
  using (public.syndic_role(immeuble_id) is not null);
create policy syndic_docs_insert on public.syndic_docs for insert to authenticated
  with check (public.syndic_role(immeuble_id) in ('owner','gestionnaire'));
create policy syndic_docs_update on public.syndic_docs for update to authenticated
  using (public.syndic_role(immeuble_id) in ('owner','gestionnaire'))
  with check (public.syndic_role(immeuble_id) in ('owner','gestionnaire'));
create policy syndic_docs_delete on public.syndic_docs for delete to authenticated
  using (public.syndic_role(immeuble_id) in ('owner','gestionnaire'));

revoke all on public.syndic_immeubles, public.syndic_membres, public.syndic_invitations, public.syndic_docs from anon;
grant select, insert, update, delete on public.syndic_immeubles, public.syndic_docs, public.syndic_invitations to authenticated;
grant select, update, delete on public.syndic_membres to authenticated;
