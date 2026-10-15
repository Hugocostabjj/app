-- =====================================================================
-- PAINEL DE OBRAS — configuração do banco (Supabase > SQL Editor > Run)
-- Cada construtora tem seus próprios dados e usuários.
-- Papéis: admin (tudo + usuários) | editor (vê e altera) | leitor (só vê)
-- =====================================================================

create extension if not exists pgcrypto;

create table if not exists construtoras (
  id          uuid primary key default gen_random_uuid(),
  nome        text not null,
  criado_por  uuid not null default auth.uid() references auth.users(id),
  criado_em   timestamptz default now()
);

create table if not exists membros (
  id              uuid primary key default gen_random_uuid(),
  construtora_id  uuid not null references construtoras(id) on delete cascade,
  email           text not null,
  user_id         uuid references auth.users(id) on delete set null,
  papel           text not null check (papel in ('admin','editor','leitor')),
  status          text not null default 'convidado' check (status in ('convidado','ativo')),
  criado_em       timestamptz default now(),
  unique (construtora_id, email)
);

create table if not exists painel_dados (
  construtora_id  uuid primary key references construtoras(id) on delete cascade,
  data            jsonb not null,
  atualizado_em   timestamptz default now(),
  atualizado_por  text
);

-- e-mails sempre em minúsculas
create or replace function membros_email_lower() returns trigger language plpgsql as $$
begin new.email := lower(trim(new.email)); return new; end $$;
drop trigger if exists trg_membros_email on membros;
create trigger trg_membros_email before insert or update on membros
  for each row execute function membros_email_lower();

-- papel do usuário logado numa construtora
create or replace function papel_em(cid uuid) returns text
language sql stable security definer set search_path = public as $$
  select papel from membros where construtora_id = cid and user_id = auth.uid() limit 1
$$;

-- vincula convites pendentes ao usuário logado e devolve as construtoras dele
create or replace function meu_acesso()
returns table(construtora_id uuid, nome text, papel text)
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return; end if;
  update membros set user_id = auth.uid(), status = 'ativo'
   where email = lower(auth.jwt()->>'email') and user_id is null;
  return query
    select m.construtora_id, c.nome, m.papel
      from membros m join construtoras c on c.id = m.construtora_id
     where m.user_id = auth.uid()
     order by m.criado_em;
end $$;

-- cria a construtora com o usuário logado como administrador
create or replace function criar_construtora(p_nome text) returns uuid
language plpgsql security definer set search_path = public as $$
declare cid uuid;
begin
  if auth.uid() is null then raise exception 'não autenticado'; end if;
  insert into construtoras(nome, criado_por) values (trim(p_nome), auth.uid()) returning id into cid;
  insert into membros(construtora_id, email, user_id, papel, status)
       values (cid, lower(auth.jwt()->>'email'), auth.uid(), 'admin', 'ativo');
  return cid;
end $$;

revoke execute on function meu_acesso() from anon;
revoke execute on function criar_construtora(text) from anon;

-- ---------------- regras de acesso (RLS) ----------------
alter table construtoras enable row level security;
alter table membros      enable row level security;
alter table painel_dados enable row level security;

drop policy if exists "ver construtora"        on construtoras;
drop policy if exists "admin edita construtora" on construtoras;
create policy "ver construtora" on construtoras for select to authenticated
  using (papel_em(id) is not null);
create policy "admin edita construtora" on construtoras for update to authenticated
  using (papel_em(id) = 'admin');

drop policy if exists "ver membros"          on membros;
drop policy if exists "admin insere membros" on membros;
drop policy if exists "admin altera membros" on membros;
drop policy if exists "admin remove membros" on membros;
create policy "ver membros" on membros for select to authenticated
  using (papel_em(construtora_id) is not null);
create policy "admin insere membros" on membros for insert to authenticated
  with check (papel_em(construtora_id) = 'admin');
create policy "admin altera membros" on membros for update to authenticated
  using (papel_em(construtora_id) = 'admin' and user_id is distinct from auth.uid())
  with check (papel_em(construtora_id) = 'admin');
create policy "admin remove membros" on membros for delete to authenticated
  using (papel_em(construtora_id) = 'admin' and user_id is distinct from auth.uid());

drop policy if exists "ver dados"     on painel_dados;
drop policy if exists "inserir dados" on painel_dados;
drop policy if exists "editar dados"  on painel_dados;
create policy "ver dados" on painel_dados for select to authenticated
  using (papel_em(construtora_id) is not null);
create policy "inserir dados" on painel_dados for insert to authenticated
  with check (papel_em(construtora_id) in ('admin','editor'));
create policy "editar dados" on painel_dados for update to authenticated
  using (papel_em(construtora_id) in ('admin','editor'))
  with check (papel_em(construtora_id) in ('admin','editor'));

-- a tabela antiga (versão sem login) não é mais usada:
-- drop table if exists painel_estado;
