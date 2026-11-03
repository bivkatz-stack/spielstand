begin;

alter table public.game_players
  add column if not exists access_level text not null default 'editor'
  check (access_level in ('viewer', 'editor'));

alter table public.game_players
  drop constraint if exists game_players_player_id_owner_id_fkey;

alter table public.game_players
  add constraint game_players_player_id_fkey
  foreign key (player_id) references public.players(id) on delete restrict;

alter table public.games
  drop constraint if exists games_starting_player_id_owner_id_fkey;

alter table public.games
  add constraint games_starting_player_id_fkey
  foreign key (starting_player_id) references public.players(id) on delete restrict;

create table if not exists public.game_invites (
  token uuid primary key default gen_random_uuid(),
  game_id uuid not null,
  owner_id uuid not null,
  permission text not null check (permission in ('viewer', 'editor')),
  created_at timestamptz not null default now(),
  unique (game_id),
  foreign key (game_id, owner_id)
    references public.games (id, owner_id)
    on delete cascade
);

create index if not exists game_invites_owner_idx
  on public.game_invites (owner_id, game_id);

alter table public.game_invites enable row level security;

drop policy if exists "Players belong to the authenticated owner" on public.players;
drop policy if exists "Games belong to the authenticated owner" on public.games;
drop policy if exists "Game participants belong to the authenticated owner" on public.game_players;
drop policy if exists "Rounds belong to the authenticated owner" on public.rounds;
drop policy if exists "Round scores belong to the authenticated owner" on public.round_scores;
drop policy if exists "Round events belong to the authenticated owner" on public.round_events;

create or replace function public.can_view_game(p_game_id uuid, p_owner_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.games g
    where g.id = p_game_id
      and g.owner_id = p_owner_id
      and g.owner_id = auth.uid()
  ) or exists (
    select 1
    from public.game_players gp
    join public.players p on p.id = gp.player_id
    where gp.game_id = p_game_id
      and gp.owner_id = p_owner_id
      and p.owner_id = auth.uid()
  );
$$;

create or replace function public.can_edit_game(p_game_id uuid, p_owner_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.games g
    where g.id = p_game_id
      and g.owner_id = p_owner_id
      and g.owner_id = auth.uid()
  ) or exists (
    select 1
    from public.game_players gp
    join public.players p on p.id = gp.player_id
    where gp.game_id = p_game_id
      and gp.owner_id = p_owner_id
      and p.owner_id = auth.uid()
      and exists (
        select 1
        from public.game_invites gi
        where gi.game_id = gp.game_id
          and gi.owner_id = gp.owner_id
          and gi.permission = 'editor'
      )
  );
$$;

revoke all on function public.can_view_game(uuid, uuid) from public, anon;
revoke all on function public.can_edit_game(uuid, uuid) from public, anon;
grant execute on function public.can_view_game(uuid, uuid) to authenticated;
grant execute on function public.can_edit_game(uuid, uuid) to authenticated;

create policy "Players are visible to their owner or a shared game"
  on public.players for select to authenticated
  using (
    owner_id = (select auth.uid())
    or exists (
      select 1
      from public.game_players gp
      where gp.player_id = players.id
        and public.can_view_game(gp.game_id, gp.owner_id)
    )
  );
create policy "Players can only be created by their owner"
  on public.players for insert to authenticated
  with check (owner_id = (select auth.uid()));
create policy "Players can only be changed by their owner"
  on public.players for update to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));
create policy "Players can only be deleted by their owner"
  on public.players for delete to authenticated
  using (owner_id = (select auth.uid()));

create policy "Games are visible to owners and participants"
  on public.games for select to authenticated
  using (public.can_view_game(id, owner_id));
create policy "Games can only be created by their owner"
  on public.games for insert to authenticated
  with check (owner_id = (select auth.uid()));
create policy "Games can only be changed by their owner"
  on public.games for update to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));
create policy "Games can only be deleted by their owner"
  on public.games for delete to authenticated
  using (owner_id = (select auth.uid()));

create policy "Participants are visible to game members"
  on public.game_players for select to authenticated
  using (public.can_view_game(game_id, owner_id));
create policy "Owners add participants"
  on public.game_players for insert to authenticated
  with check (owner_id = (select auth.uid()));
create policy "Owners update participants"
  on public.game_players for update to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));
create policy "Owners remove participants"
  on public.game_players for delete to authenticated
  using (owner_id = (select auth.uid()));

create policy "Rounds are visible to game members"
  on public.rounds for select to authenticated
  using (public.can_view_game(game_id, owner_id));
create policy "Editors create rounds"
  on public.rounds for insert to authenticated
  with check (public.can_edit_game(game_id, owner_id));
create policy "Editors update rounds"
  on public.rounds for update to authenticated
  using (public.can_edit_game(game_id, owner_id))
  with check (public.can_edit_game(game_id, owner_id));
create policy "Editors delete rounds"
  on public.rounds for delete to authenticated
  using (public.can_edit_game(game_id, owner_id));

create policy "Scores are visible to game members"
  on public.round_scores for select to authenticated
  using (public.can_view_game(game_id, owner_id));
create policy "Editors add scores"
  on public.round_scores for insert to authenticated
  with check (public.can_edit_game(game_id, owner_id));
create policy "Editors update scores"
  on public.round_scores for update to authenticated
  using (public.can_edit_game(game_id, owner_id))
  with check (public.can_edit_game(game_id, owner_id));
create policy "Editors delete scores"
  on public.round_scores for delete to authenticated
  using (public.can_edit_game(game_id, owner_id));

create policy "Events are visible to game members"
  on public.round_events for select to authenticated
  using (public.can_view_game(game_id, owner_id));
create policy "Editors add events"
  on public.round_events for insert to authenticated
  with check (public.can_edit_game(game_id, owner_id));
create policy "Editors update events"
  on public.round_events for update to authenticated
  using (public.can_edit_game(game_id, owner_id))
  with check (public.can_edit_game(game_id, owner_id));
create policy "Editors delete events"
  on public.round_events for delete to authenticated
  using (public.can_edit_game(game_id, owner_id));

create policy "Invites are manageable by their owner"
  on public.game_invites for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

grant select, insert, update, delete on public.game_invites to authenticated;

create or replace function public.join_game(p_token uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  invite public.game_invites%rowtype;
  game_row public.games%rowtype;
  joining_player_id uuid;
  existing_member boolean;
  next_seat integer;
begin
  if auth.uid() is null then
    raise exception 'Anmeldung erforderlich';
  end if;

  select * into invite
  from public.game_invites gi
  where gi.token = p_token;

  if not found then
    raise exception 'Dieser Einladungslink ist ungültig oder wurde widerrufen';
  end if;

  select * into game_row
  from public.games g
  where g.id = invite.game_id
    and g.owner_id = invite.owner_id
  for update;

  if not found then
    raise exception 'Die Partie existiert nicht mehr';
  end if;

  select p.id into joining_player_id
  from public.players p
  where p.owner_id = auth.uid()
  order by p.created_at asc
  limit 1;

  if joining_player_id is null then
    raise exception 'Für dein Konto wurde noch kein Spielerprofil angelegt';
  end if;

  select exists (
    select 1
    from public.game_players gp
    where gp.game_id = game_row.id
      and gp.owner_id = game_row.owner_id
      and gp.player_id = joining_player_id
  ) into existing_member;

  if not existing_member then
    select coalesce(max(gp.seat_order), 0) + 1 into next_seat
    from public.game_players gp
    where gp.game_id = game_row.id
      and gp.owner_id = game_row.owner_id;

    if next_seat > 20 then
      raise exception 'Diese Partie hat bereits 20 Mitspielende';
    end if;

    insert into public.game_players (game_id, owner_id, player_id, seat_order, access_level)
    values (game_row.id, game_row.owner_id, joining_player_id, next_seat, invite.permission);

    insert into public.round_scores (game_id, owner_id, round_id, player_id, points)
    select r.game_id, r.owner_id, r.id, joining_player_id, 0
    from public.rounds r
    where r.game_id = game_row.id
      and r.owner_id = game_row.owner_id
    on conflict (round_id, player_id) do nothing;
  elsif game_row.owner_id <> auth.uid() then
    update public.game_players gp
    set access_level = invite.permission
    where gp.game_id = game_row.id
      and gp.owner_id = game_row.owner_id
      and gp.player_id = joining_player_id;
  end if;

  return jsonb_build_object(
    'game_id', game_row.id,
    'game_name', game_row.name,
    'permission', invite.permission
  );
end;
$$;

revoke all on function public.join_game(uuid) from public, anon;
grant execute on function public.join_game(uuid) to authenticated;

notify pgrst, 'reload schema';

commit;
