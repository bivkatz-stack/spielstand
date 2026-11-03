begin;

create table public.players (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (char_length(btrim(name)) between 1 and 40),
  created_at timestamptz not null default now(),
  unique (id, owner_id)
);

create unique index players_owner_name_unique
  on public.players (owner_id, lower(btrim(name)));

create table public.games (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null default 'Rommé' check (char_length(btrim(name)) between 1 and 60),
  starting_player_id uuid not null,
  created_at timestamptz not null default now(),
  unique (id, owner_id),
  foreign key (starting_player_id, owner_id)
    references public.players (id, owner_id)
    on delete restrict
);

create table public.game_players (
  game_id uuid not null,
  owner_id uuid not null,
  player_id uuid not null,
  seat_order smallint not null check (seat_order > 0),
  primary key (game_id, player_id),
  unique (game_id, seat_order),
  unique (game_id, owner_id, player_id),
  foreign key (game_id, owner_id)
    references public.games (id, owner_id)
    on delete cascade,
  foreign key (player_id, owner_id)
    references public.players (id, owner_id)
    on delete restrict
);

create table public.rounds (
  id uuid primary key default gen_random_uuid(),
  game_id uuid not null,
  owner_id uuid not null,
  round_number integer not null check (round_number > 0),
  starter_player_id uuid not null,
  winner_player_id uuid not null,
  created_at timestamptz not null default now(),
  unique (game_id, round_number),
  unique (id, game_id, owner_id),
  foreign key (game_id, owner_id)
    references public.games (id, owner_id)
    on delete cascade,
  foreign key (game_id, owner_id, starter_player_id)
    references public.game_players (game_id, owner_id, player_id)
    on delete restrict,
  foreign key (game_id, owner_id, winner_player_id)
    references public.game_players (game_id, owner_id, player_id)
    on delete restrict
);

create table public.round_scores (
  game_id uuid not null,
  owner_id uuid not null,
  round_id uuid not null,
  player_id uuid not null,
  points numeric not null default 0 check (points <> 'NaN'::numeric),
  primary key (round_id, player_id),
  foreign key (round_id, game_id, owner_id)
    references public.rounds (id, game_id, owner_id)
    on delete cascade,
  foreign key (game_id, owner_id, player_id)
    references public.game_players (game_id, owner_id, player_id)
    on delete restrict
);

create table public.round_events (
  game_id uuid not null,
  owner_id uuid not null,
  round_id uuid not null,
  player_id uuid not null,
  event_type text not null check (event_type in (
    'joker_from_discard',
    'three_aces',
    'two_aces_joker'
  )),
  primary key (round_id, player_id, event_type),
  foreign key (round_id, game_id, owner_id)
    references public.rounds (id, game_id, owner_id)
    on delete cascade,
  foreign key (game_id, owner_id, player_id)
    references public.game_players (game_id, owner_id, player_id)
    on delete restrict
);

create index games_owner_created_at_idx
  on public.games (owner_id, created_at desc);
create index rounds_game_round_idx
  on public.rounds (game_id, round_number);
create index round_scores_game_player_idx
  on public.round_scores (game_id, player_id);
create index round_events_game_player_type_idx
  on public.round_events (game_id, player_id, event_type);

alter table public.players enable row level security;
alter table public.games enable row level security;
alter table public.game_players enable row level security;
alter table public.rounds enable row level security;
alter table public.round_scores enable row level security;
alter table public.round_events enable row level security;

create policy "Players belong to the authenticated owner"
  on public.players for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

create policy "Games belong to the authenticated owner"
  on public.games for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

create policy "Game participants belong to the authenticated owner"
  on public.game_players for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

create policy "Rounds belong to the authenticated owner"
  on public.rounds for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

create policy "Round scores belong to the authenticated owner"
  on public.round_scores for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

create policy "Round events belong to the authenticated owner"
  on public.round_events for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

grant usage on schema public to authenticated;
grant select, insert, update, delete on
  public.players,
  public.games,
  public.game_players,
  public.rounds,
  public.round_scores,
  public.round_events
to authenticated;

commit;
