-- profiles has no row level security (planted finding)
create table public.profiles (id uuid primary key, display_name text);

create table public.notes (id uuid primary key, body text);
alter table public.notes enable row level security;
create policy "owners read notes" on public.notes for select using (auth.uid() = id);
