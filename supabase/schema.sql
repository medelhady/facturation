-- Tables for the invoice app (already run in the Supabase SQL editor)
create table products (
  id bigint generated always as identity primary key,
  name text not null,
  price numeric not null default 0,
  created_at timestamptz not null default now()
);
create table settings (
  id int primary key default 1 check (id = 1),
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
create sequence invoice_number_seq start 1;
create table invoices (
  id bigint generated always as identity primary key,
  number int not null unique default nextval('invoice_number_seq'),
  customer text,
  customer_phone text,
  invoice_date date,
  discount numeric not null default 0,
  tax_rate numeric not null default 0,
  subtotal numeric not null default 0,
  total numeric not null default 0,
  lang text default 'ar',
  created_at timestamptz not null default now()
);
create table invoice_items (
  id bigint generated always as identity primary key,
  invoice_id bigint not null references invoices(id) on delete cascade,
  name text not null,
  qty numeric not null,
  price numeric not null
);
alter table products enable row level security;
alter table settings enable row level security;
alter table invoices enable row level security;
alter table invoice_items enable row level security;
create policy "auth only" on products for all to authenticated using (true) with check (true);
create policy "auth only" on settings for all to authenticated using (true) with check (true);
create policy "auth only" on invoices for all to authenticated using (true) with check (true);
create policy "auth only" on invoice_items for all to authenticated using (true) with check (true);
grant usage, select on sequence invoice_number_seq to authenticated;
