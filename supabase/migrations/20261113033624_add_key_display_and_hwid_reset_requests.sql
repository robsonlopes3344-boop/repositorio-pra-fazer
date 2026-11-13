alter table collins_private.licenses
  add column if not exists key_ciphertext text;

create table if not exists collins_private.device_reset_requests (
  id bigserial primary key,
  license_id bigint not null references collins_private.licenses(id) on delete cascade,
  account_id bigint not null references collins_private.accounts(id) on delete cascade,
  old_device_hash text not null check (old_device_hash ~ '^[0-9a-f]{64}$'),
  new_device_hash text not null check (new_device_hash ~ '^[0-9a-f]{64}$'),
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);

create unique index if not exists device_reset_requests_one_pending_per_account
  on collins_private.device_reset_requests(account_id)
  where status = 'pending';

create index if not exists device_reset_requests_status_created_idx
  on collins_private.device_reset_requests(status, created_at desc);

create index if not exists device_reset_requests_license_idx
  on collins_private.device_reset_requests(license_id);

alter table collins_private.device_reset_requests enable row level security;
revoke all on table collins_private.device_reset_requests from public, anon, authenticated;
revoke all on sequence collins_private.device_reset_requests_id_seq from public, anon, authenticated;

