CREATE TABLE accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  refresh_token_enc TEXT NOT NULL,
  quota_total INTEGER NOT NULL DEFAULT 0,
  quota_used INTEGER NOT NULL DEFAULT 0,
  synced_at TEXT
);

CREATE TABLE files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES accounts(id),
  drive_file_id TEXT NOT NULL,
  virtual_path TEXT NOT NULL UNIQUE,
  size INTEGER NOT NULL DEFAULT 0,
  mime TEXT,
  md5 TEXT,
  public_link TEXT,
  UNIQUE (account_id, drive_file_id)
);
CREATE INDEX idx_files_account ON files(account_id);

CREATE TABLE rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,            -- e.g. 'rebalance'
  threshold REAL NOT NULL DEFAULT 0.9,
  enabled INTEGER NOT NULL DEFAULT 1
);
INSERT INTO rules (kind, threshold) VALUES ('rebalance', 0.9);

CREATE TABLE jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  error TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
