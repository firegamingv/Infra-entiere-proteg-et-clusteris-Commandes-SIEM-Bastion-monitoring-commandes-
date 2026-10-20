-- OSTRAL boutique (Z1) — schéma initial.
-- Aucune donnée de carte bancaire n'est stockée ici (E02, PCI DSS SAQ A) :
-- seule la référence de paiement du PSP est conservée.

CREATE TABLE customers (
  id               SERIAL PRIMARY KEY,
  email            TEXT NOT NULL UNIQUE CHECK (email = lower(email)),
  password_hash    TEXT NOT NULL,                 -- bcrypt (coût 12 par défaut)
  full_name        TEXT NOT NULL,
  address_line     TEXT NOT NULL,
  postal_code      TEXT NOT NULL,
  city             TEXT NOT NULL,
  failed_attempts  INTEGER NOT NULL DEFAULT 0,    -- E04 : échecs consécutifs
  locked_until     TIMESTAMPTZ,                   -- E04 / SS2 : verrouillage temporaire
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at    TIMESTAMPTZ
);

-- Journal des tentatives de connexion (succès et échecs) : sert au comptage par IP et
-- par compte (E04, SS2) et à l'investigation (E08).
CREATE TABLE login_attempts (
  id           BIGSERIAL PRIMARY KEY,
  email        TEXT NOT NULL,
  customer_id  INTEGER REFERENCES customers(id) ON DELETE SET NULL,
  ip           INET,
  success      BOOLEAN NOT NULL,
  reason       TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX login_attempts_ip_idx    ON login_attempts (ip, created_at);
CREATE INDEX login_attempts_email_idx ON login_attempts (email, created_at);

-- Sessions côté serveur : seule l'empreinte HMAC du jeton est stockée.
CREATE TABLE sessions (
  id_hash      BYTEA PRIMARY KEY,
  customer_id  INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  ip           INET,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

CREATE TABLE products (
  id            SERIAL PRIMARY KEY,
  sku           TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  description   TEXT NOT NULL,
  price_cents   INTEGER NOT NULL CHECK (price_cents > 0),
  weight_grams  INTEGER NOT NULL CHECK (weight_grams > 0),
  active        BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE orders (
  id              SERIAL PRIMARY KEY,
  reference       TEXT NOT NULL UNIQUE,           -- référence non devinable exposée dans les URL
  customer_id     INTEGER NOT NULL REFERENCES customers(id),
  status          TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'awaiting_payment', 'paid', 'failed', 'cancelled')),
  total_cents     INTEGER NOT NULL CHECK (total_cents > 0),
  currency        TEXT NOT NULL DEFAULT 'EUR',
  psp_payment_id  TEXT UNIQUE,
  erp_order_id    INTEGER,                        -- identifiant sale.order dans Odoo
  erp_synced_at   TIMESTAMPTZ,
  tracking_number TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  paid_at         TIMESTAMPTZ
);
CREATE INDEX orders_customer_idx ON orders (customer_id, created_at DESC);

CREATE TABLE order_lines (
  id                SERIAL PRIMARY KEY,
  order_id          INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id        INTEGER NOT NULL REFERENCES products(id),
  sku               TEXT NOT NULL,
  name              TEXT NOT NULL,
  quantity          INTEGER NOT NULL CHECK (quantity BETWEEN 1 AND 20),
  unit_price_cents  INTEGER NOT NULL CHECK (unit_price_cents > 0)
);

-- Anti-rejeu des notifications PSP : chaque event_id n'est traité qu'une fois.
CREATE TABLE payment_events (
  event_id     TEXT PRIMARY KEY,
  payment_id   TEXT NOT NULL,
  order_ref    TEXT NOT NULL,
  status       TEXT NOT NULL,
  received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- R2 : file d'attente (pattern outbox). Une commande payée y est insérée dans la même
-- transaction que son passage à « paid » ; le worker la pousse vers l'ERP (F04) ou le
-- transporteur (F03) et réessaie avec backoff tant que la cible est indisponible.
CREATE TABLE outbox (
  id               BIGSERIAL PRIMARY KEY,
  kind             TEXT NOT NULL CHECK (kind IN ('erp_order', 'carrier_label')),
  aggregate_id     INTEGER NOT NULL REFERENCES orders(id),
  payload          JSONB NOT NULL,
  status           TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'done')),
  attempts         INTEGER NOT NULL DEFAULT 0,
  next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  locked_until     TIMESTAMPTZ,
  last_error       TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at     TIMESTAMPTZ,
  UNIQUE (kind, aggregate_id)
);
CREATE INDEX outbox_pending_idx ON outbox (next_attempt_at) WHERE status = 'pending';
