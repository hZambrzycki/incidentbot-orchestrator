PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

-- =========================================================
-- Runbook executions (audit + observability + lineage)
-- =========================================================
CREATE TABLE IF NOT EXISTS runbook_executions (
  id TEXT PRIMARY KEY,
  incident_id TEXT,
  runbook_name TEXT NOT NULL,
  status TEXT NOT NULL,
  triggered_by TEXT NOT NULL,

  -- observability / lineage
  execution_origin TEXT,
  retry_of_execution_id TEXT,

  -- targeting
  target_service TEXT,
  target_instance TEXT,

  -- payload
  parameters_json TEXT,
  output TEXT,
  error TEXT,

  -- timings
  started_at TEXT,
  completed_at TEXT,
  duration_seconds REAL,

  -- legacy (compat)
  confirm_state TEXT,
  confirm_token TEXT,

  -- confirmation linkage
  confirmed_execution_id TEXT,
  confirmed_by TEXT,
  confirmed_at TEXT,

  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_exec_incident     ON runbook_executions(incident_id);
CREATE INDEX IF NOT EXISTS idx_exec_confirmed    ON runbook_executions(confirmed_execution_id);
CREATE INDEX IF NOT EXISTS idx_exec_started_at   ON runbook_executions(started_at);
CREATE INDEX IF NOT EXISTS idx_exec_runbook_name ON runbook_executions(runbook_name);

-- =========================================================
-- Runbook confirmations (idempotent confirm control-plane)
-- =========================================================
CREATE TABLE IF NOT EXISTS runbook_confirmations (
  pending_execution_id   TEXT PRIMARY KEY,
  incident_id            TEXT NOT NULL,
  runbook_name           TEXT NOT NULL,
  actor_id               TEXT NOT NULL,
  status                 TEXT NOT NULL CHECK(status IN ('pending','success','skipped','error')),
  confirmed_execution_id TEXT,
  created_at             TEXT NOT NULL,
  updated_at             TEXT NOT NULL,
  result_json            TEXT
);

-- =========================================================
-- Durable Runbook Queue (resume after restart)
-- =========================================================
-- This table is the "control plane" queue for async runbook tasks.
-- - Confirmable runbooks do NOT enqueue here (they stay runbook_executions.status='pending').
-- - Non-confirmable async runbooks are queued here and a worker leases/runs them.
CREATE TABLE IF NOT EXISTS runbook_queue (
  execution_id TEXT PRIMARY KEY, -- FK-ish to runbook_executions.id

  runbook_name TEXT NOT NULL,
  incident_id TEXT,
  target_service TEXT,
  target_instance TEXT,

  parameters_json TEXT,
  triggered_by TEXT NOT NULL,

  execution_origin TEXT,
  retry_of_execution_id TEXT,

  status TEXT NOT NULL CHECK(status IN ('queued','running','done','dead')),
  attempts INTEGER NOT NULL DEFAULT 0,

  last_heartbeat TEXT,
  available_at TEXT,

  lease_owner TEXT,
  lease_expires_at TEXT,

  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Basic indexes
CREATE INDEX IF NOT EXISTS idx_rbq_status     ON runbook_queue(status);
CREATE INDEX IF NOT EXISTS idx_rbq_updated_at ON runbook_queue(updated_at);
CREATE INDEX IF NOT EXISTS idx_rbq_incident   ON runbook_queue(incident_id);
CREATE INDEX IF NOT EXISTS idx_rbq_retry_of   ON runbook_queue(retry_of_execution_id);

-- Critical path for claim_one():
-- filters: status='queued' AND available_at<=now AND (lease_expires_at IS NULL OR lease_expires_at<=now)
-- order: updated_at ASC
CREATE INDEX IF NOT EXISTS idx_rbq_claim
  ON runbook_queue(status, available_at, lease_expires_at, updated_at);

-- =========================================================
-- Incidents persistence
-- =========================================================
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  severity INTEGER NOT NULL,
  status TEXT NOT NULL,

  source_alert TEXT,           -- fingerprint principal (puede ser NULL)
  service TEXT,
  instance TEXT,

  labels_json TEXT,
  annotations_json TEXT,

  diagnosis TEXT,
  reopen_count INTEGER NOT NULL DEFAULT 0,

  error_type TEXT,
  error_summary TEXT,

  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  resolved_at TEXT,
  last_fired_at TEXT,
  last_processed_at TEXT,

  episodes_json TEXT,          -- list IncidentEpisode
  runbooks_executed_json TEXT  -- list strings
);

CREATE INDEX IF NOT EXISTS idx_incidents_status     ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_updated_at ON incidents(updated_at);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);

-- Fingerprint -> incident_id (dedupe/reopen tras restart)
CREATE TABLE IF NOT EXISTS incident_fingerprints (
  fingerprint TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_fp_incident_id ON incident_fingerprints(incident_id);

-- =========================================================
-- Incident / Runbook Event Timeline (forensics + UI)
-- =========================================================
CREATE TABLE IF NOT EXISTS incident_events (
  id TEXT PRIMARY KEY,                 -- uuid
  event_key TEXT NOT NULL UNIQUE,      -- idempotency key
  created_at TEXT NOT NULL,            -- ISO-8601 UTC

  -- correlation
  incident_id TEXT,                    -- nullable
  execution_id TEXT,                   -- runbook_executions.id (soft link)
  confirmation_id TEXT,                -- runbook_confirmations.pending_execution_id (soft link)
  queue_execution_id TEXT,             -- runbook_queue.execution_id (soft link)

  -- classification
  event_type TEXT NOT NULL,            -- e.g. runbook.execution.started
  severity TEXT NOT NULL DEFAULT 'info'
    CHECK(severity IN ('debug','info','warning','error','critical')),

  -- actor/context
  actor TEXT NOT NULL,                 -- system/api/human/recovery/worker/telegram
  source TEXT,                         -- runbook_engine / incident_manager / worker / api
  message TEXT,                        -- short human friendly
  details_json TEXT,                   -- JSON payload

  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ie_incident_time  ON incident_events(incident_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ie_execution_time ON incident_events(execution_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ie_type_time      ON incident_events(event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_ie_created_at     ON incident_events(created_at);


-- =========================================================
-- Runbook Failures (reliability analytics)
-- =========================================================
CREATE TABLE IF NOT EXISTS runbook_failures (
  id TEXT PRIMARY KEY,                  -- uuid
  created_at TEXT NOT NULL,             -- ISO UTC

  -- idempotency key (IMPORTANT)
  -- lets you dedupe failures deterministically (e.g. execution_id + kind + is_final)
  failure_key TEXT NOT NULL UNIQUE,

  incident_id TEXT,
  execution_id TEXT NOT NULL,           -- failing execution id
  runbook_name TEXT NOT NULL,
  target_service TEXT,
  target_instance TEXT,

  failure_kind TEXT NOT NULL CHECK(failure_kind IN (
    'validation',
    'timeout',
    'exception',
    'non_success',
    'cancelled',
    'ttl_skipped',
    'recovered_stale',
    'unknown'
  )),
  final_status TEXT NOT NULL,           -- failed/timeout/skipped/error
  execution_origin TEXT,
  retry_of_execution_id TEXT,
  attempt_no INTEGER,
  is_final INTEGER NOT NULL DEFAULT 1 CHECK(is_final IN (0,1)),

  error_message TEXT,                   -- short
  error_hash TEXT,                      -- stable grouping key
  details_json TEXT,

  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_rf_incident_time ON runbook_failures(incident_id, created_at);
CREATE INDEX IF NOT EXISTS idx_rf_runbook_time  ON runbook_failures(runbook_name, created_at);
CREATE INDEX IF NOT EXISTS idx_rf_service_time  ON runbook_failures(target_service, created_at);
CREATE INDEX IF NOT EXISTS idx_rf_hash_time     ON runbook_failures(error_hash, created_at);

-- One final failure per execution (optional but recommended)
-- If you keep this, you guarantee only one "final" row per execution_id.
CREATE UNIQUE INDEX IF NOT EXISTS uq_rf_execution_final
  ON runbook_failures(execution_id)
  WHERE is_final = 1;