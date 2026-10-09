-- SQLite is a derived index; canonical JSON remains the source of truth.
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    fingerprint_version INTEGER NOT NULL CHECK (fingerprint_version >= 1),
    status TEXT NOT NULL CHECK (status IN ('OPEN','PATCH_PROPOSED','VERIFYING','CLOSED','REOPENED','ACCEPTED_RISK')),
    canonical_path TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS finding_sources (
    id INTEGER PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    tool TEXT NOT NULL,
    raw_reference TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_history (
    id INTEGER PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    timestamp TEXT NOT NULL,
    event TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gate_runs (
    run_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('PASS','BLOCK','REVIEW_REQUIRED')),
    report_reference TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS escalation_state (
    finding_id TEXT NOT NULL REFERENCES findings(id),
    stage INTEGER NOT NULL CHECK (stage IN (30,60,90)),
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    attempted_at TEXT,
    delivered_at TEXT,
    error TEXT,
    PRIMARY KEY (finding_id, stage, target)
);
