CREATE TABLE IF NOT EXISTS knowledge_domains (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS knowledge_entries (
    id SERIAL PRIMARY KEY,
    domain_id INT REFERENCES knowledge_domains(id),
    title TEXT,
    content TEXT,
    entry_type TEXT,
    source TEXT,
    external_ref TEXT,
    confidence FLOAT
);

ALTER TABLE knowledge_entries
ADD COLUMN IF NOT EXISTS external_ref TEXT;

DROP INDEX IF EXISTS idx_knowledge_entries_source_external_ref;

CREATE UNIQUE INDEX IF NOT EXISTS idx_knowledge_entries_source_external_ref_unique
ON knowledge_entries (source, external_ref);
