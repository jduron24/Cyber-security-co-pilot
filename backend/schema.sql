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
    confidence FLOAT
);
