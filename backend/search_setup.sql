ALTER TABLE knowledge_entries
  ADD COLUMN IF NOT EXISTS search_vector tsvector;

UPDATE knowledge_entries
  SET search_vector = to_tsvector('english', coalesce(title, '') || ' ' || coalesce(content, ''));

CREATE INDEX IF NOT EXISTS idx_kb_search ON knowledge_entries USING GIN(search_vector);

CREATE OR REPLACE FUNCTION update_search_vector()
RETURNS TRIGGER AS $$
BEGIN
  NEW.search_vector := to_tsvector('english',
    coalesce(NEW.title, '') || ' ' || coalesce(NEW.content, ''));
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_vector ON knowledge_entries;
CREATE TRIGGER trg_search_vector
BEFORE INSERT OR UPDATE ON knowledge_entries
FOR EACH ROW EXECUTE FUNCTION update_search_vector();
