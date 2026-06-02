-- AEGIS-X schema: Postgres + pgvector + RLS
CREATE EXTENSION IF NOT EXISTS vector;

-- Guest + authenticated users share challenges via user_id (guest uses fixed UUID from app)
CREATE TABLE challenges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  target_url TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  challenge_id UUID NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
  user_id UUID NOT NULL,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ,
  total_steps INT NOT NULL DEFAULT 0,
  success BOOLEAN,
  cost_tokens INT NOT NULL DEFAULT 0,
  strategy_ids_used UUID[] DEFAULT '{}'
);

CREATE TABLE world_model_states (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  step INT NOT NULL,
  state_json JSONB NOT NULL DEFAULT '{}',
  UNIQUE (run_id, step)
);

CREATE TABLE goals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  parent_id UUID REFERENCES goals(id) ON DELETE SET NULL,
  description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  confidence REAL NOT NULL DEFAULT 0.5
);

CREATE TABLE agent_steps (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  step INT NOT NULL,
  agent_name TEXT NOT NULL,
  input_json JSONB NOT NULL DEFAULT '{}',
  output_json JSONB NOT NULL DEFAULT '{}',
  reasoning TEXT,
  tokens INT NOT NULL DEFAULT 0,
  duration_ms INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE episodic_memory (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  challenge_id UUID REFERENCES challenges(id) ON DELETE SET NULL,
  run_id UUID REFERENCES runs(id) ON DELETE SET NULL,
  summary TEXT NOT NULL,
  embedding vector(1536),
  outcome TEXT NOT NULL
);

CREATE TABLE semantic_memory (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  concept TEXT NOT NULL,
  description TEXT NOT NULL,
  embedding vector(1536),
  occurrences INT NOT NULL DEFAULT 1,
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE strategies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  graph_json JSONB NOT NULL DEFAULT '{"nodes":[],"edges":[]}',
  success_rate REAL NOT NULL DEFAULT 0,
  uses INT NOT NULL DEFAULT 0,
  avg_steps REAL NOT NULL DEFAULT 0,
  parent_id UUID REFERENCES strategies(id) ON DELETE SET NULL,
  embedding vector(1536),
  generation INT NOT NULL DEFAULT 0,
  archived BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE kg_nodes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('Challenge','Concept','Technique','Tool','Strategy','Observation','Evidence','Outcome')),
  label TEXT NOT NULL,
  props_json JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE kg_edges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  src_id UUID NOT NULL REFERENCES kg_nodes(id) ON DELETE CASCADE,
  dst_id UUID NOT NULL REFERENCES kg_nodes(id) ON DELETE CASCADE,
  relation TEXT NOT NULL,
  weight REAL NOT NULL DEFAULT 1,
  run_id UUID REFERENCES runs(id) ON DELETE SET NULL
);

CREATE TABLE reflections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  failure_report TEXT,
  success_report TEXT,
  new_knowledge_json JSONB NOT NULL DEFAULT '[]',
  strategy_mutations_json JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX idx_runs_challenge ON runs(challenge_id);
CREATE INDEX idx_agent_steps_run ON agent_steps(run_id, step);
CREATE INDEX idx_episodic_embedding ON episodic_memory USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
CREATE INDEX idx_semantic_embedding ON semantic_memory USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
CREATE INDEX idx_strategies_embedding ON strategies USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

ALTER TABLE challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE world_model_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE goals ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE episodic_memory ENABLE ROW LEVEL SECURITY;
ALTER TABLE semantic_memory ENABLE ROW LEVEL SECURITY;
ALTER TABLE strategies ENABLE ROW LEVEL SECURITY;
ALTER TABLE kg_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE kg_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE reflections ENABLE ROW LEVEL SECURITY;

CREATE POLICY challenges_owner ON challenges FOR ALL USING (auth.uid() = user_id);
CREATE POLICY runs_owner ON runs FOR ALL USING (auth.uid() = user_id);
CREATE POLICY world_model_via_run ON world_model_states FOR ALL
  USING (EXISTS (SELECT 1 FROM runs r WHERE r.id = run_id AND r.user_id = auth.uid()));
CREATE POLICY goals_via_run ON goals FOR ALL
  USING (EXISTS (SELECT 1 FROM runs r WHERE r.id = run_id AND r.user_id = auth.uid()));
CREATE POLICY agent_steps_via_run ON agent_steps FOR ALL
  USING (EXISTS (SELECT 1 FROM runs r WHERE r.id = run_id AND r.user_id = auth.uid()));
CREATE POLICY episodic_owner ON episodic_memory FOR ALL USING (auth.uid() = user_id);
CREATE POLICY semantic_owner ON semantic_memory FOR ALL USING (auth.uid() = user_id);
CREATE POLICY strategies_owner ON strategies FOR ALL USING (auth.uid() = user_id);
CREATE POLICY kg_nodes_owner ON kg_nodes FOR ALL USING (auth.uid() = user_id);
CREATE POLICY kg_edges_owner ON kg_edges FOR ALL USING (auth.uid() = user_id);
CREATE POLICY reflections_via_run ON reflections FOR ALL
  USING (EXISTS (SELECT 1 FROM runs r WHERE r.id = run_id AND r.user_id = auth.uid()));

-- Seed root strategy (run after auth or via service role)
-- INSERT handled by app bootstrap
