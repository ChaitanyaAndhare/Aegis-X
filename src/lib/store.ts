import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import type { AgentStep, Challenge, ChatMessage, IntelligenceReport, Run } from './types'

const DATA_DIR = join(process.cwd(), '.aegis-data')

type StoreData = {
  challenges: Challenge[]
  runs: Run[]
  agent_steps: AgentStep[]
  scan_results: { run_id: string; report: IntelligenceReport }[]
  episodic_memory: { id: string; user_id: string; run_id?: string; summary: string; outcome: string }[]
  chat_sessions: { run_id: string; messages: ChatMessage[] }[]
}

function load(): StoreData {
  mkdirSync(DATA_DIR, { recursive: true })
  const path = join(DATA_DIR, 'store.json')
  if (!existsSync(path)) {
    const empty: StoreData = {
      challenges: [],
      runs: [],
      agent_steps: [],
      scan_results: [],
      episodic_memory: [],
      chat_sessions: [],
    }
    writeFileSync(path, JSON.stringify(empty, null, 2))
    return empty
  }
  const raw = JSON.parse(readFileSync(path, 'utf-8')) as StoreData & Record<string, unknown>
  return {
    challenges: raw.challenges ?? [],
    runs: raw.runs ?? [],
    agent_steps: raw.agent_steps ?? [],
    scan_results: raw.scan_results ?? [],
    episodic_memory: (raw.episodic_memory ?? []).map((e: { id: string; user_id: string; summary: string; outcome: string; run_id?: string }) => ({
      id: e.id,
      user_id: e.user_id,
      run_id: e.run_id,
      summary: e.summary,
      outcome: e.outcome,
    })),
    chat_sessions: raw.chat_sessions ?? [],
  }
}

function save(data: StoreData) {
  writeFileSync(join(DATA_DIR, 'store.json'), JSON.stringify(data, null, 2))
}

export const localStore = {
  read(): StoreData {
    return load()
  },
  write(mutate: (d: StoreData) => void) {
    const d = load()
    mutate(d)
    save(d)
  },
}

export function uuid(): string {
  return crypto.randomUUID()
}
