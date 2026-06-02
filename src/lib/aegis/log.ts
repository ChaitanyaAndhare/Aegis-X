export function logAegis(msg: string) {
  console.log(`[AEGIS] ${msg}`)
}

export function logAgent(
  agent: 'Recon' | 'Risk' | 'Threat' | 'Intelligence',
  phase: 'Started' | 'Completed',
) {
  console.log(`[${agent}] ${phase}`)
}

export function logError(err: unknown) {
  console.error('[AEGIS] ERROR', err instanceof Error ? err.message : err)
}
