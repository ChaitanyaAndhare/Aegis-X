import { Loader2 } from 'lucide-react'

const STEPS = [
  'Active pentest',
  'Evidence capture',
  'Expert analysis',
  'Threat modeling',
  'Risk scoring',
  'Remediation roadmap',
]

export function PipelineLoader({ activeStep }: { activeStep: number }) {
  return (
    <div className="py-16 text-center">
      <Loader2 className="mx-auto h-8 w-8 animate-spin text-primary" />
      <p className="mt-4 text-sm font-medium">Penetration test in progress</p>
      <p className="mt-1 text-xs text-muted-foreground">{STEPS[activeStep - 1] ?? STEPS[0]}</p>
      <p className="mt-4 max-w-sm mx-auto text-xs text-muted-foreground">
        Safe educational probes only — no destructive or denial-of-service testing
      </p>
    </div>
  )
}
