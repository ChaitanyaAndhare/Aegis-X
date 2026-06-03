import { Loader2 } from 'lucide-react'

const STEPS = [
  'Extract — browser & network capture',
  'Transform — heuristic rules engine',
  'Risk — contextual severity profiling',
  'Load — persist inventory & findings',
  'Delta — historical comparison',
]

export function PipelineLoader({ activeStep }: { activeStep: number }) {
  return (
    <div className="py-16 text-center">
      <Loader2 className="mx-auto h-8 w-8 animate-spin text-primary" />
      <p className="mt-4 text-sm font-medium">Penetration test in progress</p>
      <p className="mt-1 text-xs text-muted-foreground">{STEPS[activeStep - 1] ?? STEPS[0]}</p>
      <p className="mt-4 max-w-sm mx-auto text-xs text-muted-foreground">
        Deterministic Security ETL — zero AI in the evaluation pipeline
      </p>
    </div>
  )
}
