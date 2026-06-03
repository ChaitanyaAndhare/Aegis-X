const STEPS = ['Extract', 'Transform', 'Risk', 'Load', 'Delta']

export function PipelineLoader({ activeStep }: { activeStep: number }) {
  const current = Math.min(activeStep, STEPS.length)

  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center animate-fade-in">
      <p className="ax-label mb-6">Running scan</p>
      <div className="flex gap-2">
        {STEPS.map((label, i) => (
          <div
            key={label}
            className={`h-1 w-12 rounded-full transition-colors duration-500 ${
              i < current ? 'bg-foreground' : 'bg-border'
            }`}
          />
        ))}
      </div>
      <p className="mt-8 font-display text-2xl">{STEPS[current - 1] ?? STEPS[0]}</p>
    </div>
  )
}
