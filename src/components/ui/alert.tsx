import { cn } from '@/lib/utils'

export function Alert({ className, variant = 'default', ...props }: React.HTMLAttributes<HTMLDivElement> & { variant?: 'default' | 'destructive' }) {
  return (
    <div
      role="alert"
      className={cn(
        'relative w-full rounded-xl border p-4 text-sm backdrop-blur-sm',
        variant === 'destructive'
          ? 'border-destructive/40 bg-destructive/10 text-destructive'
          : 'border-white/[0.08] bg-muted/30 text-foreground',
        className,
      )}
      {...props}
    />
  )
}
