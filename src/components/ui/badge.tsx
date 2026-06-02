import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-bold uppercase', {
  variants: {
    variant: {
      default: 'bg-primary/20 text-primary',
      critical: 'bg-destructive/20 text-destructive',
      high: 'bg-orange-500/20 text-orange-400',
      medium: 'bg-warning/20 text-warning',
      low: 'bg-sky-500/20 text-sky-400',
      muted: 'bg-muted text-muted-foreground',
    },
  },
  defaultVariants: { variant: 'default' },
})

export function Badge({ className, variant, ...props }: React.HTMLAttributes<HTMLDivElement> & VariantProps<typeof badgeVariants>) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />
}
