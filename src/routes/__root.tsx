import { createRootRoute } from '@tanstack/react-router'
import { GuestProvider } from '../lib/guest'
import { AppShell } from '@/components/layout/AppShell'

export const Route = createRootRoute({
  component: () => (
    <GuestProvider>
      <AppShell />
    </GuestProvider>
  ),
})
