import { createFileRoute, redirect } from '@tanstack/react-router'

export const Route = createFileRoute('/genome/$runId')({
  beforeLoad: ({ params }) => {
    throw redirect({ to: '/runs/$runId', params: { runId: params.runId } })
  },
  component: () => null,
})
