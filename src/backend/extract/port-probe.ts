import net from 'node:net'

const DEFAULT_PORTS = [80, 443, 8080, 8443] as const

function probePort(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket()
    let settled = false
    const finish = (open: boolean) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(open)
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => finish(true))
    socket.once('timeout', () => finish(false))
    socket.once('error', () => finish(false))
    socket.connect(port, host)
  })
}

export async function scanTcpPorts(
  hostname: string,
  ports: readonly number[] = DEFAULT_PORTS,
  timeoutMs = 2500,
): Promise<number[]> {
  const open: number[] = []
  await Promise.all(
    ports.map(async (port) => {
      const isOpen = await probePort(hostname, port, timeoutMs)
      if (isOpen) open.push(port)
    }),
  )
  return open.sort((a, b) => a - b)
}
