import dns from 'node:dns/promises'

export type DnsRecordSet = {
  A?: string[]
  AAAA?: string[]
  MX?: string[]
  TXT?: string[]
  CNAME?: string[]
}

export async function resolveDnsRecords(hostname: string): Promise<DnsRecordSet> {
  const records: DnsRecordSet = { A: [], AAAA: [], MX: [], TXT: [], CNAME: [] }

  const safe = async <T>(fn: () => Promise<T>): Promise<T | undefined> => {
    try {
      return await fn()
    } catch {
      return undefined
    }
  }

  const a = await safe(() => dns.resolve4(hostname))
  if (a?.length) records.A = a

  const aaaa = await safe(() => dns.resolve6(hostname))
  if (aaaa?.length) records.AAAA = aaaa

  const mx = await safe(() => dns.resolveMx(hostname))
  if (mx?.length) records.MX = mx.map((m) => `${m.exchange} (priority ${m.priority})`)

  const txt = await safe(() => dns.resolveTxt(hostname))
  if (txt?.length) records.TXT = txt.map((chunks) => chunks.join(''))

  const cname = await safe(() => dns.resolveCname(hostname))
  if (cname?.length) records.CNAME = cname

  return records
}
