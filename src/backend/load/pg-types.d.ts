declare module 'pg' {
  export class Pool {
    constructor(config?: { connectionString?: string; ssl?: { rejectUnauthorized: boolean } })
    query(text: string, values?: unknown[]): Promise<unknown>
    connect(): Promise<{
      query(text: string, values?: unknown[]): Promise<unknown>
      release(): void
    }>
  }
}
