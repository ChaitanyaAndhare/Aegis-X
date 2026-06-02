import { createContext, useContext, useState, useEffect, type ReactNode } from 'react'

const GuestCtx = createContext<{ guest: boolean; setGuest: (v: boolean) => void }>({
  guest: true,
  setGuest: () => {},
})

export function GuestProvider({ children }: { children: ReactNode }) {
  const [guest, setGuest] = useState(() => localStorage.getItem('aegis-guest') !== '0')

  useEffect(() => {
    localStorage.setItem('aegis-guest', guest ? '1' : '0')
    if (!localStorage.getItem('aegis-user-id')) {
      localStorage.setItem('aegis-user-id', '00000000-0000-4000-8000-000000000001')
    }
  }, [guest])

  return <GuestCtx.Provider value={{ guest, setGuest }}>{children}</GuestCtx.Provider>
}

export function useGuest() {
  return useContext(GuestCtx)
}
