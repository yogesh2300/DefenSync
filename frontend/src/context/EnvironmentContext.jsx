import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { ENVIRONMENT_STORAGE_KEY, isEnvironment } from '../environment'

const EnvironmentContext = createContext(null)

function readStored() {
  try {
    const value = sessionStorage.getItem(ENVIRONMENT_STORAGE_KEY)
    return isEnvironment(value) ? value : null
  } catch {
    return null
  }
}

export function EnvironmentProvider({ children }) {
  const [environment, setEnvironmentState] = useState(readStored)

  const setEnvironment = useCallback((next) => {
    if (!isEnvironment(next)) return
    setEnvironmentState(next)
    try {
      sessionStorage.setItem(ENVIRONMENT_STORAGE_KEY, next)
    } catch {
      // storage can be unavailable; the in-memory state still applies
    }
  }, [])

  const clearEnvironment = useCallback(() => {
    setEnvironmentState(null)
    try {
      sessionStorage.removeItem(ENVIRONMENT_STORAGE_KEY)
    } catch {
      // ignore
    }
  }, [])

  useEffect(() => {
    window.addEventListener('defensync:logout', clearEnvironment)
    window.addEventListener('defensync:authenticated', clearEnvironment)
    return () => {
      window.removeEventListener('defensync:logout', clearEnvironment)
      window.removeEventListener('defensync:authenticated', clearEnvironment)
    }
  }, [clearEnvironment])

  return (
    <EnvironmentContext.Provider value={{ environment, setEnvironment, clearEnvironment }}>
      {children}
    </EnvironmentContext.Provider>
  )
}

export function useEnvironment() {
  const context = useContext(EnvironmentContext)
  if (!context) throw new Error('useEnvironment must be used within EnvironmentProvider')
  return context
}
