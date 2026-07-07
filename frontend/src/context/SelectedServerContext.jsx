import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { getServers } from '../api/client'
import { useAuth } from './AuthContext'

const SelectedServerContext = createContext(null)
const STORAGE_KEY = 'defensync_selected_server'

export function SelectedServerProvider({ children }) {
  const { user } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const [servers, setServers] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedServerId, setSelectedServerIdState] = useState(
    () => searchParams.get('server_id') || localStorage.getItem(STORAGE_KEY) || '',
  )

  const refreshServers = useCallback(async () => {
    if (!user) {
      setServers([])
      setLoading(false)
      return
    }
    setLoading(true)
    try {
      const rows = await getServers()
      setServers(Array.isArray(rows) ? rows : [])
    } catch {
      setServers([])
    } finally {
      setLoading(false)
    }
  }, [user])

  useEffect(() => {
    refreshServers()
  }, [refreshServers])

  useEffect(() => {
    if (!selectedServerId) return
    if (!loading && servers.length && !servers.some((server) => server.id === selectedServerId)) {
      setSelectedServerIdState('')
      localStorage.removeItem(STORAGE_KEY)
    }
  }, [servers, selectedServerId, loading])

  const setSelectedServerId = useCallback((serverId) => {
    setSelectedServerIdState(serverId)
    if (serverId) localStorage.setItem(STORAGE_KEY, serverId)
    else localStorage.removeItem(STORAGE_KEY)

    const next = new URLSearchParams(searchParams)
    if (serverId) next.set('server_id', serverId)
    else next.delete('server_id')
    setSearchParams(next, { replace: true })
    window.dispatchEvent(new CustomEvent('defensync:server-changed', { detail: { serverId } }))
  }, [searchParams, setSearchParams])

  useEffect(() => {
    const onLogout = () => {
      setSelectedServerIdState('')
      setServers([])
      localStorage.removeItem(STORAGE_KEY)
    }
    window.addEventListener('defensync:logout', onLogout)
    return () => window.removeEventListener('defensync:logout', onLogout)
  }, [])

  const selectedServer = useMemo(
    () => servers.find((server) => server.id === selectedServerId) || null,
    [servers, selectedServerId],
  )

  const serverParams = useMemo(
    () => (selectedServerId ? { server_id: selectedServerId } : {}),
    [selectedServerId],
  )

  return (
    <SelectedServerContext.Provider
      value={{
        servers,
        loading,
        selectedServerId,
        selectedServer,
        setSelectedServerId,
        refreshServers,
        serverParams,
        isAllServers: !selectedServerId,
      }}
    >
      {children}
    </SelectedServerContext.Provider>
  )
}

export function useSelectedServer() {
  const context = useContext(SelectedServerContext)
  if (!context) {
    throw new Error('useSelectedServer must be used within SelectedServerProvider')
  }
  return context
}
