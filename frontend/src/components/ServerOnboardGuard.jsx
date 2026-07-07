import { useEffect, useState } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { getServers } from '../api/client'
import { useAuth } from '../context/AuthContext'

export default function ServerOnboardGuard() {
  const { user, loading } = useAuth()
  const location = useLocation()
  const [ready, setReady] = useState(false)
  const [hasServers, setHasServers] = useState(true)

  useEffect(() => {
    if (loading || !user) {
      setReady(false)
      return undefined
    }

    let cancelled = false
    getServers()
      .then((servers) => {
        if (cancelled) return
        setHasServers(Array.isArray(servers) && servers.length > 0)
        setReady(true)
      })
      .catch(() => {
        if (cancelled) return
        setHasServers(false)
        setReady(true)
      })

    return () => {
      cancelled = true
    }
  }, [user, loading])

  if (!user || loading || !ready) return null

  const onServerFlow = location.pathname.startsWith('/servers')
  if (!hasServers && !onServerFlow) {
    return <Navigate to="/servers/new" replace />
  }

  return null
}
