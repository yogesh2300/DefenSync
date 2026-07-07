import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import { SelectedServerProvider } from './context/SelectedServerContext'
import Layout from './components/Layout'
import ServerOnboardGuard from './components/ServerOnboardGuard'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Events from './pages/Events'
import Alerts from './pages/Alerts'
import Detection from './pages/Detection'
import Collection from './pages/Collection'
import Servers from './pages/Servers'
import ServerDetails from './pages/ServerDetails'
import EditServer from './pages/EditServer'
import LoadingSpinner from './components/ui/LoadingSpinner'

function AuthenticatedLayout() {
  const { user } = useAuth()
  return <Layout key={user?.id || 'anonymous'} />
}

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <LoadingSpinner fullScreen label="Authenticating..." />
  if (!user) return <Navigate to="/login" replace />
  return (
    <>
      <ServerOnboardGuard />
      {children}
    </>
  )
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <AuthenticatedLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="events" element={<Events />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="detection" element={<Detection />} />
        <Route path="servers/new" element={<Servers />} />
        <Route path="servers" element={<Servers />} />
        <Route path="servers/:serverId/edit" element={<EditServer />} />
        <Route path="servers/:serverId" element={<ServerDetails />} />
        <Route path="collection" element={<Collection />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <SelectedServerProvider>
          <AppRoutes />
        </SelectedServerProvider>
      </AuthProvider>
    </BrowserRouter>
  )
}
