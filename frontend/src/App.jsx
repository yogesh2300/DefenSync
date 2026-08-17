import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import { SelectedServerProvider } from './context/SelectedServerContext'
import Layout from './components/Layout'
import AdminLayout from './components/admin/AdminLayout'
import ServerOnboardGuard from './components/ServerOnboardGuard'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Events from './pages/Events'
import Alerts from './pages/Alerts'
import Detection from './pages/Detection'
import Intelligence from './pages/Intelligence'
import Collection from './pages/Collection'
import Servers from './pages/Servers'
import ServerDetails from './pages/ServerDetails'
import EditServer from './pages/EditServer'
import AdminDashboard from './pages/admin/AdminDashboard'
import AdminUsers from './pages/admin/AdminUsers'
import AdminUserDetail from './pages/admin/AdminUserDetail'
import AdminServers from './pages/admin/AdminServers'
import AdminCollections from './pages/admin/AdminCollections'
import AdminEvents from './pages/admin/AdminEvents'
import AdminAlerts from './pages/admin/AdminAlerts'
import AdminDetections from './pages/admin/AdminDetections'
import AdminML from './pages/admin/AdminML'
import AdminSystemHealth from './pages/admin/AdminSystemHealth'
import AdminAnalytics from './pages/admin/AdminAnalytics'
import AdminSettings from './pages/admin/AdminSettings'
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

function AdminRoute({ children }) {
  const { user, loading, isAdmin } = useAuth()
  if (loading) return <LoadingSpinner fullScreen label="Authenticating..." />
  if (!user) return <Navigate to="/login" replace />
  if (!isAdmin) return <Navigate to="/dashboard" replace />
  return children
}

function AnalystRoute({ children }) {
  const { user, loading, isAdmin } = useAuth()
  if (loading) return <LoadingSpinner fullScreen label="Authenticating..." />
  if (!user) return <Navigate to="/login" replace />
  if (isAdmin) return <Navigate to="/admin/dashboard" replace />
  return children
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      <Route
        path="/admin"
        element={(
          <AdminRoute>
            <AdminLayout />
          </AdminRoute>
        )}
      >
        <Route index element={<Navigate to="/admin/dashboard" replace />} />
        <Route path="dashboard" element={<AdminDashboard />} />
        <Route path="users" element={<AdminUsers />} />
        <Route path="users/:userId" element={<AdminUserDetail />} />
        <Route path="servers" element={<AdminServers />} />
        <Route path="collections" element={<AdminCollections />} />
        <Route path="events" element={<AdminEvents />} />
        <Route path="alerts" element={<AdminAlerts />} />
        <Route path="detections" element={<AdminDetections />} />
        <Route path="ml" element={<AdminML />} />
        <Route path="system-health" element={<AdminSystemHealth />} />
        <Route path="analytics" element={<AdminAnalytics />} />
        <Route path="settings" element={<AdminSettings />} />
      </Route>

      <Route
        path="/"
        element={(
          <ProtectedRoute>
            <AuthenticatedLayout />
          </ProtectedRoute>
        )}
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<AnalystRoute><Dashboard /></AnalystRoute>} />
        <Route path="events" element={<AnalystRoute><Events /></AnalystRoute>} />
        <Route path="alerts" element={<AnalystRoute><Alerts /></AnalystRoute>} />
        <Route path="detection" element={<AnalystRoute><Detection /></AnalystRoute>} />
        <Route path="intelligence" element={<AnalystRoute><Intelligence /></AnalystRoute>} />
        <Route path="servers/new" element={<AnalystRoute><Servers /></AnalystRoute>} />
        <Route path="servers" element={<AnalystRoute><Servers /></AnalystRoute>} />
        <Route path="servers/:serverId/edit" element={<AnalystRoute><EditServer /></AnalystRoute>} />
        <Route path="servers/:serverId" element={<AnalystRoute><ServerDetails /></AnalystRoute>} />
        <Route path="collection" element={<AnalystRoute><Collection /></AnalystRoute>} />
      </Route>

      <Route path="*" element={<Navigate to="/dashboard" replace />} />
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
