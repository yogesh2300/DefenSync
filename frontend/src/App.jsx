import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import { EnvironmentProvider, useEnvironment } from './context/EnvironmentContext'
import { SelectedServerProvider } from './context/SelectedServerContext'
import { adminConsoleRedirect, workspaceRedirect } from './environment'
import Layout from './components/Layout'
import AdminLayout from './components/admin/AdminLayout'
import Login from './pages/Login'
import ForgotPassword from './pages/ForgotPassword'
import EnvironmentSelect from './pages/EnvironmentSelect'
import Dashboard from './pages/Dashboard'
import Events from './pages/Events'
import Alerts from './pages/Alerts'
import Intelligence from './pages/Intelligence'
import Collection from './pages/Collection'
import Servers from './pages/Servers'
import ServerDetails from './pages/ServerDetails'
import EditServer from './pages/EditServer'
import CloudAccounts from './pages/CloudAccounts'
import MlDemo from './pages/MlDemo'
import TrustedDevices from './pages/TrustedDevices'
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

// The environment is UI context only; every API still enforces account scope server-side.
function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  const { environment } = useEnvironment()
  const location = useLocation()
  if (loading) return <LoadingSpinner fullScreen label="Authenticating..." />
  const redirect = workspaceRedirect(user, environment, location.pathname)
  if (redirect) return <Navigate to={redirect} replace />
  return children
}

function EnvironmentRoute() {
  const { user, loading } = useAuth()
  if (loading) return <LoadingSpinner fullScreen label="Authenticating..." />
  if (!user) return <Navigate to="/login" replace />
  return <EnvironmentSelect />
}

function AdminRoute({ children }) {
  const { user, loading } = useAuth()
  const { environment } = useEnvironment()
  if (loading) return <LoadingSpinner fullScreen label="Authenticating..." />
  const redirect = adminConsoleRedirect(user, environment)
  if (redirect) return <Navigate to={redirect} replace />
  return children
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/environment" element={<EnvironmentRoute />} />

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
        <Route path="cloud-accounts" element={<CloudAccounts admin />} />
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
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="events" element={<Events />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="detection" element={<Navigate to="/intelligence" replace />} />
        <Route path="intelligence" element={<Intelligence />} />
        <Route path="servers/new" element={<Servers />} />
        <Route path="servers" element={<Servers />} />
        <Route path="servers/:serverId/edit" element={<EditServer />} />
        <Route path="servers/:serverId" element={<ServerDetails />} />
        <Route path="cloud-accounts/new" element={<CloudAccounts />} />
        <Route path="cloud-accounts" element={<CloudAccounts />} />
        <Route path="cloud-investigation" element={<Navigate to="/dashboard" replace />} />
        <Route path="collection" element={<Collection />} />
        <Route path="ml-demo" element={<MlDemo />} />
        <Route path="trusted-devices" element={<TrustedDevices />} />
      </Route>

      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <EnvironmentProvider>
          <SelectedServerProvider>
            <AppRoutes />
          </SelectedServerProvider>
        </EnvironmentProvider>
      </AuthProvider>
    </BrowserRouter>
  )
}
