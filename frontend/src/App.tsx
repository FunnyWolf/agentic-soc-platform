import {useEffect} from 'react'
import {Navigate, Route, Routes, useLocation} from 'react-router-dom'
import Login from './pages/Login'
import MainLayout from './components/MainLayout'
import ResourceDetailRoute from './components/ResourceDetailRoute'
import CaseList from './pages/CaseList'
import AlertList from './pages/AlertList'
import ArtifactList from './pages/ArtifactList'
import EnrichmentList from './pages/EnrichmentList'
import PlaybookList from './pages/PlaybookList'
import KnowledgeList from './pages/KnowledgeList'
import Dashboard from './pages/Dashboard'
import SystemSettings from './pages/SystemSettings'
import CustomDefinitions from './pages/CustomDefinitions'
import {useAuthStore} from './stores/auth'
import {hasPermission, type PermissionKey} from './utils/permissions'
import {getMe} from './api/auth'
import {buildLoginRedirectPath} from './utils/authRedirect'
import {RealtimeProvider} from './realtime'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const token = useAuthStore((s) => s.token)
  const user = useAuthStore((s) => s.user)
  const setAuth = useAuthStore((s) => s.setAuth)

  useEffect(() => {
    if (!token || user?.role) return
    getMe().then(({ data }) => setAuth(token, data)).catch((error) => {
      console.warn('Failed to refresh current user profile', error)
    })
  }, [setAuth, token, user?.role])

  if (!token) return <Navigate to={buildLoginRedirectPath(`${location.pathname}${location.search}${location.hash}`)} replace />
  return <RealtimeProvider>{children}</RealtimeProvider>
}

function PermissionRoute({ permission, children }: { permission: PermissionKey; children: React.ReactNode }) {
  const user = useAuthStore((s) => s.user)
  if (!hasPermission(user, permission)) return <Navigate to="/cases" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<ProtectedRoute><MainLayout /></ProtectedRoute>}>
        <Route index element={<Navigate to="/cases" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="cases" element={<CaseList />} />
        <Route path="cases/:rowId" element={<ResourceDetailRoute resourceKey="cases" />} />
        <Route path="alerts" element={<AlertList />} />
        <Route path="alerts/:rowId" element={<ResourceDetailRoute resourceKey="alerts" />} />
        <Route path="artifacts" element={<ArtifactList />} />
        <Route path="artifacts/:rowId" element={<ResourceDetailRoute resourceKey="artifacts" />} />
        <Route path="enrichments" element={<EnrichmentList />} />
        <Route path="enrichments/:rowId" element={<ResourceDetailRoute resourceKey="enrichments" />} />
        <Route path="playbooks" element={<PlaybookList />} />
        <Route path="playbooks/:rowId" element={<ResourceDetailRoute resourceKey="playbooks" />} />
        <Route path="knowledge" element={<KnowledgeList />} />
        <Route path="knowledge/:rowId" element={<ResourceDetailRoute resourceKey="knowledge" />} />
        <Route path="custom" element={<PermissionRoute permission="admin"><CustomDefinitions /></PermissionRoute>} />
        <Route path="system" element={<PermissionRoute permission="admin"><SystemSettings /></PermissionRoute>} />
        <Route path="system/users" element={<Navigate to="/system" replace />} />
      </Route>
    </Routes>
  )
}
