import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from '@/store/authStore';
import { HomePage } from '@/pages/Home/HomePage';
import { Login } from '@/pages/Auth/Login';
import { Signup } from '@/pages/Auth/Signup';
import { KeySetup } from '@/pages/Auth/KeySetup';
import { ReviewerDashboard } from '@/pages/Reviewer/Dashboard';
import { ReviewPage } from '@/pages/Reviewer/Review';
import { TokensPage } from '@/pages/Reviewer/Tokens';
import { ReviewerSubmissions } from './pages/Reviewer/Submissions';

import { UploadPage } from '@/pages/Submitter/Upload';
import { MySubmissions } from '@/pages/Submitter/MySubmissions';
import { SubmissionDetail } from '@/pages/Submitter/SubmissionDetail';
import { SubmissionResultsPage } from '@/pages/Submitter/SubmissionResults';
import { AdminDashboard } from '@/pages/Admin/Dashboard';
import { Escalations } from '@/pages/Admin/Escalations';
import { AuditLogs } from '@/pages/Admin/AuditLogs';
import { Statistics } from '@/pages/Admin/Statistics';
import { RingManagement } from '@/pages/Admin/RingManagement';
import { CredentialAllocation } from '@/pages/Admin/CredentialAllocation';

function getDefaultRouteForRole(role: string | undefined) {
  switch (role) {
    case 'reviewer':
      return '/reviewer/dashboard';
    case 'admin':
      return '/admin/dashboard';
    case 'submitter':
    default:
      return '/submitter/submissions';
  }
}

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />;
}

function RoleRoute({ children, role }: { children: React.ReactNode; role: 'submitter' | 'reviewer' | 'admin' }) {
  const { isAuthenticated, user } = useAuthStore();
  if (!isAuthenticated || !user) return <Navigate to="/login" />;
  if (user.role !== role) return <Navigate to={getDefaultRouteForRole(user.role)} />;
  return <>{children}</>;
}

export function AppRouter() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<Signup />} />
      <Route path="/keysetup" element={<KeySetup />} />
      
  <Route path="/reviewer/dashboard" element={<RoleRoute role="reviewer"><ReviewerDashboard /></RoleRoute>} />
  <Route path="/reviewer/tokens" element={<RoleRoute role="reviewer"><TokensPage /></RoleRoute>} />
  <Route path="/reviewer/submissions" element={<RoleRoute role="reviewer"><ReviewerSubmissions /></RoleRoute>} />
  <Route path="/reviewer/upload" element={<RoleRoute role="reviewer"><UploadPage /></RoleRoute>} />
  <Route path="/review/:id" element={<RoleRoute role="reviewer"><ReviewPage /></RoleRoute>} />
      
      <Route path="/submitter/upload" element={<RoleRoute role="submitter"><UploadPage /></RoleRoute>} />
      <Route path="/submitter/submissions" element={<RoleRoute role="submitter"><MySubmissions /></RoleRoute>} />
      <Route path="/submitter/submissions/:id" element={<RoleRoute role="submitter"><SubmissionDetail /></RoleRoute>} />
      <Route path="/submitter/results/:id" element={<RoleRoute role="submitter"><SubmissionResultsPage /></RoleRoute>} />
      
      <Route path="/admin/dashboard" element={<RoleRoute role="admin"><AdminDashboard /></RoleRoute>} />
      <Route path="/admin/rings" element={<RoleRoute role="admin"><RingManagement /></RoleRoute>} />
      <Route path="/admin/escalations" element={<RoleRoute role="admin"><Escalations /></RoleRoute>} />
      <Route path="/admin/audit-logs" element={<RoleRoute role="admin"><AuditLogs /></RoleRoute>} />
      <Route path="/admin/statistics" element={<RoleRoute role="admin"><Statistics /></RoleRoute>} />
      <Route path="/admin/credentials" element={<RoleRoute role="admin"><CredentialAllocation /></RoleRoute>} />
    </Routes>
  );
}

