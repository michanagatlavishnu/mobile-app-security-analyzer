import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import PublicLayout from './layouts/PublicLayout';
import DashboardLayout from './layouts/DashboardLayout';
import { ProtectedRoute } from './context/AuthContext';

// Standard Pages
import LandingPage from './pages/LandingPage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import UploadPage from './pages/UploadPage';
import ScanHistoryPage from './pages/ScanHistoryPage';
import ScanDetailsPage from './pages/ScanDetailsPage';
import ScanComparisonPage from './pages/ScanComparisonPage';
import FindingDetailsPage from './pages/FindingDetailsPage';
import ReportsPage from './pages/ReportsPage';
import ProfilePage from './pages/ProfilePage';
import NotFoundPage from './pages/NotFoundPage';

// Admin Portal Pages
import AdminPage from './pages/AdminPage';
import AdminUsersPage from './pages/AdminUsersPage';
import AdminUserDetailsPage from './pages/AdminUserDetailsPage';
import AdminApplicationsPage from './pages/AdminApplicationsPage';
import AdminApplicationDetailsPage from './pages/AdminApplicationDetailsPage';
import AdminScansPage from './pages/AdminScansPage';
import AdminFindingsPage from './pages/AdminFindingsPage';
import AdminAuditLogsPage from './pages/AdminAuditLogsPage';
import AdminSystemHealthPage from './pages/AdminSystemHealthPage';

export default function App() {
  return (
    <Routes>
      {/* Public Pages */}
      <Route element={<PublicLayout />}>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
      </Route>

      {/* Authenticated Protected Dashboard Pages */}
      <Route
        element={
          <ProtectedRoute>
            <DashboardLayout />
          </ProtectedRoute>
        }
      >
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/upload" element={<UploadPage />} />
        <Route path="/scans" element={<ScanHistoryPage />} />
        <Route path="/scans/compare" element={<ScanComparisonPage />} />
        <Route path="/scans/:id" element={<ScanDetailsPage />} />
        <Route path="/scans/:id/findings/:findingId" element={<FindingDetailsPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/profile" element={<ProfilePage />} />

        {/* Admin Portal Protected Routes (Enforces role === 'admin') */}
        <Route
          path="/admin"
          element={
            <ProtectedRoute requireAdmin={true}>
              <AdminPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/users"
          element={
            <ProtectedRoute requireAdmin={true}>
              <AdminUsersPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/users/:id"
          element={
            <ProtectedRoute requireAdmin={true}>
              <AdminUserDetailsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/applications"
          element={
            <ProtectedRoute requireAdmin={true}>
              <AdminApplicationsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/applications/:packageName"
          element={
            <ProtectedRoute requireAdmin={true}>
              <AdminApplicationDetailsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/scans"
          element={
            <ProtectedRoute requireAdmin={true}>
              <AdminScansPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/findings"
          element={
            <ProtectedRoute requireAdmin={true}>
              <AdminFindingsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/audit-logs"
          element={
            <ProtectedRoute requireAdmin={true}>
              <AdminAuditLogsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/admin/system"
          element={
            <ProtectedRoute requireAdmin={true}>
              <AdminSystemHealthPage />
            </ProtectedRoute>
          }
        />
      </Route>

      {/* 404 Catch-All */}
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
