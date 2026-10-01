import api from './api';

export const adminService = {
  // Phase 3: Overview Dashboard
  getDashboard: async () => {
    const res = await api.get('/admin/dashboard');
    return res.data;
  },

  // Legacy Telemetry
  getMetrics: async () => {
    const res = await api.get('/admin/metrics');
    return res.data;
  },

  // Phase 4 & 6: User Management
  getUsers: async (params = {}) => {
    const res = await api.get('/admin/users', { params });
    return res.data;
  },

  // Phase 5: User Details
  getUserDetails: async (id) => {
    const res = await api.get(`/admin/users/${id}`);
    return res.data;
  },

  getUserActivity: async (id, params = {}) => {
    const res = await api.get(`/admin/users/${id}/activity`, { params });
    return res.data;
  },

  updateUserRole: async (id, role) => {
    const res = await api.patch(`/admin/users/${id}/role`, { role });
    return res.data;
  },

  updateUserStatus: async (id, status) => {
    const res = await api.patch(`/admin/users/${id}/status`, { status });
    return res.data;
  },

  // Phase 7: Audit Logs
  getAuditLogs: async (params = {}) => {
    const res = await api.get('/admin/audit-logs', { params });
    return res.data;
  },

  // Phase 8: Registration Trends
  getRegistrationAnalytics: async () => {
    const res = await api.get('/admin/analytics/registrations');
    return res.data;
  },

  // Phase 9: Activity Telemetry
  getActivityAnalytics: async () => {
    const res = await api.get('/admin/analytics/activity');
    return res.data;
  },

  // Phase 10: Applications
  getApplications: async (params = {}) => {
    const res = await api.get('/admin/applications', { params });
    return res.data;
  },

  getApplicationDetails: async (packageName) => {
    const res = await api.get(`/admin/applications/${encodeURIComponent(packageName)}`);
    return res.data;
  },

  // Phase 11: Scans
  getScans: async (params = {}) => {
    const res = await api.get('/admin/scans', { params });
    return res.data;
  },

  // Phase 12: Findings
  getFindings: async (params = {}) => {
    const res = await api.get('/admin/findings', { params });
    return res.data;
  },

  // Phase 13: System Health
  getSystemHealth: async () => {
    const res = await api.get('/admin/system-health');
    return res.data;
  },
};

export default adminService;
