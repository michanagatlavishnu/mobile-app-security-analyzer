import api from './api';

export const adminService = {
  getMetrics: async () => {
    const res = await api.get('/admin/metrics');
    return res.data;
  },

  getAllUsers: async () => {
    const res = await api.get('/admin/users');
    return res.data;
  },

  updateUserRole: async (id, role) => {
    const res = await api.put(`/admin/users/${id}/role`, { role });
    return res.data;
  },

  updateUserStatus: async (id, status) => {
    const res = await api.put(`/admin/users/${id}/status`, { status });
    return res.data;
  },

  getAuditLogs: async (page = 1, limit = 50) => {
    const res = await api.get(`/admin/audit-logs?page=${page}&limit=${limit}`);
    return res.data;
  },
};

export default adminService;
