import api from './api';

export const authService = {
  // Health check endpoint implemented in Phase 2
  checkHealth: async () => {
    const res = await api.get('/health');
    return res.data;
  },

  checkDbHealth: async () => {
    const res = await api.get('/health/db');
    return res.data;
  },

  // Future authentication endpoints (to be connected in Phase 4)
  login: async (credentials) => {
    const res = await api.post('/auth/login', credentials);
    return res.data;
  },

  register: async (userData) => {
    const res = await api.post('/auth/register', userData);
    return res.data;
  },

  getCurrentUser: async () => {
    const res = await api.get('/auth/me');
    return res.data;
  },
};

export default authService;
