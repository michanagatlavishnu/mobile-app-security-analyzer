import api from './api';

export const userService = {
  getProfile: async () => {
    const res = await api.get('/users/profile');
    return res.data;
  },

  updateProfile: async (userData) => {
    const res = await api.put('/users/profile', userData);
    return res.data;
  },

  changePassword: async (passwords) => {
    const res = await api.put('/users/change-password', passwords);
    return res.data;
  },
};

export default userService;
