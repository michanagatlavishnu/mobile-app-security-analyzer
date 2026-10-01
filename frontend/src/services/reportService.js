import api from './api';

export const reportService = {
  generateReport: async (scanId) => {
    const res = await api.post(`/reports/${scanId}/generate`);
    return res.data;
  },

  getReport: async (scanId) => {
    const res = await api.get(`/reports/${scanId}`);
    return res.data;
  },

  downloadReportUrl: (scanId) => {
    return `${api.defaults.baseURL}/reports/${scanId}/download`;
  },
};

export default reportService;
