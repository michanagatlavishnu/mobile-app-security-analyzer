import api from './api';

export const scanService = {
  /**
   * Get all scans for the authenticated user
   */
  getScans: async () => {
    const res = await api.get('/scans');
    return res.data;
  },

  /**
   * Get scan details by ID, including findings if completed
   */
  getScan: async (id) => {
    const res = await api.get(`/scans/${id}`);
    return res.data;
  },

  /**
   * Start static security scan on an uploaded APK
   */
  startScan: async (scanId) => {
    const res = await api.post(`/scans/${scanId}/start`);
    return res.data;
  },

  /**
   * Delete scan record
   */
  deleteScan: async (id) => {
    const res = await api.delete(`/scans/${id}`);
    return res.data;
  },

  /**
   * Get individual finding details
   */
  getFinding: async (scanId, findingId) => {
    const res = await api.get(`/scans/${scanId}/findings/${findingId}`);
    return res.data;
  },

  /**
   * Update finding remediation status and notes
   */
  updateFinding: async (scanId, findingId, data) => {
    const res = await api.patch(`/scans/${scanId}/findings/${findingId}`, data);
    return res.data;
  },

  /**
   * Add analyst note to finding
   */
  addFindingNote: async (scanId, findingId, note) => {
    const res = await api.post(`/scans/${scanId}/findings/${findingId}/notes`, { note });
    return res.data;
  },

  /**
   * Compare two completed scans
   */
  compareScans: async (baseScanId, targetScanId) => {
    const res = await api.get(`/scans/compare?baseScanId=${baseScanId}&targetScanId=${targetScanId}`);
    return res.data;
  },

  /**
   * Fetch aggregate dashboard metrics and score history
   */
  getDashboardStats: async () => {
    const res = await api.get('/dashboard/stats');
    return res.data;
  },

  /**
   * Download generated PDF security assessment report
   */
  downloadPdf: async (scanId, filename) => {
    const res = await api.get(`/reports/${scanId}/pdf`, { responseType: 'blob' });
    const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename || `security_report_scan_${scanId}.pdf`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  },

  /**
   * Export sanitized JSON report
   */
  downloadJson: async (scanId, filename) => {
    const res = await api.get(`/reports/${scanId}/json`, { responseType: 'blob' });
    const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename || `security_report_scan_${scanId}.json`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  },

  /**
   * Export findings CSV
   */
  downloadCsv: async (scanId, filename) => {
    const res = await api.get(`/reports/${scanId}/csv`, { responseType: 'blob' });
    const url = window.URL.createObjectURL(new Blob([res.data], { type: 'text/csv' }));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename || `vulnerabilities_scan_${scanId}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  },
};

export default scanService;
