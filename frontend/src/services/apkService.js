import api from './api';

export const apkService = {
  /**
   * Upload an APK file via FormData
   * Note: We do NOT manually set Content-Type header so the browser/Axios sets the correct boundary
   */
  uploadApk: async (formData, onProgress) => {
    const res = await api.post('/apk/upload', formData, {
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onProgress(percentCompleted);
        }
      },
    });
    return res.data;
  },

  /**
   * Get APK metadata by ID
   */
  getApk: async (id) => {
    const res = await api.get(`/apk/${id}`);
    return res.data;
  },

  /**
   * Delete APK and associated scan records
   */
  deleteApk: async (id) => {
    const res = await api.delete(`/apk/${id}`);
    return res.data;
  },
};

export default apkService;
