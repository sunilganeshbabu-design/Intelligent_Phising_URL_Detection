import axios from 'axios';

const API_BASE_URL = 'http://127.0.0.1:8000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach JWT token automatically from localStorage or sessionStorage
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('phishguard_token') || sessionStorage.getItem('phishguard_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auth Endpoints
export const loginUser = async (username_or_email, password, remember_me = true) => {
  const response = await api.post('/auth/login', { username_or_email, password, remember_me });
  return response.data;
};

export const registerUser = async (full_name, email, password, confirm_password = '') => {
  const response = await api.post('/auth/register', { full_name, email, password, confirm_password });
  return response.data;
};

export const getCurrentUserProfile = async () => {
  const response = await api.get('/auth/me');
  return response.data;
};

export const updateUserProfile = async (profileData) => {
  const response = await api.put('/auth/profile', profileData);
  return response.data;
};

export const changeUserPassword = async (current_password, new_password, confirm_password = '') => {
  const response = await api.post('/auth/change-password', {
    current_password,
    new_password,
    confirm_password: confirm_password || new_password
  });
  return response.data;
};

export const requestForgotPassword = async (email) => {
  const response = await api.post('/auth/forgot-password', { email });
  return response.data;
};

export const submitResetPassword = async (email, reset_code, new_password, confirm_password = '') => {
  const response = await api.post('/auth/reset-password', {
    email,
    reset_code,
    new_password,
    confirm_password: confirm_password || new_password
  });
  return response.data;
};

export const verifyEmailToken = async (tokenOrCode, email = null) => {
  const response = await api.post('/auth/verify-email', {
    token: tokenOrCode,
    code: tokenOrCode,
    email
  });
  return response.data;
};

export const resendEmailVerification = async (email) => {
  const response = await api.post('/auth/resend-verification', { email });
  return response.data;
};

export const logoutUser = async () => {
  try {
    await api.post('/auth/logout');
  } catch {
    // Ignore server logout error
  }
};

// Predict & XAI Endpoints
export const predictSingleUrl = async (url, model_name = 'XGBoost', include_xai = true, scan_type = 'url') => {
  const response = await api.post('/predict', { url, model_name, include_xai, scan_type });
  return response.data;
};

export const predictBulkUrls = async (urls, model_name = 'XGBoost') => {
  const response = await api.post('/predict/bulk', { urls, model_name });
  return response.data;
};

// History Endpoints
export const getScanHistory = async (page = 1, page_size = 15, search = '', filter_type = 'all', scan_type = 'all') => {
  const response = await api.get('/history', {
    params: { page, page_size, search, filter_type, scan_type },
  });
  return response.data;
};

export const getScanDetail = async (scanId) => {
  const response = await api.get(`/history/${scanId}`);
  return response.data;
};

export const deleteScan = async (scanId) => {
  const response = await api.delete(`/history/${scanId}`);
  return response.data;
};

export const clearAllHistory = async (scan_type = 'all') => {
  const response = await api.delete('/history', {
    params: { scan_type }
  });
  return response.data;
};

// Dashboard Endpoints
export const getDashboardStats = async () => {
  const response = await api.get('/dashboard');
  return response.data;
};

// Report Endpoints
export const getPdfDownloadUrl = (scanId) => {
  return `${API_BASE_URL}/reports/pdf/${scanId}`;
};

export const downloadScanPdf = async (scanId, customFilename = null) => {
  const response = await api.get(`/reports/pdf/${scanId}`, {
    responseType: 'blob',
  });
  
  const blob = new Blob([response.data], { type: 'application/pdf' });
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = downloadUrl;
  
  let filename = customFilename;
  const contentDisposition = response.headers['content-disposition'];
  if (!filename && contentDisposition) {
    const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/);
    if (filenameMatch && filenameMatch[1]) {
      filename = filenameMatch[1];
    }
  }
  if (!filename) {
    filename = `PhishGuard_Audit_Report_${scanId}.pdf`;
  }
  
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(downloadUrl);
  return filename;
};

export const downloadCsvReport = async () => {
  const response = await api.get('/reports/export-csv', {
    responseType: 'blob',
  });
  const blob = new Blob([response.data], { type: 'text/csv' });
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = downloadUrl;
  link.setAttribute('download', `phishguard_scans_${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(downloadUrl);
};

export const getCsvExportUrl = () => {
  return `${API_BASE_URL}/reports/export-csv`;
};

// Chatbot Endpoints
export const querySecurityChatbot = async (message, scannedUrlContext = '', predictionContext = null, history = []) => {
  const response = await api.post('/chatbot', {
    message,
    scanned_url_context: scannedUrlContext,
    prediction_context: predictionContext,
    history: history,
  });
  return response.data;
};

// Admin Endpoints
export const listAdminUsers = async () => {
  const response = await api.get('/admin/users');
  return response.data;
};

export const toggleUserStatus = async (userId) => {
  const response = await api.put(`/admin/users/${userId}/toggle-status`);
  return response.data;
};

export const toggleUserRole = async (userId) => {
  const response = await api.put(`/admin/users/${userId}/toggle-role`);
  return response.data;
};

export const getDatasetStats = async () => {
  const response = await api.get('/admin/dataset-stats');
  return response.data;
};

export const retrainModel = async () => {
  const response = await api.post('/admin/retrain-model');
  return response.data;
};

export const getSystemHealth = async () => {
  const response = await api.get('/admin/system-health');
  return response.data;
};

// Additional Features API
export const simulateWhatIf = async (features, model_name = 'XGBoost') => {
  const response = await api.post('/predict/simulate-whatif', { features, model_name });
  return response.data;
};

export const scanEmailAddress = async (email) => {
  const response = await api.post('/email-scan', { email });
  return response.data;
};

export const scanEmailContent = async (emailOrSubject, body = '', sender = '') => {
  const email = (typeof emailOrSubject === 'string' && emailOrSubject.includes('@') && !body)
    ? emailOrSubject
    : (sender || emailOrSubject || body);
  const response = await api.post('/email-scan', { email, subject: emailOrSubject, body, sender });
  return response.data;
};

export const lookupThreatIndicator = async (queryTerm) => {
  const encoded = encodeURIComponent(queryTerm);
  const response = await api.get(`/threat-lookup/${encoded}`);
  return response.data;
};

// 10-Module Architecture API Endpoints
export const getModulesRegistry = async () => {
  const response = await api.get('/modules/registry');
  return response.data;
};

export const getModulesStatus = async () => {
  const response = await api.get('/modules/status');
  return response.data;
};

export const getModuleDatasetInfo = async (url = '') => {
  const response = await api.get('/modules/dataset-info', { params: url ? { url } : {} });
  return response.data;
};

export const runModuleValidation = async (url) => {
  const response = await api.post('/modules/validate-url', { url });
  return response.data;
};

export const runModuleFeatureExtraction = async (url) => {
  const response = await api.post('/modules/extract-features', { url });
  return response.data;
};

export const runModuleFeaturePreprocessing = async (features) => {
  const response = await api.post('/modules/preprocess-features', { features });
  return response.data;
};

export const runModuleClassification = async (features, model_name = 'XGBoost') => {
  const response = await api.post('/modules/classify', { features, model_name });
  return response.data;
};

export const runModuleRiskAnalysis = async (features, model_name = 'XGBoost') => {
  const response = await api.post('/modules/risk-analysis', { features, model_name });
  return response.data;
};

export const runModuleXAIExplain = async (features, model_name = 'XGBoost') => {
  const response = await api.post('/modules/xai-explain', { features, model_name });
  return response.data;
};

export const getModuleFeatureImportance = async (model_name = 'XGBoost', url = '') => {
  const response = await api.get('/modules/feature-importance', { params: url ? { model_name, url } : { model_name } });
  return response.data;
};

export const getModuleDatabaseStats = async () => {
  const response = await api.get('/modules/database-stats');
  return response.data;
};

export const runModuleRecommendations = async (features) => {
  const response = await api.post('/modules/recommendations', { features });
  return response.data;
};

export const runFull10ModulePipeline = async (url, model_name = 'XGBoost', include_xai = true) => {
  const response = await api.post('/modules/pipeline-run', { url, model_name, include_xai });
  return response.data;
};

export default api;

