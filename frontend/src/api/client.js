import axios from 'axios'

const ACTIVE_KEY_STORAGE = 'mw_active_api_key'
const ACTIVE_KEY_MASK_STORAGE = 'mw_active_api_key_mask'

const apiClient = axios.create({
  baseURL: '/api',
  timeout: 30000,
})

export function getActiveApiKey() {
  return localStorage.getItem(ACTIVE_KEY_STORAGE) || ''
}

export function setActiveApiKey(key, maskedKey = '') {
  if (!key) {
    localStorage.removeItem(ACTIVE_KEY_STORAGE)
    localStorage.removeItem(ACTIVE_KEY_MASK_STORAGE)
    return
  }
  localStorage.setItem(ACTIVE_KEY_STORAGE, key)
  if (maskedKey) {
    localStorage.setItem(ACTIVE_KEY_MASK_STORAGE, maskedKey)
  }
}

export function getActiveApiKeyMask() {
  return localStorage.getItem(ACTIVE_KEY_MASK_STORAGE) || ''
}

apiClient.interceptors.request.use((config) => {
  const key = getActiveApiKey()
  if (key) {
    config.headers['X-API-Key'] = key
  }
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const detail = error.response?.data?.detail
    const message =
      (typeof detail === 'string' && detail) ||
      detail?.error ||
      error.response?.data?.message ||
      error.message ||
      'Unexpected API error'
    return Promise.reject(new Error(message))
  }
)

export const predict = (record) => apiClient.post('/predict', record).then((r) => r.data)

export const predictBatch = (payload) =>
  apiClient.post('/predict/batch', payload).then((r) => r.data)

export const predictCSV = (file) => {
  const formData = new FormData()
  formData.append('file', file)
  return apiClient
    .post('/predict/csv', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    .then((r) => r.data)
}

export const getModelInfo = () => apiClient.get('/model/info').then((r) => r.data)

export const getFeatureImportance = () =>
  apiClient.get('/model/feature-importance').then((r) => r.data)

export const getHealth = () => apiClient.get('/health').then((r) => r.data)

export const getStreamStats = () => apiClient.get('/stream/stats').then((r) => r.data)

export const getScenarios = () => apiClient.get('/simulate/scenarios').then((r) => r.data)

export const injectScenario = (scenario) =>
  apiClient.post('/simulate/scenario', { scenario }).then((r) => r.data)

export const createApiKey = (payload) => apiClient.post('/keys', payload).then((r) => r.data)

export const listApiKeys = () => apiClient.get('/keys').then((r) => r.data)

export const revokeApiKey = (keyId) => apiClient.delete(`/keys/${keyId}`).then((r) => r.data)

export const getKeyUsage = (keyId) => apiClient.get(`/keys/${keyId}/usage`).then((r) => r.data)
