import axios from 'axios'

const TOKEN_KEY = 'auth_token'

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
})

// M6：请求拦截器——从 localStorage 注入 Bearer token（不 import store，避免循环依赖）
api.interceptors.request.use((config) => {
  const token = typeof localStorage !== 'undefined' ? localStorage.getItem(TOKEN_KEY) : null
  if (token) {
    config.headers = config.headers || {}
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// M6：响应拦截器——401 清 token 并跳登录页（登录页自身的 401 不跳）
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status
    const data = error.response?.data
    // §11.4：后端统一错误响应 {code, message, details}；message 承载友好提示。
    // 兼容旧 detail 字符串（非统一格式的兜底）。
    if (data && typeof data === 'object') {
      error.code = data.code
      error.details = data.details
      if (typeof data.message === 'string' && data.message) {
        error.friendlyMessage = data.message
      }
    }
    if (!error.friendlyMessage && typeof data?.detail === 'string') {
      error.friendlyMessage = data.detail
    }
    if (status === 401) {
      if (typeof localStorage !== 'undefined') localStorage.removeItem(TOKEN_KEY)
      // 动态 import router，避免 api ↔ router 循环依赖
      import('../router').then(({ default: router }) => {
        if (router.currentRoute.value.name !== 'Login') {
          router.push({ name: 'Login' })
        }
      })
    }
    return Promise.reject(error)
  },
)

// Projects
export const uploadProject = (formData) => api.post('/projects/upload', formData, { timeout: 120000 })
export const getProjects = () => api.get('/projects')
export const getProject = (id) => api.get(`/projects/${id}`)
export const rebuildProjectCache = (id) => api.post(`/projects/${id}/rebuild-cache`)
export const getProjectFile = (id, path) => api.get(`/projects/${id}/file`, { params: { path } })
export const deleteProject = (id) => api.delete(`/projects/${id}`)
export const getProjectRoutes = (id) => api.get(`/projects/${id}/routes`)
export const getProjectRuleHits = (id) => api.get(`/projects/${id}/rule-hits`)

// LLM Configs
export const getLlmConfigs = () => api.get('/llm-configs')
export const createLlmConfig = (data) => api.post('/llm-configs', data)
export const updateLlmConfig = (id, data) => api.put(`/llm-configs/${id}`, data)
export const deleteLlmConfig = (id) => api.delete(`/llm-configs/${id}`)
export const testLlmConfig = (id) => api.post(`/llm-configs/${id}/test`)

// Audits
export const createAudit = (data) => api.post('/audits', data)
export const getAudits = (projectId, limit) => api.get('/audits', { params: { project_id: projectId, limit } })
export const getAudit = (id) => api.get(`/audits/${id}`)
export const getAuditSnapshot = (id, params) => api.get(`/audits/${id}/snapshot`, { params })
const normalizeAuditEventParams = (afterId = 0, limit = 100) => {
  if (afterId && typeof afterId === 'object') {
    const cursor = afterId.after_id ?? afterId.since_sequence ?? 0
    return {
      after_id: Number(cursor || 0),
      limit: Number(afterId.limit || limit || 100),
    }
  }
  return { after_id: Number(afterId || 0), limit: Number(limit || 100) }
}
export const getAuditEvents = (id, afterId = 0, limit = 100) =>
  api.get(`/audits/${id}/events`, { params: normalizeAuditEventParams(afterId, limit) })
export const getAuditStages = (id, params) => api.get(`/audits/${id}/stages`, { params })
export const getAuditStage = (id, stageNum) => api.get(`/audits/${id}/stages/${stageNum}`)
export const getAuditStageArtifact = (id, stageNum) => api.get(`/audits/${id}/stages/${stageNum}/artifact`)
export const cancelAudit = (id) => api.post(`/audits/${id}/cancel`)
export const retryAudit = (id, stageNums) =>
  api.post(`/audits/${id}/retry`, stageNums && stageNums.length ? { stage_nums: stageNums } : undefined)
export const pauseAudit = (id) => api.post(`/audits/${id}/pause`)
export const resumeAudit = (id) => api.post(`/audits/${id}/resume`)
export const deleteAudit = (id) => api.delete(`/audits/${id}`)

// Vulnerabilities
export const getVulns = (params) => api.get('/vulnerabilities', { params })
export const getVuln = (id) => api.get(`/vulnerabilities/${id}`)
export const updateVulnReview = (id, payload) => api.patch(`/vulnerabilities/${id}`, payload)
export const deleteVuln = (id) => api.delete(`/vulnerabilities/${id}`)

// Reports
export const exportReport = (taskId, format = 'html') => api.post('/reports/export', { task_id: taskId, format })
export const deleteReport = (taskId, filename) => api.delete(`/reports/${taskId}/${encodeURIComponent(filename)}`)
// M6：报告下载改走鉴权 API（blob），替代旧的 /reports 静态挂载 + window.open
export const downloadByUrl = (url) => {
  // download_url 形如 /api/reports/download/...，去掉 /api 前缀避免与 baseURL(/api) 叠加
  const stripped = String(url || '').replace(/^\/api\//, '/')
  return api.get(stripped, { responseType: 'blob' })
}

// Stats
export const getStats = () => api.get('/stats')

export default api
