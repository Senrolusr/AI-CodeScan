import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const detail = error.response?.data?.detail
    if (typeof detail === 'string') {
      error.friendlyMessage = detail
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
export const getAuditStages = (id, params) => api.get(`/audits/${id}/stages`, { params })
export const getAuditStage = (id, stageNum) => api.get(`/audits/${id}/stages/${stageNum}`)
export const getAuditStageArtifact = (id, stageNum) => api.get(`/audits/${id}/stages/${stageNum}/artifact`)
export const getAuditVulns = (id, params) => api.get(`/audits/${id}/vulns`, { params })
export const cancelAudit = (id) => api.post(`/audits/${id}/cancel`)
export const retryAudit = (id) => api.post(`/audits/${id}/retry`)
export const deleteAudit = (id) => api.delete(`/audits/${id}`)

// Vulnerabilities
export const getVulns = (params) => api.get('/vulnerabilities', { params })
export const getVuln = (id) => api.get(`/vulnerabilities/${id}`)
export const updateVulnStatus = (id, status) => api.patch(`/vulnerabilities/${id}`, { confirmed_status: status })
export const deleteVuln = (id) => api.delete(`/vulnerabilities/${id}`)

// Reports
export const exportReport = (taskId, format) => api.post('/reports/export', { task_id: taskId, format })
export const getReports = (taskId) => api.get(`/reports/list/${taskId}`)
export const deleteReport = (taskId, filename) => api.delete(`/reports/${taskId}/${encodeURIComponent(filename)}`)

// Stats
export const getStats = () => api.get('/stats')

export default api
