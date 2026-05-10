import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  { path: '/', name: 'Dashboard', component: () => import('../views/Dashboard.vue') },
  { path: '/projects', name: 'Projects', component: () => import('../views/Projects.vue') },
  { path: '/projects/:id', name: 'ProjectDetail', component: () => import('../views/ProjectDetail.vue'), props: true },
  { path: '/llm-configs', name: 'LlmConfigs', component: () => import('../views/LlmConfigs.vue') },
  { path: '/audits/:id', name: 'AuditDetail', component: () => import('../views/AuditDetail.vue'), props: true },
  { path: '/audits/:id/stage-one', name: 'StageOneDetail', component: () => import('../views/StageOneDetail.vue'), props: true },
  { path: '/audits/:id/stages/:stageNum/artifact', name: 'StageArtifactDetail', component: () => import('../views/StageArtifactDetail.vue'), props: true },
  { path: '/vulns/:id', name: 'VulnDetail', component: () => import('../views/VulnDetail.vue'), props: true },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
