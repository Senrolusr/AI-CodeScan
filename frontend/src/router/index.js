import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  { path: '/login', name: 'Login', component: () => import('../views/Login.vue'), meta: { public: true } },
  { path: '/', name: 'Dashboard', component: () => import('../views/Dashboard.vue'), meta: { requiresAuth: true } },
  { path: '/projects', name: 'Projects', component: () => import('../views/Projects.vue'), meta: { requiresAuth: true } },
  { path: '/projects/:id', name: 'ProjectDetail', component: () => import('../views/ProjectDetail.vue'), props: true, meta: { requiresAuth: true } },
  { path: '/llm-configs', name: 'LlmConfigs', component: () => import('../views/LlmConfigs.vue'), meta: { requiresAuth: true } },
  { path: '/audits/:id', name: 'AuditDetail', component: () => import('../views/AuditDetail.vue'), props: true, meta: { requiresAuth: true } },
  { path: '/audits/:id/stage-one', name: 'StageOneDetail', component: () => import('../views/StageOneDetail.vue'), props: true, meta: { requiresAuth: true } },
  { path: '/audits/:id/stages/:stageNum/artifact', name: 'StageArtifactDetail', component: () => import('../views/StageArtifactDetail.vue'), props: true, meta: { requiresAuth: true } },
  { path: '/vulns/:id', name: 'VulnDetail', component: () => import('../views/VulnDetail.vue'), props: true, meta: { requiresAuth: true } },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// M6：路由守卫——未登录访问受保护页 → /login；已登录访问 /login → /
// 直接读 localStorage（不 import store），避免 router ↔ store ↔ api 循环依赖。
const TOKEN_KEY = 'auth_token'
router.beforeEach((to) => {
  const token = typeof localStorage !== 'undefined' ? localStorage.getItem(TOKEN_KEY) : null
  if (to.meta.requiresAuth && !token) {
    return { name: 'Login', query: to.fullPath !== '/' ? { redirect: to.fullPath } : undefined }
  }
  if (to.name === 'Login' && token) {
    return { path: '/' }
  }
  return true
})

export default router
