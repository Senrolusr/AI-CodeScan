<script setup>
import { ref, computed } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from './i18n'
import { useTheme } from './composables/useTheme'

const route = useRoute()
const isCollapse = ref(false)
const { locale, t, setLocale } = useI18n()
const { isDark, toggleTheme } = useTheme()

const menuItems = [
  { index: '/', icon: 'DataAnalysis', titleKey: 'dashboard' },
  { index: '/projects', icon: 'FolderOpened', titleKey: 'projects' },
  { index: '/llm-configs', icon: 'Setting', titleKey: 'llmConfigs' },
]

const activeMenu = computed(() => route.path)
const routeTitle = computed(() => {
  const map = {
    Dashboard: 'dashboard',
    Projects: 'projects',
    ProjectDetail: 'projects',
    LlmConfigs: 'llmConfigs',
    AuditDetail: 'audit',
    StageOneDetail: 'audit',
    StageArtifactDetail: 'audit',
    VulnDetail: 'vulnerabilityDetail',
  }
  return t(map[route.name] || 'home')
})
</script>

<template>
  <el-container style="height: 100vh">
    <el-aside :width="isCollapse ? '64px' : '220px'" class="app-sidebar">
      <div class="app-sidebar-logo">
        <span v-if="!isCollapse" style="font-size: 16px; font-weight: bold; white-space: nowrap">
          {{ t('appTitle') }}
        </span>
        <span v-else style="font-size: 14px; font-weight: bold">CAP</span>
      </div>
      <el-menu
        :default-active="activeMenu"
        :collapse="isCollapse"
        router
        style="border-right: none"
      >
        <el-menu-item v-for="item in menuItems" :key="item.index" :index="item.index">
          <el-icon><component :is="item.icon" /></el-icon>
          <template #title>{{ t(item.titleKey) }}</template>
        </el-menu-item>
      </el-menu>
      <div style="position: absolute; bottom: 20px; left: 0; right: 0; text-align: center">
        <el-button
          :icon="isCollapse ? 'Expand' : 'Fold'"
          text
          @click="isCollapse = !isCollapse"
        />
      </div>
    </el-aside>

    <el-container>
      <el-header class="app-header">
        <el-breadcrumb separator="/">
          <el-breadcrumb-item :to="{ path: '/' }">{{ t('home') }}</el-breadcrumb-item>
          <el-breadcrumb-item v-if="route.name !== 'Dashboard'">
            {{ routeTitle }}
          </el-breadcrumb-item>
        </el-breadcrumb>
        <div style="display: flex; gap: 8px; align-items: center">
          <el-button size="small" :type="locale === 'zh' ? 'primary' : 'default'" @click="setLocale('zh')">
            {{ t('languageZh') }}
          </el-button>
          <el-button size="small" :type="locale === 'en' ? 'primary' : 'default'" @click="setLocale('en')">
            {{ t('languageEn') }}
          </el-button>
          <el-button size="small" @click="toggleTheme" :title="isDark ? 'Light mode' : 'Dark mode'">
            {{ isDark ? '☀️' : '🌙' }}
          </el-button>
        </div>
      </el-header>
      <el-main class="app-main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<style scoped>
.app-sidebar {
  transition: width 0.3s;
  background: var(--bg-sidebar);
  border-right: 1px solid var(--border-sidebar);
  position: relative;
}
.app-sidebar :deep(.el-menu) {
  background: transparent;
}
.app-sidebar :deep(.el-menu-item) {
  color: var(--text-sidebar);
}
.app-sidebar :deep(.el-menu-item.is-active) {
  color: var(--text-sidebar-active);
}
.app-sidebar-logo {
  padding: 16px;
  text-align: center;
  border-bottom: 1px solid var(--border-sidebar);
  color: #fff;
}
html.dark .app-sidebar-logo {
  color: var(--text-primary);
}
.app-header {
  border-bottom: 1px solid var(--border-light);
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--bg-header);
}
.app-main {
  background: var(--bg-page);
  padding: 20px;
}
</style>
