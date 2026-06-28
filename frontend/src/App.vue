<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useI18n } from './i18n'
import { useTheme } from './composables/useTheme'
import { useAuthStore } from './stores/auth'

const route = useRoute()
const router = useRouter()
const isCollapse = ref(false)
const { locale, t, setLocale } = useI18n()
const { isDark, toggleTheme } = useTheme()
const auth = useAuthStore()

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

// M6：进入受保护页时拉取用户信息（token 已由守卫校验存在）
onMounted(() => {
  if (auth.isAuthenticated) auth.fetchMe()
})

async function handleLogout() {
  await auth.logout()
  router.push({ name: 'Login' })
}

// M6：修改密码
const pwdDialog = ref(false)
const pwdForm = reactive({ oldPassword: '', newPassword: '', confirmPassword: '' })
const pwdLoading = ref(false)

function openChangePassword() {
  pwdForm.oldPassword = ''
  pwdForm.newPassword = ''
  pwdForm.confirmPassword = ''
  pwdDialog.value = true
}

async function submitChangePassword() {
  if (pwdForm.newPassword.length < 6) {
    ElMessage.warning(t('passwordTooShort'))
    return
  }
  if (pwdForm.newPassword !== pwdForm.confirmPassword) {
    ElMessage.warning(t('passwordMismatch'))
    return
  }
  pwdLoading.value = true
  try {
    await auth.changePassword(pwdForm.oldPassword, pwdForm.newPassword)
    ElMessage.success(t('passwordChanged'))
    pwdDialog.value = false
  } catch (error) {
    ElMessage.error(error.friendlyMessage || t('loginFailed'))
  } finally {
    pwdLoading.value = false
  }
}
</script>

<template>
  <router-view v-if="route.name === 'Login'" />
  <el-container v-else style="height: 100vh">
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
          <el-divider direction="vertical" />
          <span v-if="auth.user" class="app-user">{{ auth.user.username }}</span>
          <el-button size="small" @click="openChangePassword">{{ t('changePassword') }}</el-button>
          <el-button size="small" type="danger" plain @click="handleLogout">{{ t('logout') }}</el-button>
        </div>
      </el-header>
      <el-main class="app-main">
        <router-view />
      </el-main>
    </el-container>

    <el-dialog v-model="pwdDialog" :title="t('changePassword')" width="420px">
      <el-form label-width="110px">
        <el-form-item :label="t('oldPassword')">
          <el-input v-model="pwdForm.oldPassword" type="password" show-password />
        </el-form-item>
        <el-form-item :label="t('newPassword')">
          <el-input v-model="pwdForm.newPassword" type="password" show-password />
        </el-form-item>
        <el-form-item :label="t('confirmPassword')">
          <el-input v-model="pwdForm.confirmPassword" type="password" show-password />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pwdDialog = false">{{ t('cancel') }}</el-button>
        <el-button type="primary" :loading="pwdLoading" @click="submitChangePassword">{{ t('save') }}</el-button>
      </template>
    </el-dialog>
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
.app-user {
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
.app-main {
  background: var(--bg-page);
  padding: 20px;
}
</style>
