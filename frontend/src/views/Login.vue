<script setup>
import { ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '../stores/auth'
import { useI18n } from '../i18n'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const { locale, t, setLocale } = useI18n()

const form = ref({ username: '', password: '' })
const loading = ref(false)

async function handleSubmit() {
  if (!form.value.username || !form.value.password) {
    ElMessage.warning(t('loginFillWarning'))
    return
  }
  loading.value = true
  try {
    await auth.login(form.value.username, form.value.password)
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
    router.push(redirect)
  } catch (error) {
    ElMessage.error(error.friendlyMessage || t('loginFailed'))
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="login-page">
    <div class="login-lang">
      <el-button size="small" :type="locale === 'zh' ? 'primary' : 'default'" @click="setLocale('zh')">
        {{ t('languageZh') }}
      </el-button>
      <el-button size="small" :type="locale === 'en' ? 'primary' : 'default'" @click="setLocale('en')">
        {{ t('languageEn') }}
      </el-button>
    </div>
    <el-card class="login-card">
      <h2 class="login-title">{{ t('appTitle') }}</h2>
      <p class="login-subtitle">{{ t('loginTitle') }}</p>
      <el-form @submit.prevent="handleSubmit">
        <el-form-item>
          <el-input
            v-model="form.username"
            :placeholder="t('username')"
            size="large"
            autocomplete="username"
            @keyup.enter="handleSubmit"
          />
        </el-form-item>
        <el-form-item>
          <el-input
            v-model="form.password"
            type="password"
            show-password
            :placeholder="t('password')"
            size="large"
            autocomplete="current-password"
            @keyup.enter="handleSubmit"
          />
        </el-form-item>
        <el-button type="primary" size="large" style="width: 100%" :loading="loading" @click="handleSubmit">
          {{ t('login') }}
        </el-button>
      </el-form>
    </el-card>
  </div>
</template>

<style scoped>
.login-page {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg-page);
  position: relative;
}
.login-lang {
  position: absolute;
  top: 16px;
  right: 16px;
  display: flex;
  gap: 8px;
}
.login-card {
  width: 380px;
  padding: 24px 16px;
}
.login-title {
  text-align: center;
  margin: 0 0 4px;
  font-size: 22px;
}
.login-subtitle {
  text-align: center;
  color: var(--el-text-color-secondary);
  margin: 0 0 24px;
  font-size: 14px;
}
</style>
