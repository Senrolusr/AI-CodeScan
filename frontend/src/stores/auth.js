import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '../api'

const TOKEN_KEY = 'auth_token'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(typeof localStorage !== 'undefined' ? (localStorage.getItem(TOKEN_KEY) || '') : '')
  const user = ref(null)

  const isAuthenticated = computed(() => !!token.value)

  function setToken(value) {
    token.value = value || ''
    if (token.value) {
      localStorage.setItem(TOKEN_KEY, token.value)
    } else {
      localStorage.removeItem(TOKEN_KEY)
    }
  }

  async function login(username, password) {
    const { data } = await api.post('/auth/login', { username, password })
    setToken(data.token)
    user.value = data.user
    return data
  }

  async function fetchMe() {
    if (!token.value) return null
    try {
      const { data } = await api.get('/auth/me')
      user.value = data
      return data
    } catch (error) {
      if (error.response?.status === 401) {
        setToken('')
        user.value = null
      }
      return null
    }
  }

  async function logout() {
    try {
      await api.post('/auth/logout')
    } catch (_e) {
      // 即使后端调用失败也强制清空本地态
    }
    setToken('')
    user.value = null
  }

  async function changePassword(oldPassword, newPassword) {
    await api.patch('/auth/password', { old_password: oldPassword, new_password: newPassword })
  }

  return { token, user, isAuthenticated, setToken, login, fetchMe, logout, changePassword }
})
