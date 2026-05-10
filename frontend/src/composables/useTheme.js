import { ref, watchEffect } from 'vue'

const STORAGE_KEY = 'codescan-theme'

const isDark = ref(false)

function applyTheme(dark) {
  document.documentElement.classList.toggle('dark', dark)
}

function initTheme() {
  const stored = localStorage.getItem(STORAGE_KEY)
  if (stored === 'dark' || stored === 'light') {
    isDark.value = stored === 'dark'
  } else {
    isDark.value = window.matchMedia('(prefers-color-scheme: dark)').matches
  }
  applyTheme(isDark.value)
}

function toggleTheme() {
  isDark.value = !isDark.value
}

initTheme()

watchEffect(() => {
  localStorage.setItem(STORAGE_KEY, isDark.value ? 'dark' : 'light')
  applyTheme(isDark.value)
})

export function useTheme() {
  return { isDark, toggleTheme }
}
