import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

// 前端单元测试配置（文档 §14.2）。
// jsdom 提供 DOM 给组件测试；globals=true 免逐文件 import describe/it/expect。
// store 测试不碰 DOM，但统一 jsdom 环境开销可忽略，避免按文件切环境的复杂度。
export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.{test,spec}.js'],
    setupFiles: ['./vitest.setup.js'],
  },
})
