// jsdom 缺失的浏览器 API 补丁：Element Plus 的 popper / 折叠 / 响应式组件依赖
// ResizeObserver / IntersectionObserver / matchMedia，jsdom 没有这些，不补会抛错。
class _RO {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = globalThis.ResizeObserver || _RO
globalThis.IntersectionObserver = globalThis.IntersectionObserver || _RO

if (!globalThis.matchMedia) {
  globalThis.matchMedia = (query) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener() {},
    removeEventListener() {},
    addListener() {},
    removeListener() {},
    dispatchEvent() { return false },
  })
}
