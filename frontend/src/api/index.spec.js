import { describe, it, expect, vi, beforeEach } from 'vitest'
import api, { getAuditEvents } from './index'

// §11.4：响应拦截器把后端统一错误 {code, message, details} 挂到 error 对象。
// 直接取 axios instance 内部注册的 onRejected handler 驱动（避开真实网络）。
const onError = api.interceptors.response.handlers[0].rejected

describe('response interceptor (§11.4 统一错误)', () => {
  it('挂载 code / friendlyMessage / details', async () => {
    const error = {
      response: {
        status: 404,
        data: { code: 'AUDIT_NOT_FOUND', message: '审计任务不存在', details: { foo: 1 } },
      },
    }
    await expect(onError(error)).rejects.toMatchObject({
      code: 'AUDIT_NOT_FOUND',
      friendlyMessage: '审计任务不存在',
      details: { foo: 1 },
    })
  })

  it('兼容旧 detail 字符串（非统一格式兜底）', async () => {
    const error = { response: { status: 400, data: { detail: '旧消息' } } }
    await expect(onError(error)).rejects.toMatchObject({ friendlyMessage: '旧消息' })
  })

  it('message 缺失时不抛错，friendlyMessage 保持未设置', async () => {
    const error = { response: { status: 500, data: { code: 'X' } } }
    await expect(onError(error)).rejects.toMatchObject({ code: 'X' })
  })
})

describe('getAuditEvents', () => {
  beforeEach(() => {
    vi.spyOn(api, 'get').mockResolvedValue({ data: {} })
  })

  it('序列化数字 after_id 和 limit', async () => {
    await getAuditEvents(12, 34, 500)
    expect(api.get).toHaveBeenCalledWith('/audits/12/events', {
      params: { after_id: 34, limit: 500 },
    })
  })

  it('兼容对象参数 after_id', async () => {
    await getAuditEvents(12, { after_id: 34, limit: 200 })
    expect(api.get).toHaveBeenCalledWith('/audits/12/events', {
      params: { after_id: 34, limit: 200 },
    })
  })

  it('兼容旧对象参数 since_sequence', async () => {
    await getAuditEvents(12, { since_sequence: 34, limit: 200 })
    expect(api.get).toHaveBeenCalledWith('/audits/12/events', {
      params: { after_id: 34, limit: 200 },
    })
  })
})
