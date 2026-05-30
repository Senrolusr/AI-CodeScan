const hasClaimedAudit = (audit) => Boolean(audit?.summary?._queue_claimed_at)

export const hasActiveAuditWorker = (audit) => (
  audit?.status === 'running'
  || hasClaimedAudit(audit)
)

export const isAuditRunning = (audit) => (
  ['pending', 'running'].includes(audit?.status)
)

export const isAuditDeleteBlocked = (audit) => (
  isAuditRunning(audit) || hasActiveAuditWorker(audit)
)

export const isAuditRetryBlocked = (audit) => (
  isAuditRunning(audit) || hasClaimedAudit(audit)
)
