import { ElMessage, ElMessageBox } from 'element-plus'
import { deleteAudit } from '../api'
import { useI18n } from '../i18n'
import { isAuditDeleteBlocked } from '../utils/auditTaskState'

export function useAuditDeletion(onDeleted) {
  const { t } = useI18n()

  const removeAudit = async (audit) => {
    if (isAuditDeleteBlocked(audit)) {
      ElMessage.warning(t('deleteAuditRunningBlocked'))
      return false
    }

    try {
      await ElMessageBox.confirm(
        t('deleteAuditConfirm', { id: audit.id }),
        t('confirm'),
        { type: 'warning' },
      )
      await deleteAudit(audit.id)
      ElMessage.success(t('deleted'))
      await onDeleted?.(audit)
      return true
    } catch (e) {
      if (e !== 'cancel') {
        ElMessage.error(e.friendlyMessage || t('deleteFailed'))
      }
      return false
    }
  }

  return { removeAudit }
}
