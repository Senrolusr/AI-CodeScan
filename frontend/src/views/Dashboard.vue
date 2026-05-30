<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getStats, getAudits, getVulns, deleteVuln } from '../api'
import { useI18n } from '../i18n'
import { useAuditDeletion } from '../composables/useAuditDeletion'
import { isAuditDeleteBlocked } from '../utils/auditTaskState'

const router = useRouter()
const stats = ref({ project_count: 0, audit_count: 0, vuln_count: 0, critical_count: 0 })
const recentAudits = ref([])
const recentVulns = ref([])
const loading = ref(true)
const { t, statusLabel, severityLabel, severityColor, statusType, formatDateTime } = useI18n()

const loadDashboard = async () => {
  try {
    const [statsRes, auditsRes, vulnsRes] = await Promise.all([
      getStats(),
      getAudits(undefined, 5),
      getVulns({ limit: 10 }),
    ])
    stats.value = statsRes.data
    recentAudits.value = auditsRes.data || []
    recentVulns.value = vulnsRes.data || []
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
}

onMounted(loadDashboard)

const { removeAudit } = useAuditDeletion(loadDashboard)

const removeVuln = async (vuln) => {
  try {
    await ElMessageBox.confirm(
      t('deleteVulnConfirm', { title: vuln.title }),
      t('confirm'),
      { type: 'warning' },
    )
    await deleteVuln(vuln.id)
    ElMessage.success(t('deleted'))
    await loadDashboard()
  } catch (e) {
    if (e !== 'cancel') {
      ElMessage.error(e.friendlyMessage || t('deleteFailed'))
    }
  }
}

</script>

<template>
  <div v-loading="loading">
    <!-- Stats Cards -->
    <el-row :gutter="20" style="margin-bottom: 24px">
      <el-col :span="6" v-for="(item, idx) in [
        { label: t('projectCount'), key: 'project_count', icon: 'FolderOpened', color: '#409EFF' },
        { label: t('auditCount'), key: 'audit_count', icon: 'Search', color: '#67C23A' },
        { label: t('vulnerabilityCount'), key: 'vuln_count', icon: 'Warning', color: '#E6A23C' },
        { label: t('criticalHigh'), key: 'critical_count', icon: 'CircleClose', color: '#F56C6C' },
      ]" :key="idx">
        <el-card shadow="hover" :body-style="{ padding: '20px' }">
          <div style="display: flex; align-items: center; gap: 16px">
            <el-icon :size="36" :color="item.color"><component :is="item.icon" /></el-icon>
            <div>
              <div style="font-size: 28px; font-weight: bold; color: var(--text-primary)">{{ stats[item.key] }}</div>
              <div style="font-size: 14px; color: var(--text-muted)">{{ item.label }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20">
      <!-- Recent Audits -->
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <span style="font-weight: bold">{{ t('recentAudits') }}</span>
          </template>
          <el-table :data="recentAudits" stripe size="small" v-if="recentAudits.length">
            <el-table-column prop="id" label="ID" width="60" />
            <el-table-column prop="project_id" :label="t('project')" width="80" />
            <el-table-column prop="status" :label="t('status')" width="100">
              <template #default="{ row }">
                <el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="current_stage" :label="t('stage')" width="70">
              <template #default="{ row }">{{ row.current_stage }}/{{ row.total_stages }}</template>
            </el-table-column>
            <el-table-column :label="t('action')" width="130">
              <template #default="{ row }">
                <el-button size="small" text type="primary" @click="router.push(`/audits/${row.id}`)">
                  {{ t('view') }}
                </el-button>
                <el-button
                  size="small"
                  text
                  type="danger"
                  :disabled="isAuditDeleteBlocked(row)"
                  @click="removeAudit(row)"
                >
                  {{ t('delete') }}
                </el-button>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-else :description="t('noAudits')" :image-size="60" />
        </el-card>
      </el-col>

      <!-- Recent Vulnerabilities -->
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <span style="font-weight: bold">{{ t('recentVulnerabilities') }}</span>
          </template>
          <el-table :data="recentVulns" stripe size="small" v-if="recentVulns.length">
            <el-table-column prop="title" :label="t('title')" show-overflow-tooltip />
            <el-table-column prop="severity" :label="t('severity')" width="90">
              <template #default="{ row }">
                <el-tag :color="severityColor(row.severity)" effect="dark" size="small" style="border: none">
                  {{ severityLabel(row.severity) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column :label="t('action')" width="130">
              <template #default="{ row }">
                <el-button size="small" text type="primary" @click="router.push(`/vulns/${row.id}`)">
                  {{ t('detail') }}
                </el-button>
                <el-button size="small" text type="danger" @click="removeVuln(row)">
                  {{ t('delete') }}
                </el-button>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-else :description="t('noVulns')" :image-size="60" />
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>
