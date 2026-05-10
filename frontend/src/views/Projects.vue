<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { getProjects, uploadProject, deleteProject } from '../api'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useI18n } from '../i18n'

const router = useRouter()
const { t, formatDate } = useI18n()
const projects = ref([])
const loading = ref(true)
const uploadDialog = ref(false)
const uploading = ref(false)
const form = ref({ name: '' })
const fileList = ref([])

const loadProjects = async () => {
  loading.value = true
  try {
    const res = await getProjects()
    projects.value = res.data
  } catch (e) {
    ElMessage.error(t('failedLoadProjects'))
  } finally {
    loading.value = false
  }
}

onMounted(loadProjects)

const handleUpload = async () => {
  if (!form.value.name || !fileList.value.length) {
    ElMessage.warning(t('uploadFillWarning'))
    return
  }
  const selectedFile = fileList.value[0]?.raw
  if (!selectedFile || !selectedFile.name?.toLowerCase().endsWith('.zip')) {
    ElMessage.warning(t('zipOnly'))
    return
  }
  uploading.value = true
  try {
    const fd = new FormData()
    fd.append('file', selectedFile)
    fd.append('name', form.value.name)
    await uploadProject(fd)
    ElMessage.success(t('uploadSuccess'))
    uploadDialog.value = false
    form.value = { name: '' }
    fileList.value = []
    loadProjects()
  } catch (e) {
    ElMessage.error(e.friendlyMessage || t('uploadFailed'))
  } finally {
    uploading.value = false
  }
}

const handleDelete = async (p) => {
  try {
    await ElMessageBox.confirm(t('deleteProjectConfirm', { name: p.name }), t('confirm'), { type: 'warning' })
    await deleteProject(p.id)
    ElMessage.success(t('deleted'))
    loadProjects()
  } catch {}
}

const handleFileChange = (file, newFileList) => {
  fileList.value = newFileList.slice(-1)
  if (file?.raw && !file.raw.name?.toLowerCase().endsWith('.zip')) {
    ElMessage.warning(t('zipOnly'))
    fileList.value = []
  }
}
</script>

<template>
  <div>
    <div class="page-header">
      <h2 style="margin: 0">{{ t('projectsTitle') }}</h2>
      <el-button type="primary" @click="uploadDialog = true">
        <el-icon><Upload /></el-icon> {{ t('uploadProject') }}
      </el-button>
    </div>

    <el-row :gutter="16" v-loading="loading">
      <el-col :span="8" v-for="p in projects" :key="p.id" style="margin-bottom: 16px">
        <el-card shadow="hover" @click="router.push(`/projects/${p.id}`)" style="cursor: pointer">
          <template #header>
            <div style="display: flex; justify-content: space-between; align-items: center">
              <span class="card-title">{{ p.name }}</span>
              <el-button size="small" text type="danger" @click.stop="handleDelete(p)">
                <el-icon><Delete /></el-icon>
              </el-button>
            </div>
          </template>
          <div class="text-muted">
            <div v-if="p.tech_stack">
              <el-tag size="small" type="info">{{ p.tech_stack }}</el-tag>
            </div>
            <div style="margin-top: 8px">{{ t('fileLabelShort', { count: p.file_count || 0 }) }}</div>
            <div style="margin-top: 4px">{{ formatDate(p.created_at) }}</div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-empty v-if="!loading && !projects.length" :description="t('noProjects')" />

    <!-- Upload Dialog -->
    <el-dialog v-model="uploadDialog" :title="t('uploadProjectTitle')" width="500px">
      <el-form label-width="100px">
        <el-form-item :label="t('name')">
          <el-input v-model="form.name" :placeholder="t('name')" />
        </el-form-item>
        <el-form-item :label="t('sourceZip')">
          <el-upload
            :auto-upload="false"
            :limit="1"
            accept=".zip"
            :on-change="handleFileChange"
            :file-list="fileList"
          >
            <el-button>{{ t('selectZip') }}</el-button>
            <template #tip><div class="el-upload__tip">{{ t('zipOnly') }}</div></template>
          </el-upload>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="uploadDialog = false">{{ t('cancel') }}</el-button>
        <el-button type="primary" :loading="uploading" @click="handleUpload">{{ t('upload') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>
