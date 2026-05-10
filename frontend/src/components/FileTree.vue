<script setup>
import { ref } from 'vue'

const props = defineProps({ tree: Array })
const emit = defineEmits(['select'])
const expanded = ref({})

const toggle = (path) => {
  expanded.value[path] = !expanded.value[path]
}
</script>

<template>
  <div class="file-tree">
    <template v-for="node in tree" :key="node.path">
      <!-- Directory -->
      <div v-if="node.type === 'directory'">
        <div class="tree-item dir" @click="toggle(node.path)">
          <el-icon size="14">
            <component :is="expanded[node.path] ? 'FolderOpened' : 'Folder'" />
          </el-icon>
          <span>{{ node.name }}</span>
        </div>
        <div v-show="expanded[node.path]" style="padding-left: 16px">
          <FileTree :tree="node.children || []" @select="emit('select', $event)" />
        </div>
      </div>
      <!-- File -->
      <div v-else class="tree-item file" @click="emit('select', node.path)">
        <el-icon size="14" color="#909399"><Document /></el-icon>
        <span>{{ node.name }}</span>
      </div>
    </template>
  </div>
</template>

<style scoped>
.tree-item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 8px;
  cursor: pointer;
  font-size: 13px;
  border-radius: 4px;
  color: var(--text-secondary);
}
.tree-item:hover {
  background: #f5f7fa;
}
.tree-item.dir {
  color: var(--text-primary);
  font-weight: 500;
}
.tree-item.file {
  color: var(--text-secondary);
}
</style>
