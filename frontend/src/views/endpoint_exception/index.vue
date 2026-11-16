<template>
  <section class="page" data-module="endpoint-exception">
    <header class="page-head">
      <div>
        <h2>端点异常待处理清单</h2>
        <p class="page-desc">
          认证失败的端点自动落到本清单，工作台与凭据抽屉读取同一窗口；超出归属范围的账号看不到他人凭据的异常。
        </p>
      </div>
      <div class="page-actions">
        <label class="filter-item">
          <span>调用账号（归属范围）</span>
          <select v-model="session.account" @change="reload">
            <option v-for="item in session.accounts" :key="item.账号" :value="item.账号">
              {{ item.账号 }} · {{ item.说明 }}
            </option>
          </select>
        </label>
      </div>
    </header>

    <div class="stat-row">
      <article v-for="item in stats" :key="item.label" class="stat-card">
        <span class="stat-label">{{ item.label }}</span>
        <strong class="stat-value">{{ item.value }}</strong>
      </article>
    </div>

    <form class="filter-bar" @submit.prevent="reload">
      <label class="filter-item">
        <span>处理状态</span>
        <select v-model="statusFilter">
          <option value="">全部</option>
          <option value="待处理">待处理</option>
          <option value="已处理">已处理</option>
        </select>
      </label>
      <button class="btn" type="submit">查询</button>
      <button class="btn ghost" type="button" @click="statusFilter = ''; reload()">重置条件</button>
    </form>

    <table class="data-table">
      <thead>
        <tr>
          <th v-for="column in columns" :key="column">{{ column }}</th>
          <th>处理动作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="String(row.id)" :class="{ 'row-pending': row.处理状态 === '待处理' }">
          <td v-for="column in columns" :key="column">{{ row[column] ?? '—' }}</td>
          <td class="row-actions">
            <button
              v-if="row.处理状态 === '待处理'"
              class="link"
              type="button"
              @click="resolve(row)"
            >
              复核闭环
            </button>
            <span v-else class="muted-text">已闭环</span>
          </td>
        </tr>
        <tr v-if="!rows.length">
          <td :colspan="columns.length + 1" class="empty-state">
            当前账号归属范围内没有端点异常（认证失败与越权取用都会进入这里）
          </td>
        </tr>
      </tbody>
    </table>

    <footer class="page-foot">
      <span>共 {{ total }} 条异常记录</span>
      <span v-if="message" :class="messageOk ? '' : 'error-text'">{{ message }}</span>
    </footer>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { request } from '@/api/client'
import { useSessionStore } from '@/stores/session'

type Row = Record<string, string | number | null>

const ENDPOINT = '/api/endpoint-exception'
const CREDENTIAL_ENDPOINT = '/api/credential'
const session = useSessionStore()

const columns = ['异常编号', '凭证编号', '引用端点', '关联指纹', '异常原因', '上报账号', '处理状态', '发生时间', '处理说明']
const rows = ref<Row[]>([])
const total = ref(0)
const stats = ref<{ label: string; value: number }[]>([])
const statusFilter = ref('待处理')
const message = ref('')
const messageOk = ref(true)

function accountQuery() {
  return `account=${encodeURIComponent(session.account)}`
}

async function loadAccounts() {
  if (session.accounts.length) return
  const response = await request(`${CREDENTIAL_ENDPOINT}/accounts`)
  if (response.ok) {
    const payload = await response.json()
    session.setAccounts(payload.items ?? [])
  }
}

async function reload() {
  const params = new URLSearchParams()
  params.set('account', session.account)
  if (statusFilter.value) params.set('status', statusFilter.value)
  const response = await request(`${ENDPOINT}?${params.toString()}`)
  if (!response.ok) {
    message.value = '异常清单读取失败'
    messageOk.value = false
    return
  }
  const payload = await response.json()
  rows.value = payload.items ?? []
  total.value = payload.total ?? 0
  const statsResp = await request(`${ENDPOINT}/stats?${accountQuery()}`)
  if (statsResp.ok) stats.value = (await statsResp.json()).items ?? []
}

async function resolve(row: Row) {
  const note = window.prompt(`复核异常 ${row.异常编号}，填写处理说明：`, '重新推送有效密钥后恢复')
  if (note === null) return
  const response = await request(`${ENDPOINT}/${row.id}/resolve?${accountQuery()}`, {
    method: 'POST',
    body: JSON.stringify({ values: { 处理说明: note } }),
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    message.value = payload.detail ?? '异常闭环被拒绝'
    messageOk.value = false
    return
  }
  message.value = payload.message ?? '异常已闭环'
  messageOk.value = true
  await reload()
}

onMounted(async () => {
  await loadAccounts()
  await reload()
})
</script>

<style scoped>
.row-pending {
  background: #fffbeb;
}
.muted-text {
  color: var(--muted);
  font-size: 12px;
}
</style>
