<template>
  <section class="page" data-module="credential">
    <header class="page-head">
      <div>
        <h2>凭据生效数据集</h2>
        <p class="page-desc">
          按凭证编号管理新旧指纹与重叠有效窗口；只有被授权端点能读取对应凭据，轮换冲突由优先级规则裁决。
        </p>
      </div>
      <div class="page-actions">
        <label class="filter-item">
          <span>调用账号（归属范围）</span>
          <select v-model="session.account" @change="reloadAll">
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

    <div class="rule-bar">
      <span>轮换冲突优先级规则：<strong>{{ priorityRule }}</strong></span>
      <button
        v-for="rule in priorityRules"
        :key="rule"
        class="btn"
        :class="{ primary: rule === priorityRule }"
        type="button"
        @click="switchRule(rule)"
      >
        {{ rule === 'new-first' ? '新指纹优先' : '旧指纹优先' }}
      </button>
    </div>

    <form class="filter-bar" @submit.prevent="reload">
      <label class="filter-item">
        <span>凭证编号</span>
        <input v-model="filters.keyword" placeholder="按凭证编号检索" />
      </label>
      <label class="filter-item">
        <span>引用端点</span>
        <input v-model="filters.endpoint" placeholder="按引用端点检索" />
      </label>
      <label class="filter-item">
        <span>只看冲突窗口</span>
        <input v-model="filters.conflict_only" type="checkbox" />
      </label>
      <button class="btn" type="submit">查询</button>
      <button class="btn ghost" type="button" @click="resetFilters">重置条件</button>
    </form>

    <table class="data-table">
      <thead>
        <tr>
          <th v-for="column in columns" :key="column">{{ column }}</th>
          <th>当前窗口状态</th>
          <th>可执行动作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="String(row.id)" :class="{ 'row-conflict': row.冲突标记, 'row-failed': row.失败窗口 }">
          <td v-for="column in columns" :key="column">{{ row[column] ?? '—' }}</td>
          <td>
            <span class="state-tag" :class="stateClass(String(row.当前窗口状态 ?? ''))">{{ row.当前窗口状态 }}</span>
            <span v-if="row.冲突标记" class="state-tag conflict">轮换冲突</span>
            <span v-if="row.失败窗口" class="state-tag failed">失败窗口</span>
          </td>
          <td class="row-actions">
            <button class="link" type="button" @click="openRotate(row)">轮换密钥</button>
            <button class="link" type="button" @click="closeWindow(row)">关闭窗口</button>
          </td>
        </tr>
        <tr v-if="!rows.length">
          <td :colspan="columns.length + 2" class="empty-state">
            当前账号归属范围内没有凭据窗口（超出归属范围的账号只能查看授权端点，读不到他人凭据）
          </td>
        </tr>
      </tbody>
    </table>

    <div class="panel-grid">
      <article class="side-panel">
        <h3>登记凭据窗口</h3>
        <p class="panel-hint">凭据密钥仅用于计算指纹，列表与日志只保存指纹，不回显密钥。</p>
        <form class="stack-form" @submit.prevent="createWindow">
          <label v-for="field in createFields" :key="field.key" class="filter-item">
            <span>{{ field.label }}</span>
            <input v-model="createForm[field.key]" :placeholder="field.placeholder" />
          </label>
          <button class="btn primary" type="submit">登记窗口</button>
        </form>
      </article>

      <article class="side-panel">
        <h3>采集端取用模拟（一次请求绑定一把有效密钥）</h3>
        <form class="stack-form" @submit.prevent="fetchCredential">
          <label class="filter-item">
            <span>凭证编号</span>
            <input v-model="fetchForm.凭证编号" placeholder="例如 AUTH-0001" />
          </label>
          <label class="filter-item">
            <span>引用端点</span>
            <input v-model="fetchForm.引用端点" placeholder="例如 EP-PRIMARY-01" />
          </label>
          <label class="filter-item">
            <span>取用时间（可空，默认当前时间）</span>
            <input v-model="fetchForm.取用时间" placeholder="2026-11-16T10:00:00" />
          </label>
          <button class="btn primary" type="submit">取用凭据</button>
        </form>
        <div v-if="fetchResult" class="result-box">
          <p>绑定指纹：<strong>{{ fetchResult.绑定指纹 }}</strong></p>
          <p>窗口记录：#{{ fetchResult.窗口记录 }} · {{ fetchResult.轮换状态 }}</p>
          <p v-if="fetchResult.冲突并存" class="error-text">
            新旧窗口并存，已按「{{ fetchResult.优先级规则 }}」裁决本次请求
          </p>
        </div>
      </article>

      <article class="side-panel">
        <h3>只读窗口共享</h3>
        <p class="panel-hint">只有凭证属主能发起共享；越权共享会被后端拒绝。</p>
        <form class="stack-form" @submit.prevent="shareReadonly">
          <label class="filter-item">
            <span>凭证编号</span>
            <input v-model="shareForm.凭证编号" placeholder="只能共享自己名下凭证" />
          </label>
          <label class="filter-item">
            <span>目标账号</span>
            <select v-model="shareForm.目标账号">
              <option v-for="item in session.accounts.filter((a) => a.账号 !== session.account)" :key="item.账号" :value="item.账号">
                {{ item.账号 }} · {{ item.说明 }}
              </option>
            </select>
          </label>
          <button class="btn primary" type="submit">共享只读窗口</button>
        </form>
      </article>
    </div>

    <h3 class="section-title">取用日志（主备端点复测应出现相同指纹）</h3>
    <table class="data-table">
      <thead>
        <tr>
          <th v-for="column in logColumns" :key="column">{{ column }}</th>
          <th>认证回报</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in accessLogs" :key="String(row.id)">
          <td v-for="column in logColumns" :key="column">{{ row[column] ?? '—' }}</td>
          <td class="row-actions">
            <button class="link" type="button" @click="reportAuth(row, '成功')">回报成功</button>
            <button class="link" type="button" @click="reportAuth(row, '失败')">回报失败</button>
          </td>
        </tr>
        <tr v-if="!accessLogs.length">
          <td :colspan="logColumns.length + 1" class="empty-state">当前账号暂无取用日志</td>
        </tr>
      </tbody>
    </table>

    <footer class="page-foot">
      <span>共 {{ total }} 条凭据窗口记录</span>
      <span v-if="message" :class="messageOk ? '' : 'error-text'">{{ message }}</span>
    </footer>
  </section>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'

import { request } from '@/api/client'
import { useSessionStore } from '@/stores/session'

type Row = Record<string, string | number | boolean | null>
type FetchResult = {
  绑定指纹: string
  窗口记录: number
  轮换状态: string
  冲突并存: boolean
  优先级规则: string
}

const ENDPOINT = '/api/credential'
const session = useSessionStore()

const columns = ['凭证编号', '引用端点', '端点角色', '旧指纹', '新指纹', '生效开始', '生效结束', '轮换状态', '归属范围', '失败窗口']
const logColumns = ['凭证编号', '引用端点', '调用账号', '绑定指纹', '取用结果', '认证结果', '处理状态', '取用时间', '备注']
const priorityRules = ['new-first', 'old-first']

const rows = ref<Row[]>([])
const accessLogs = ref<Row[]>([])
const total = ref(0)
const stats = ref<{ label: string; value: number }[]>([])
const priorityRule = ref('new-first')
const message = ref('')
const messageOk = ref(true)
const filters = reactive({ keyword: '', endpoint: '', conflict_only: false })
const fetchResult = ref<FetchResult | null>(null)

const createFields = [
  { key: '凭证编号', label: '凭证编号', placeholder: '例如 AUTH-0004' },
  { key: '引用端点', label: '引用端点', placeholder: '必须在账号授权端点内' },
  { key: '端点角色', label: '端点角色', placeholder: '主端点 / 备用端点' },
  { key: '凭证密钥', label: '凭证密钥', placeholder: '提交后只保存 sha256 指纹' },
  { key: '生效开始', label: '生效开始', placeholder: '2026-11-20T00:00:00' },
  { key: '生效结束', label: '生效结束', placeholder: '2026-12-20T00:00:00' },
]
const createForm = reactive<Record<string, string>>({})
const fetchForm = reactive({ 凭证编号: 'AUTH-0001', 引用端点: 'EP-PRIMARY-01', 取用时间: '' })
const shareForm = reactive({ 凭证编号: '', 目标账号: '' })

function accountQuery() {
  return `account=${encodeURIComponent(session.account)}`
}

function notify(text: string, ok = true) {
  message.value = text
  messageOk.value = ok
}

function stateClass(state: string) {
  return {
    生效中: 'active',
    未生效: 'pending',
    已过期: 'expired',
  }[state] ?? ''
}

async function loadAccounts() {
  const response = await request(`${ENDPOINT}/accounts`)
  if (response.ok) {
    const payload = await response.json()
    session.setAccounts(payload.items ?? [])
  }
}

async function reload() {
  const params = new URLSearchParams()
  params.set('account', session.account)
  if (filters.keyword) params.set('keyword', filters.keyword)
  if (filters.endpoint) params.set('endpoint', filters.endpoint)
  if (filters.conflict_only) params.set('conflict_only', 'true')
  const response = await request(`${ENDPOINT}/windows?${params.toString()}`)
  if (!response.ok) {
    notify('凭据窗口列表读取失败', false)
    return
  }
  const payload = await response.json()
  rows.value = payload.items ?? []
  total.value = payload.total ?? 0
  const [statsResp, ruleResp, logsResp] = await Promise.all([
    request(`${ENDPOINT}/windows/stats?${accountQuery()}`),
    request(`${ENDPOINT}/priority-rule`),
    request(`${ENDPOINT}/access-logs?${accountQuery()}&size=100`),
  ])
  if (statsResp.ok) stats.value = (await statsResp.json()).items ?? []
  if (ruleResp.ok) priorityRule.value = (await ruleResp.json()).规则值
  if (logsResp.ok) accessLogs.value = (await logsResp.json()).items ?? []
}

function reloadAll() {
  void reload()
}

function resetFilters() {
  filters.keyword = ''
  filters.endpoint = ''
  filters.conflict_only = false
  void reload()
}

async function postJson(path: string, values: Record<string, unknown>, successText: string) {
  const response = await request(path, { method: 'POST', body: JSON.stringify({ values }) })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    notify(payload.detail ?? '操作被后端拒绝', false)
    return null
  }
  notify(payload.message ?? successText)
  return payload
}

async function switchRule(rule: string) {
  const payload = await postJson(`${ENDPOINT}/priority-rule?${accountQuery()}`, { 规则值: rule }, '规则已更新')
  if (payload) await reload()
}

async function createWindow() {
  const payload = await postJson(`${ENDPOINT}/windows?${accountQuery()}`, { ...createForm }, '窗口已登记')
  if (payload) {
    Object.keys(createForm).forEach((key) => { createForm[key] = '' })
    await reload()
  }
}

function openRotate(row: Row) {
  const secret = window.prompt(`为凭证 ${row.凭证编号}（${row.引用端点}）输入新的凭证密钥：`)
  if (!secret) return
  const newStart = window.prompt('新窗口开始时间（ISO）', '2026-11-16T12:00:00')
  if (!newStart) return
  const overlapEnd = window.prompt('重叠结束时间（旧窗口截断点，ISO）', String(row.生效结束))
  if (!overlapEnd) return
  const newEnd = window.prompt('新窗口结束时间（ISO）', '2026-12-31T00:00:00') ?? ''
  void postJson(`${ENDPOINT}/windows/${row.id}/rotate?${accountQuery()}`, {
    凭证密钥: secret,
    新窗口开始: newStart,
    重叠结束: overlapEnd,
    新窗口结束: newEnd,
  }, '轮换完成').then((payload) => payload && reload())
}

async function closeWindow(row: Row) {
  const payload = await postJson(`${ENDPOINT}/windows/${row.id}/close?${accountQuery()}`, {}, '窗口已关闭')
  if (payload) await reload()
}

async function fetchCredential() {
  const payload = await postJson(`${ENDPOINT}/fetch?${accountQuery()}`, { ...fetchForm }, '取用成功')
  if (payload) {
    fetchResult.value = payload.entry
    await reload()
  }
}

async function shareReadonly() {
  const payload = await postJson(`${ENDPOINT}/share-readonly?${accountQuery()}`, { ...shareForm }, '共享成功')
  if (payload) await reload()
}

async function reportAuth(row: Row, result: string) {
  const payload = await postJson(
    `${ENDPOINT}/access-logs/${row.id}/auth-result?${accountQuery()}`,
    { 认证结果: result, 备注: result === '失败' ? '工作台回报：采集端认证失败' : '' },
    '认证结果已记录',
  )
  if (payload) await reload()
}

onMounted(async () => {
  await loadAccounts()
  await reload()
})
</script>

<style scoped>
.rule-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  background: #fff;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 12px;
  margin-bottom: 12px;
  font-size: 13px;
}
.panel-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin: 16px 0;
}
.side-panel {
  background: #fff;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px;
}
.side-panel h3 {
  margin: 0 0 8px;
  font-size: 14px;
}
.panel-hint {
  color: var(--muted);
  font-size: 12px;
  margin: 0 0 8px;
}
.stack-form {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.result-box {
  margin-top: 10px;
  padding: 8px;
  border: 1px dashed var(--border);
  border-radius: 6px;
  font-size: 12px;
}
.section-title {
  font-size: 14px;
  margin: 16px 0 8px;
}
.state-tag {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 10px;
  font-size: 12px;
  margin-right: 4px;
  background: #eef2ff;
  color: #3730a3;
}
.state-tag.active { background: #dcfce7; color: #166534; }
.state-tag.pending { background: #fef9c3; color: #854d0e; }
.state-tag.expired { background: #f1f5f9; color: #64748b; }
.state-tag.conflict { background: #ffedd5; color: #9a3412; }
.state-tag.failed { background: #fee2e2; color: #b42318; }
.row-conflict { background: #fffaf0; }
.row-failed { background: #fef2f2; }
</style>
