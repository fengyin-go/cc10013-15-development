import { defineStore } from 'pinia'

type AccountInfo = {
  账号: string
  说明: string
  可维护凭证: string[]
  只读共享凭证: string[]
  授权端点: string[]
}

export const useSessionStore = defineStore('session', {
  state: () => ({
    operator: '值班管理员',
    shiftLabel: '白班 08:00-20:00',
    scope: 'API数据聚合采集中心',
    // 凭据生效数据集按调用账号做归属范围隔离，默认以采集运营账号进入。
    account: 'acct-operator',
    accounts: [] as AccountInfo[],
  }),
  getters: {
    canOperate: (state) => state.operator.length > 0,
    accountInfo(state): AccountInfo | undefined {
      return state.accounts.find((item) => item.账号 === state.account)
    },
  },
  actions: {
    setShift(label: string) {
      this.shiftLabel = label
    },
    setAccount(account: string) {
      this.account = account
    },
    setAccounts(accounts: AccountInfo[]) {
      this.accounts = accounts
    },
  },
})
