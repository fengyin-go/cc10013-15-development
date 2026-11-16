"""凭据生效数据集业务规则。

这里收口轮换窗口、新旧指纹、授权范围与冲突优先级的全部判断，路由层只做参数转发。
核心约束：
- 凭据记录与引用端点一起保存新旧指纹和有效窗口；
- 只有被授权端点（经由调用账号的归属范围）能读取对应凭据；
- 同一凭证编号在轮换窗口内新旧凭据并存形成冲突，由优先级规则裁决，一次请求只绑定一把密钥；
- 认证失败的端点落到端点异常待处理清单，凭据抽屉同步显示失败窗口。
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from app.store import store

MODULE = "credential"
EXCEPTION_MODULE = "endpoint_exception"
LOG_MODULE = "credential_access_log"
RULE_MODULE = "rule_config"

# 账号 -> 归属范围：可改动的凭证编号、可读取的端点编号、只读共享的凭证编号。
# 超出归属范围的账号只能看到自己被授权的端点，读不到他人凭据，也不能越权共享。
ACCOUNT_SCOPES: dict[str, dict[str, Any]] = {
    "acct-operator": {
        "label": "采集运营账号",
        "owner_credentials": ["AUTH-0001", "AUTH-0002", "AUTH-0003"],
        "readonly_credentials": [],
        "endpoints": ["EP-PRIMARY-01", "EP-STANDBY-01", "EP-PRIMARY-02", "EP-STANDBY-02", "EP-PRIMARY-03"],
    },
    "acct-reader": {
        "label": "只读共享账号",
        "owner_credentials": [],
        "readonly_credentials": ["AUTH-0001"],
        "endpoints": ["EP-PRIMARY-01", "EP-STANDBY-01"],
    },
    "acct-outsider": {
        "label": "越权测试账号",
        "owner_credentials": [],
        "readonly_credentials": [],
        "endpoints": ["EP-OTHER-99"],
    },
}

# 轮换窗口内新旧凭据并存时的优先级规则。
# new-first：新指纹优先（默认）；old-first：旧指纹优先（验证“取舍会影响终态”）。
PRIORITY_RULES = ("new-first", "old-first")

WINDOW_FIELDS = [
    "凭证编号", "引用端点", "端点角色", "旧指纹", "新指纹", "生效开始", "生效结束",
    "轮换状态", "授权账号", "归属范围", "优先级规则", "冲突标记", "失败窗口",
]


def now_text() -> str:
    return datetime.now().replace(microsecond=0).isoformat()


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def fingerprint_of(secret: str) -> str:
    """凭据密钥不直接暴露在列表里，列表与取用日志只记录指纹。"""
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


class CredentialService:
    # ---------- 账号与授权 ----------

    def list_accounts(self) -> list[dict[str, Any]]:
        return [
            {
                "账号": account,
                "说明": scope["label"],
                "可维护凭证": list(scope["owner_credentials"]),
                "只读共享凭证": list(scope["readonly_credentials"]),
                "授权端点": list(scope["endpoints"]),
            }
            for account, scope in ACCOUNT_SCOPES.items()
        ]

    def _scope(self, account: str) -> dict[str, Any] | None:
        return ACCOUNT_SCOPES.get(account)

    def _can_view_credential(self, scope: dict[str, Any], credential_no: str) -> bool:
        return credential_no in scope["owner_credentials"] or credential_no in scope["readonly_credentials"]

    def _can_manage_credential(self, scope: dict[str, Any], credential_no: str) -> bool:
        return credential_no in scope["owner_credentials"]

    def _endpoint_authorized(self, scope: dict[str, Any], endpoint_no: str) -> bool:
        return endpoint_no in scope["endpoints"]

    def get_priority_rule(self) -> str:
        rows = store.rows(RULE_MODULE)
        for row in rows:
            if row.get("规则键") == "rotation_priority":
                return str(row.get("规则值"))
        return "new-first"

    def set_priority_rule(self, rule: str) -> tuple[dict[str, Any] | None, str]:
        if rule not in PRIORITY_RULES:
            return None, f"优先级规则「{rule}」不被支持，仅支持：{'、'.join(PRIORITY_RULES)}"
        rows = store.rows(RULE_MODULE)
        for row in rows:
            if row.get("规则键") == "rotation_priority":
                row["规则值"] = rule
                row["更新时间"] = now_text()
                return row, "轮换冲突优先级规则已更新"
        entry = {"id": len(rows) + 1, "规则键": "rotation_priority", "规则值": rule, "更新时间": now_text()}
        rows.append(entry)
        return entry, "轮换冲突优先级规则已建立"

    # ---------- 窗口判定 ----------

    def _window_state(self, row: dict[str, Any], at: datetime) -> str:
        start = parse_time(str(row.get("生效开始")))
        end = parse_time(str(row.get("生效结束")))
        if start and at < start:
            return "未生效"
        if end and at > end:
            return "已过期"
        return "生效中"

    def _decorate(self, row: dict[str, Any], at: datetime | None = None) -> dict[str, Any]:
        """补充运行期口径：当前窗口状态、是否处于轮换冲突、失败窗口标记。"""
        moment = at or datetime.now()
        state = self._window_state(row, moment)
        credential_no = str(row.get("凭证编号"))
        endpoint_no = str(row.get("引用端点"))
        conflict = False
        if state == "生效中":
            for other in store.rows(MODULE):
                if other is row:
                    continue
                if other.get("凭证编号") != credential_no or other.get("引用端点") != endpoint_no:
                    continue
                if self._window_state(other, moment) == "生效中":
                    conflict = True
                    break
        result = dict(row)
        result["当前窗口状态"] = state
        result["冲突标记"] = conflict
        result["失败窗口"] = bool(row.get("失败窗口"))
        return result

    # ---------- 列表与明细 ----------

    def list_windows(
        self,
        *,
        account: str,
        keyword: str | None = None,
        endpoint: str | None = None,
        conflict_only: bool = False,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        scope = self._scope(account)
        if scope is None:
            return [], 0
        rows = [row for row in store.rows(MODULE) if self._can_view_credential(scope, str(row.get("凭证编号")))]
        if keyword:
            rows = [row for row in rows if keyword in str(row.get("凭证编号", ""))]
        if endpoint:
            rows = [row for row in rows if endpoint in str(row.get("引用端点", ""))]
        decorated = [self._decorate(row) for row in rows]
        if conflict_only:
            decorated = [row for row in decorated if row["冲突标记"]]
        total = len(decorated)
        start = max(page - 1, 0) * size
        return decorated[start:start + size], total

    def get_window(self, entry_id: int, *, account: str) -> tuple[dict[str, Any] | None, str, int]:
        scope = self._scope(account)
        if scope is None:
            return None, f"账号 {account} 不在凭据生效数据集的授权名册内", 403
        row = store.find(MODULE, entry_id)
        if row is None:
            return None, f"凭据窗口记录 {entry_id} 不存在", 404
        if not self._can_view_credential(scope, str(row.get("凭证编号"))):
            return None, "该凭据不在当前账号的归属范围内，禁止读取", 403
        return self._decorate(row), "ok", 200

    def stats(self, *, account: str) -> list[dict[str, Any]]:
        scope = self._scope(account)
        if scope is None:
            return []
        rows = [self._decorate(row) for row in store.rows(MODULE)
                if self._can_view_credential(scope, str(row.get("凭证编号")))]
        active = [row for row in rows if row["当前窗口状态"] == "生效中"]
        return [
            {"label": "凭据窗口记录", "value": len(rows)},
            {"label": "生效中窗口", "value": len(active)},
            {"label": "轮换冲突窗口", "value": sum(1 for row in active if row["冲突标记"])},
            {"label": "失败窗口", "value": sum(1 for row in rows if row["失败窗口"])},
        ]

    # ---------- 登记与轮换 ----------

    def create_window(self, account: str, values: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str] | str]:
        scope = self._scope(account)
        if scope is None:
            return None, f"账号 {account} 无权登记凭据窗口"
        required = ["凭证编号", "引用端点", "端点角色", "生效开始", "生效结束", "凭证密钥"]
        missing = [field for field in required if not str(values.get(field) or "").strip()]
        if missing:
            return None, missing
        credential_no = str(values["凭证编号"]).strip()
        endpoint_no = str(values["引用端点"]).strip()
        if not self._can_manage_credential(scope, credential_no):
            return None, "超出归属范围：当前账号只能维护自己名下的凭证编号"
        if not self._endpoint_authorized(scope, endpoint_no):
            return None, f"端点 {endpoint_no} 不在当前账号授权范围内，禁止绑定凭据"
        start = parse_time(str(values["生效开始"]))
        end = parse_time(str(values["生效结束"]))
        if start is None or end is None:
            return None, "生效开始/结束必须是 ISO 时间，例如 2026-11-16T08:00:00"
        if end <= start:
            return None, "生效结束必须晚于生效开始"
        rows = store.rows(MODULE)
        entry = {
            "id": max((int(row.get("id", 0)) for row in rows), default=0) + 1,
            "凭证编号": credential_no,
            "引用端点": endpoint_no,
            "端点角色": str(values["端点角色"]).strip(),
            "旧指纹": str(values.get("旧指纹") or "").strip(),
            "新指纹": fingerprint_of(str(values["凭证密钥"])),
            "生效开始": start.isoformat(),
            "生效结束": end.isoformat(),
            "轮换状态": "窗口生效",
            "授权账号": account,
            "归属范围": "、".join(scope["endpoints"]),
            "优先级规则": self.get_priority_rule(),
            "失败窗口": False,
            "pending": True,
            "abnormal": False,
            "status": "已生效",
        }
        rows.append(entry)
        return self._decorate(entry), []

    def rotate(self, entry_id: int, account: str, values: dict[str, Any]) -> tuple[dict[str, Any] | None, str, int]:
        """轮换：旧窗口截断到重叠结束点，新窗口带着旧指纹登记，形成并存的轮换窗口。"""
        scope = self._scope(account)
        if scope is None:
            return None, f"账号 {account} 无权执行凭据轮换", 403
        old_row = store.find(MODULE, entry_id)
        if old_row is None:
            return None, f"凭据窗口记录 {entry_id} 不存在", 404
        credential_no = str(old_row.get("凭证编号"))
        if not self._can_manage_credential(scope, credential_no):
            return None, "超出归属范围：不能改动他人凭据", 403
        new_secret = str(values.get("凭证密钥") or "").strip()
        if not new_secret:
            return None, "轮换必须提交新的凭证密钥", 400
        overlap_end = parse_time(str(values.get("重叠结束") or ""))
        new_start = parse_time(str(values.get("新窗口开始") or ""))
        if overlap_end is None or new_start is None:
            return None, "轮换需要 重叠结束 与 新窗口开始 两个 ISO 时间", 400
        old_start = parse_time(str(old_row.get("生效开始")))
        old_end = parse_time(str(old_row.get("生效结束")))
        if old_start is None or old_end is None:
            return None, "旧窗口时间格式异常，无法轮换", 400
        if not (old_start <= new_start < overlap_end <= old_end):
            return None, "轮换窗口必须满足：旧开始 ≤ 新开始 < 重叠结束 ≤ 旧结束", 400

        new_end_text = str(values.get("新窗口结束") or "").strip() or old_end.isoformat()
        new_end = parse_time(new_end_text)
        if new_end is None or new_end <= overlap_end:
            return None, "新窗口结束必须晚于重叠结束时间", 400
        old_fingerprint = str(old_row.get("新指纹") or "")
        new_fingerprint = fingerprint_of(new_secret)
        # 同一凭证编号的主备端点使用同一把密钥：同编号其它窗口沿用相同新指纹。
        rows = store.rows(MODULE)
        # 1) 旧窗口截断为轮换窗口，保留旧指纹，状态进入“轮换中”。
        old_row["生效结束"] = overlap_end.isoformat()
        old_row["轮换状态"] = "轮换中-旧指纹"
        old_row["旧指纹"] = old_fingerprint
        old_row["优先级规则"] = self.get_priority_rule()
        # 2) 登记新窗口：与引用端点一起保存新旧指纹和有效窗口。
        new_entry = {
            "id": max((int(row.get("id", 0)) for row in rows), default=0) + 1,
            "凭证编号": credential_no,
            "引用端点": str(old_row.get("引用端点")),
            "端点角色": str(old_row.get("端点角色")),
            "旧指纹": old_fingerprint,
            "新指纹": new_fingerprint,
            "生效开始": new_start.isoformat(),
            "生效结束": new_end.isoformat(),
            "轮换状态": "轮换中-新指纹",
            "授权账号": account,
            "归属范围": old_row.get("归属范围"),
            "优先级规则": self.get_priority_rule(),
            "失败窗口": False,
            "pending": True,
            "abnormal": False,
            "status": "已生效",
        }
        rows.append(new_entry)
        # 3) 同凭证编号的备用端点同步生成同指纹的新旧窗口（主备用同一把有效密钥）。
        for sibling in rows:
            if sibling is old_row or sibling is new_entry:
                continue
            if sibling.get("凭证编号") != credential_no:
                continue
            sibling_old_end = parse_time(str(sibling.get("生效结束")))
            if sibling_old_end and sibling_old_end > overlap_end and sibling.get("轮换状态") == "窗口生效":
                sibling_fp = str(sibling.get("新指纹") or "")
                sibling["旧指纹"] = sibling_fp
                sibling["新指纹"] = new_fingerprint
                sibling["生效结束"] = overlap_end.isoformat()
                sibling["轮换状态"] = "轮换中-旧指纹"
                sibling["优先级规则"] = self.get_priority_rule()
                rows.append({
                    "id": max((int(r.get("id", 0)) for r in rows), default=0) + 1,
                    "凭证编号": credential_no,
                    "引用端点": str(sibling.get("引用端点")),
                    "端点角色": str(sibling.get("端点角色")),
                    "旧指纹": sibling_fp,
                    "新指纹": new_fingerprint,
                    "生效开始": new_start.isoformat(),
                    "生效结束": old_end.isoformat(),
                    "轮换状态": "轮换中-新指纹",
                    "授权账号": account,
                    "归属范围": sibling.get("归属范围"),
                    "优先级规则": self.get_priority_rule(),
                    "失败窗口": False,
                    "pending": True,
                    "abnormal": False,
                    "status": "已生效",
                })
        return self._decorate(new_entry), f"凭证 {credential_no} 已轮换，新旧窗口在 {new_start.isoformat()} 至 {overlap_end.isoformat()} 并存", 200

    def close_window(self, entry_id: int, account: str) -> tuple[dict[str, Any] | None, str, int]:
        scope = self._scope(account)
        if scope is None:
            return None, f"账号 {account} 无权关闭凭据窗口", 403
        row = store.find(MODULE, entry_id)
        if row is None:
            return None, f"凭据窗口记录 {entry_id} 不存在", 404
        if not self._can_manage_credential(scope, str(row.get("凭证编号"))):
            return None, "超出归属范围：不能改动他人凭据", 403
        row["轮换状态"] = "窗口关闭"
        row["生效结束"] = now_text()
        row["pending"] = False
        return self._decorate(row), "凭据窗口已关闭", 200

    # ---------- 凭据取用（一次请求只绑定一把有效密钥） ----------

    def fetch_credential(
        self,
        account: str,
        credential_no: str,
        endpoint_no: str,
        *,
        at_text: str | None = None,
    ) -> tuple[dict[str, Any] | None, str, int]:
        scope = self._scope(account)
        if scope is None:
            self._write_log(account, credential_no, endpoint_no, None, "拒绝", "账号不在授权名册", at_text)
            return None, f"账号 {account} 不在授权名册内", 403
        if not self._can_view_credential(scope, credential_no):
            self._write_log(account, credential_no, endpoint_no, None, "拒绝", "超出归属范围读取凭据", at_text)
            self._raise_exception(credential_no, endpoint_no, account, "超出归属范围的凭据读取请求已拒绝", at_text)
            return None, "超出归属范围：当前账号无权读取该凭据", 403
        if not self._endpoint_authorized(scope, endpoint_no):
            self._write_log(account, credential_no, endpoint_no, None, "拒绝", "端点未授权", at_text)
            self._raise_exception(credential_no, endpoint_no, account, f"端点 {endpoint_no} 未获该凭据授权，请求已拒绝", at_text)
            return None, f"端点 {endpoint_no} 不在授权窗口内，禁止取用凭据", 403

        moment = parse_time(at_text) or datetime.now()
        candidates = [
            row for row in store.rows(MODULE)
            if row.get("凭证编号") == credential_no
            and row.get("引用端点") == endpoint_no
            and self._window_state(row, moment) == "生效中"
        ]
        if not candidates:
            self._write_log(account, credential_no, endpoint_no, None, "无可用凭据", "当前时间没有生效窗口", at_text)
            self._raise_exception(credential_no, endpoint_no, account, "采集端找不到可用凭据：无生效窗口", at_text)
            return None, "当前窗口没有可用凭据", 409

        rule = self.get_priority_rule()
        # 冲突裁决：同编号同端点新旧凭据并存时，优先级规则决定本次请求绑定哪一把。
        chosen = self._resolve_conflict(candidates, rule)
        bound_fingerprint = str(chosen.get("新指纹"))
        conflict = len(candidates) > 1
        self._write_log(
            account, credential_no, endpoint_no, bound_fingerprint,
            "已取用", f"优先级规则 {rule} 裁决" if conflict else "单一生效窗口", at_text,
        )
        return (
            {
                "凭证编号": credential_no,
                "引用端点": endpoint_no,
                "绑定指纹": bound_fingerprint,
                "窗口记录": chosen["id"],
                "生效开始": chosen.get("生效开始"),
                "生效结束": chosen.get("生效结束"),
                "轮换状态": chosen.get("轮换状态"),
                "冲突并存": conflict,
                "优先级规则": rule,
                "取用时间": moment.isoformat(),
            },
            "ok",
            200,
        )

    def _resolve_conflict(self, candidates: list[dict[str, Any]], rule: str) -> dict[str, Any]:
        if len(candidates) == 1:
            return candidates[0]
        ordered = sorted(candidates, key=lambda row: str(row.get("生效开始")))
        return ordered[-1] if rule == "new-first" else ordered[0]

    # ---------- 认证结果回报 ----------

    def report_auth_result(
        self,
        account: str,
        log_id: int,
        values: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str, int]:
        scope = self._scope(account)
        if scope is None:
            return None, f"账号 {account} 无权回报认证结果", 403
        log_row = store.find(LOG_MODULE, log_id)
        if log_row is None:
            return None, f"取用日志 {log_id} 不存在", 404
        credential_no = str(log_row.get("凭证编号"))
        if not self._can_view_credential(scope, credential_no):
            return None, "超出归属范围：不能回报他人凭据的认证结果", 403
        result = str(values.get("认证结果") or "").strip()
        if result not in ("成功", "失败"):
            return None, "认证结果只接受 成功 或 失败", 400
        log_row["认证结果"] = result
        log_row["回报时间"] = now_text()
        log_row["备注"] = str(values.get("备注") or log_row.get("备注") or "")
        endpoint_no = str(log_row.get("引用端点"))
        bound_fingerprint = log_row.get("绑定指纹")
        if result == "失败":
            # 失败端点落到端点异常待处理清单；凭据抽屉同步显示失败窗口。
            self._raise_exception(
                credential_no, endpoint_no, account,
                f"认证失败：指纹 {bound_fingerprint} 未被采集端接受",
                None,
                fingerprint=str(bound_fingerprint or ""),
                log_id=log_id,
            )
            for row in store.rows(MODULE):
                if row.get("凭证编号") == credential_no and row.get("新指纹") == bound_fingerprint:
                    row["失败窗口"] = True
                    row["abnormal"] = True
                    row["轮换状态"] = f"{row.get('轮换状态')}-认证失败"
        else:
            log_row["处理状态"] = "已确认成功"
        return log_row, f"认证结果「{result}」已记录", 200

    # ---------- 取用日志与异常清单 ----------

    def list_logs(
        self,
        account: str,
        *,
        endpoint: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        scope = self._scope(account)
        if scope is None:
            return [], 0
        rows = []
        for row in store.rows(LOG_MODULE):
            if not self._can_view_credential(scope, str(row.get("凭证编号"))):
                continue
            if endpoint and endpoint not in str(row.get("引用端点")):
                continue
            rows.append(dict(row))
        total = len(rows)
        start = max(page - 1, 0) * size
        return rows[start:start + size], total

    def list_exceptions(
        self,
        account: str,
        *,
        status: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        scope = self._scope(account)
        if scope is None:
            return [], 0
        rows = []
        for row in store.rows(EXCEPTION_MODULE):
            # 工作台只读取同一窗口：越权账号看不到别人凭据的异常。
            if not self._can_view_credential(scope, str(row.get("凭证编号"))):
                continue
            if status and row.get("处理状态") != status:
                continue
            rows.append(dict(row))
        total = len(rows)
        start = max(page - 1, 0) * size
        return rows[start:start + size], total

    def resolve_exception(self, account: str, exception_id: int, values: dict[str, Any]) -> tuple[dict[str, Any] | None, str, int]:
        scope = self._scope(account)
        if scope is None:
            return None, f"账号 {account} 无权处理异常清单", 403
        row = store.find(EXCEPTION_MODULE, exception_id)
        if row is None:
            return None, f"异常记录 {exception_id} 不存在", 404
        if not self._can_manage_credential(scope, str(row.get("凭证编号"))):
            return None, "超出归属范围：只读账号不能处理他人凭据的异常", 403
        row["处理状态"] = "已处理"
        row["处理说明"] = str(values.get("处理说明") or "运营复核后关闭")
        row["处理时间"] = now_text()
        row["pending"] = False
        return row, "端点异常已闭环", 200

    def share_readonly(self, account: str, values: dict[str, Any]) -> tuple[dict[str, Any] | None, str, int]:
        """只读共享只能由凭证属主发起；属主不能把自己没有的凭据共享出去。"""
        scope = self._scope(account)
        if scope is None:
            return None, f"账号 {account} 无权共享凭据窗口", 403
        credential_no = str(values.get("凭证编号") or "").strip()
        target_account = str(values.get("目标账号") or "").strip()
        if not credential_no or not target_account:
            return None, "共享需要提供 凭证编号 与 目标账号", 400
        if not self._can_manage_credential(scope, credential_no):
            return None, "越权共享被拒绝：只能共享自己归属范围内的凭据", 403
        target = self._scope(target_account)
        if target is None:
            return None, f"目标账号 {target_account} 不在授权名册内", 404
        if credential_no not in target["readonly_credentials"]:
            target["readonly_credentials"].append(credential_no)
        return {"凭证编号": credential_no, "目标账号": target_account, "共享方式": "只读窗口"}, "只读窗口共享已登记", 200

    # ---------- 内部写库 ----------

    def _write_log(
        self,
        account: str,
        credential_no: str,
        endpoint_no: str,
        fingerprint: str | None,
        result: str,
        remark: str,
        at_text: str | None,
    ) -> dict[str, Any]:
        rows = store.rows(LOG_MODULE)
        entry = {
            "id": max((int(row.get("id", 0)) for row in rows), default=0) + 1,
            "凭证编号": credential_no,
            "引用端点": endpoint_no,
            "调用账号": account,
            "绑定指纹": fingerprint or "",
            "取用结果": result,
            "认证结果": "待回报",
            "处理状态": "待处理" if result != "已取用" else "待认证回报",
            "备注": remark,
            "取用时间": (parse_time(at_text) or datetime.now()).isoformat(),
            "pending": result != "已取用",
            "abnormal": result != "已取用",
        }
        rows.append(entry)
        return entry

    def _raise_exception(
        self,
        credential_no: str,
        endpoint_no: str,
        account: str,
        reason: str,
        at_text: str | None,
        *,
        fingerprint: str = "",
        log_id: int | None = None,
    ) -> dict[str, Any]:
        rows = store.rows(EXCEPTION_MODULE)
        entry = {
            "id": max((int(row.get("id", 0)) for row in rows), default=0) + 1,
            "异常编号": f"EXC-{len(rows) + 1:04d}",
            "凭证编号": credential_no,
            "引用端点": endpoint_no,
            "关联指纹": fingerprint,
            "关联日志": log_id,
            "异常原因": reason,
            "上报账号": account,
            "处理状态": "待处理",
            "发生时间": (parse_time(at_text) or datetime.now()).isoformat(),
            "pending": True,
            "abnormal": True,
        }
        rows.append(entry)
        return entry
