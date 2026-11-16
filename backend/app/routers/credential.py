"""凭据生效数据集接口。

覆盖凭据窗口登记、轮换、取用、认证回报、取用日志与只读共享；
所有授权与冲突判断都在 services 层，路由层只转发参数并翻译状态码。
调用账号统一通过查询参数 account 传递（演示用轻量归属范围模型）。
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.schemas import ActionResult, EntryPayload, PageResult
from app.services.credential import PRIORITY_RULES, CredentialService

router = APIRouter(prefix="/api/credential", tags=["凭据生效数据集"])

service = CredentialService()

LIST_FIELDS = [
    "凭证编号", "引用端点", "端点角色", "旧指纹", "新指纹", "生效开始", "生效结束",
    "轮换状态", "授权账号", "归属范围", "优先级规则", "冲突标记", "失败窗口",
]


def _fail(status_code: int, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail=message)


@router.get("/accounts")
def list_accounts() -> dict[str, Any]:
    """授权名册：列出每个账号可维护/只读的凭证与授权端点。"""
    return {"items": service.list_accounts()}


@router.get("/priority-rule")
def get_priority_rule() -> dict[str, Any]:
    return {"规则键": "rotation_priority", "规则值": service.get_priority_rule(), "可选值": list(PRIORITY_RULES)}


@router.post("/priority-rule", response_model=ActionResult)
def set_priority_rule(payload: EntryPayload) -> ActionResult:
    rule = str(payload.values.get("规则值") or "").strip()
    entry, message = service.set_priority_rule(rule)
    if entry is None:
        raise _fail(400, message)
    return ActionResult(ok=True, message=message, entry=entry)


@router.get("/windows", response_model=PageResult[dict])
def list_windows(
    account: str = Query(description="调用账号，按归属范围过滤"),
    keyword: str | None = Query(default=None, description="按凭证编号检索"),
    endpoint: str | None = Query(default=None, description="按引用端点检索"),
    conflict_only: bool = Query(default=False, description="只看轮换冲突窗口"),
    page: int = 1,
    size: int = 20,
) -> PageResult[dict]:
    """凭据抽屉：列表只返回当前账号归属范围内的窗口，密钥不落列表，仅显示指纹。"""
    if size > 200:
        raise _fail(400, "每页最多 200 条，请缩小分页范围")
    items, total = service.list_windows(
        account=account, keyword=keyword, endpoint=endpoint,
        conflict_only=conflict_only, page=page, size=size,
    )
    return PageResult(items=items, total=total, page=page, size=size)


@router.get("/windows/stats")
def window_stats(account: str = Query(description="调用账号")) -> dict[str, Any]:
    return {"items": service.stats(account=account)}


@router.get("/windows/{entry_id}")
def get_window(entry_id: int, account: str = Query(description="调用账号")) -> dict[str, Any]:
    entry, message, status_code = service.get_window(entry_id, account=account)
    if entry is None:
        raise _fail(status_code, message)
    return entry


@router.post("/windows", response_model=ActionResult)
def create_window(payload: EntryPayload, account: str = Query(description="调用账号")) -> ActionResult:
    entry, missing_or_message = service.create_window(account, payload.values)
    if entry is None:
        if isinstance(missing_or_message, list):
            return ActionResult(ok=False, message=f"缺少必填字段：{'、'.join(missing_or_message)}")
        raise _fail(403, str(missing_or_message))
    return ActionResult(ok=True, message="凭据生效窗口已登记", entry=entry)


@router.post("/windows/{entry_id}/rotate", response_model=ActionResult)
def rotate_window(entry_id: int, payload: EntryPayload, account: str = Query(description="调用账号")) -> ActionResult:
    """轮换密钥：新旧指纹与重叠有效窗口一起保存，同凭证编号主备端点同步同指纹窗口。"""
    entry, message, status_code = service.rotate(entry_id, account, payload.values)
    if entry is None:
        raise _fail(status_code, message)
    return ActionResult(ok=True, message=message, entry=entry)


@router.post("/windows/{entry_id}/close", response_model=ActionResult)
def close_window(entry_id: int, payload: EntryPayload, account: str = Query(description="调用账号")) -> ActionResult:
    entry, message, status_code = service.close_window(entry_id, account)
    if entry is None:
        raise _fail(status_code, message)
    return ActionResult(ok=True, message=message, entry=entry)


@router.post("/fetch", response_model=ActionResult)
def fetch_credential(payload: EntryPayload, account: str = Query(description="调用账号")) -> ActionResult:
    """采集端取用凭据：授权端点在有效窗口内取得密钥指纹，一次请求只绑定一把。"""
    credential_no = str(payload.values.get("凭证编号") or "").strip()
    endpoint_no = str(payload.values.get("引用端点") or "").strip()
    at_text = payload.values.get("取用时间")
    if not credential_no or not endpoint_no:
        return ActionResult(ok=False, message="取用凭据必须提供 凭证编号 与 引用端点")
    entry, message, status_code = service.fetch_credential(
        account, credential_no, endpoint_no, at_text=str(at_text) if at_text else None,
    )
    if entry is None:
        raise _fail(status_code, message)
    return ActionResult(ok=True, message="已绑定当前请求的有效密钥", entry=entry)


@router.post("/access-logs/{log_id}/auth-result", response_model=ActionResult)
def report_auth_result(log_id: int, payload: EntryPayload, account: str = Query(description="调用账号")) -> ActionResult:
    """认证结果回报：失败时端点进入异常待处理清单，凭据抽屉同步标记失败窗口。"""
    entry, message, status_code = service.report_auth_result(account, log_id, payload.values)
    if entry is None:
        raise _fail(status_code, message)
    return ActionResult(ok=True, message=message, entry=entry)


@router.get("/access-logs", response_model=PageResult[dict])
def list_access_logs(
    account: str = Query(description="调用账号"),
    endpoint: str | None = Query(default=None, description="按引用端点检索"),
    page: int = 1,
    size: int = 20,
) -> PageResult[dict]:
    """取用日志：主备端点复测时应看到相同指纹的取用记录。"""
    items, total = service.list_logs(account, endpoint=endpoint, page=page, size=size)
    return PageResult(items=items, total=total, page=page, size=size)


@router.post("/share-readonly", response_model=ActionResult)
def share_readonly(payload: EntryPayload, account: str = Query(description="调用账号（属主）")) -> ActionResult:
    """只读窗口共享：只有凭证属主能发起，越权共享直接拒绝。"""
    entry, message, status_code = service.share_readonly(account, payload.values)
    if entry is None:
        raise _fail(status_code, message)
    return ActionResult(ok=True, message=message, entry=entry)


@router.get("/export")
def export_windows(account: str = Query(description="调用账号")) -> dict[str, Any]:
    items, total = service.list_windows(account=account, page=1, size=10000)
    return {"module": "credential", "total": total, "items": items}
