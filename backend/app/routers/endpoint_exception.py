"""端点异常待处理清单接口：工作台与凭据抽屉读取同一窗口的认证失败记录。"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.schemas import ActionResult, EntryPayload, PageResult
from app.services.endpoint_exception import EndpointExceptionService

router = APIRouter(prefix="/api/endpoint-exception", tags=["端点异常待处理清单"])

service = EndpointExceptionService()


@router.get("", response_model=PageResult[dict])
def list_exceptions(
    account: str = Query(description="调用账号，按归属范围过滤"),
    status: str | None = Query(default=None, description="待处理、已处理"),
    page: int = 1,
    size: int = 20,
) -> PageResult[dict]:
    if size > 200:
        raise HTTPException(status_code=400, detail="每页最多 200 条，请缩小分页范围")
    items, total = service.list_exceptions(account, status=status, page=page, size=size)
    return PageResult(items=items, total=total, page=page, size=size)


@router.get("/stats")
def exception_stats(account: str = Query(description="调用账号")) -> dict[str, object]:
    return {"items": service.stats(account)}


@router.post("/{exception_id}/resolve", response_model=ActionResult)
def resolve_exception(exception_id: int, payload: EntryPayload, account: str = Query(description="调用账号")) -> ActionResult:
    entry, message, status_code = service.resolve(account, exception_id, payload.values)
    if entry is None:
        raise HTTPException(status_code=status_code, detail=message)
    return ActionResult(ok=True, message=message, entry=entry)
