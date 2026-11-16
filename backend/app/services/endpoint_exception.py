"""端点异常待处理清单业务规则。

认证失败的端点落到这里，工作台与凭据抽屉读取同一窗口、同一套归属范围；
状态流转只允许在 services 层完成，路由层不做业务判断。
"""
from __future__ import annotations

from typing import Any

from app.services.credential import CredentialService

credential_service = CredentialService()


class EndpointExceptionService:
    def list_exceptions(
        self,
        account: str,
        *,
        status: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        return credential_service.list_exceptions(account, status=status, page=page, size=size)

    def resolve(self, account: str, exception_id: int, values: dict[str, Any]) -> tuple[dict[str, Any] | None, str, int]:
        return credential_service.resolve_exception(account, exception_id, values)

    def stats(self, account: str) -> list[dict[str, Any]]:
        rows, _ = self.list_exceptions(account, page=1, size=10000)
        return [
            {"label": "待处理异常", "value": sum(1 for row in rows if row.get("处理状态") == "待处理")},
            {"label": "已处理异常", "value": sum(1 for row in rows if row.get("处理状态") == "已处理")},
            {"label": "关联失败指纹", "value": len({row.get("关联指纹") for row in rows if row.get("关联指纹")})},
        ]
