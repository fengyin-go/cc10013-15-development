"""凭据生效数据集端到端复测脚本。

覆盖需求点：
1. 主备端点在各自授权窗口内取得同一把有效密钥，取用日志指纹相同；
2. 轮换窗口内新旧凭据冲突，优先级规则改变当前请求绑定的密钥；
3. 一次请求只绑定一把有效密钥；
4. 越权端点读不到窗口外密钥、越权账号看不到/改不到他人凭据、不能越权共享只读窗口；
5. 认证失败 -> 端点异常待处理清单 + 凭据抽屉失败窗口；
6. 工作台与凭据抽屉读取同一窗口（同一归属范围）。
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8000"

PASS = 0
FAIL = 0


def call(method: str, path: str, values: dict | None = None) -> tuple[int, dict]:
    url = f"{BASE}{path}"
    data = json.dumps({"values": values or {}}).encode("utf-8") if method == "POST" else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


def q(**params) -> str:
    return urllib.parse.urlencode(params)


print("== 1. 授权名册与窗口列表的归属范围 ==")
status, body = call("GET", "/api/credential/accounts")
accounts = {item["账号"]: item for item in body["items"]}
check("名册含运营/只读/越权三类账号", set(accounts) == {"acct-operator", "acct-reader", "acct-outsider"})

status, op_windows = call("GET", f"/api/credential/windows?{q(account='acct-operator')}")
op_cred_nos = {row["凭证编号"] for row in op_windows["items"]}
check("运营账号可见名下全部三个凭证编号", op_cred_nos == {"AUTH-0001", "AUTH-0002", "AUTH-0003"})

status, reader_windows = call("GET", f"/api/credential/windows?{q(account='acct-reader')}")
reader_cred_nos = {row["凭证编号"] for row in reader_windows["items"]}
check("只读账号只看到被共享的 AUTH-0001", reader_cred_nos == {"AUTH-0001"})

status, outsider_windows = call("GET", f"/api/credential/windows?{q(account='acct-outsider')}")
check("越权账号的凭据抽屉为空", outsider_windows["total"] == 0)

print("== 2. 主备端点复测：同一把有效密钥、相同指纹 ==")
status, primary = call("POST", f"/api/credential/fetch?{q(account='acct-operator')}",
                       {"凭证编号": "AUTH-0001", "引用端点": "EP-PRIMARY-01"})
check("主端点取用成功", status == 200, str(primary))
status, standby = call("POST", f"/api/credential/fetch?{q(account='acct-operator')}",
                       {"凭证编号": "AUTH-0001", "引用端点": "EP-STANDBY-01"})
check("备用端点取用成功", status == 200, str(standby))
check("主备端点绑定同一指纹",
      primary["entry"]["绑定指纹"] == standby["entry"]["绑定指纹"] and bool(primary["entry"]["绑定指纹"]))
check("一次请求只绑定一把密钥（单个绑定指纹字段）",
      isinstance(primary["entry"]["绑定指纹"], str) and primary["entry"]["绑定指纹"].startswith("sha256:"))

status, logs = call("GET", f"/api/credential/access-logs?{q(account='acct-operator', endpoint='EP-')}")
new_logs = [row for row in logs["items"] if row["取用结果"] == "已取用"]
fp_set = {row["绑定指纹"] for row in new_logs if row["凭证编号"] == "AUTH-0001"}
check("取用日志中主备端点记录相同指纹", len(fp_set) == 1)
check("只读账号能看到共享凭证的取用日志",
      call("GET", f"/api/credential/access-logs?{q(account='acct-reader')}")[1]["total"] >= 2)
check("越权账号看不到任何取用日志",
      call("GET", f"/api/credential/access-logs?{q(account='acct-outsider')}")[1]["total"] == 0)

print("== 3. 轮换冲突：优先级规则决定当前请求依据 ==")
status, conflict_rows = call("GET", f"/api/credential/windows?{q(account='acct-operator', conflict_only='true')}")
check("抽屉能识别轮换冲突窗口", conflict_rows["total"] >= 2)
check("冲突窗口记录了新旧两个指纹",
      all(row["旧指纹"] and row["新指纹"] for row in conflict_rows["items"]))

# 默认 new-first：应绑定新指纹
new_fp = next(row["新指纹"] for row in conflict_rows["items"] if row["轮换状态"] == "轮换中-新指纹")
old_fp = next(row["新指纹"] for row in conflict_rows["items"] if row["轮换状态"] == "轮换中-旧指纹")
check("默认 new-first 绑定新指纹", primary["entry"]["绑定指纹"] == new_fp,
      f"{primary['entry']['绑定指纹']} != {new_fp}")

status, rule = call("POST", f"/api/credential/priority-rule?{q(account='acct-operator')}", {"规则值": "old-first"})
check("优先级规则可切换为 old-first", status == 200 and rule["entry"]["规则值"] == "old-first")
status, primary_old = call("POST", f"/api/credential/fetch?{q(account='acct-operator')}",
                           {"凭证编号": "AUTH-0001", "引用端点": "EP-PRIMARY-01"})
check("old-first 时同一请求改绑旧指纹（取舍影响终态）",
      primary_old["entry"]["绑定指纹"] == old_fp and primary_old["entry"]["绑定指纹"] != new_fp)
call("POST", f"/api/credential/priority-rule?{q(account='acct-operator')}", {"规则值": "new-first"})

print("== 4. 授权隔离：越权端点与越权账号 ==")
# 越权端点：账号有权看凭证，但端点不在授权窗口
status, body = call("POST", f"/api/credential/fetch?{q(account='acct-operator')}",
                    {"凭证编号": "AUTH-0001", "引用端点": "EP-OTHER-99"})
check("归属范围外端点取用被 403 拒绝", status == 403)
# 越权账号读他人凭据
status, body = call("POST", f"/api/credential/fetch?{q(account='acct-outsider')}",
                    {"凭证编号": "AUTH-0001", "引用端点": "EP-OTHER-99"})
check("越权账号读取他人凭据被 403 拒绝", status == 403)
# 越权账号看单条窗口明细
status, body = call("GET", f"/api/credential/windows/1?{q(account='acct-outsider')}")
check("越权账号读取窗口明细被 403 拒绝", status == 403)
# 越权账号尝试登记/轮换
status, body = call("POST", f"/api/credential/windows?{q(account='acct-outsider')}",
                    {"凭证编号": "AUTH-0001", "引用端点": "EP-OTHER-99", "端点角色": "主端点",
                     "生效开始": "2026-11-20T00:00:00", "生效结束": "2026-12-20T00:00:00",
                     "凭证密钥": "k"})
check("越权账号登记窗口被拒绝", status == 403)
status, body = call("POST", f"/api/credential/windows/1/rotate?{q(account='acct-reader')}",
                    {"凭证密钥": "x", "重叠结束": "2026-11-17T00:00:00", "新窗口开始": "2026-11-16T00:00:00"})
check("只读账号不能改动他人凭据", status == 403)
# 越权共享只读窗口
status, body = call("POST", f"/api/credential/share-readonly?{q(account='acct-reader')}",
                    {"凭证编号": "AUTH-0001", "目标账号": "acct-outsider"})
check("非属主越权共享被拒绝", status == 403)
status, body = call("POST", f"/api/credential/share-readonly?{q(account='acct-operator')}",
                    {"凭证编号": "AUTH-0002", "目标账号": "acct-reader"})
check("属主共享只读窗口成功", status == 200)
status, reader_after = call("GET", f"/api/credential/windows?{q(account='acct-reader')}")
check("共享后只读账号抽屉出现 AUTH-0002",
      {row["凭证编号"] for row in reader_after["items"]} == {"AUTH-0001", "AUTH-0002"})

print("== 5. 无可用凭据与认证失败闭环 ==")
# 过期窗口：采集端找不到可用凭据
status, body = call("POST", f"/api/credential/fetch?{q(account='acct-operator')}",
                    {"凭证编号": "AUTH-0003", "引用端点": "EP-PRIMARY-03"})
check("过期窗口取用返回 409 无可用凭据", status == 409)
status, exc_before = call("GET", f"/api/endpoint-exception?{q(account='acct-operator')}")
check("找不到凭据自动落入异常待处理清单",
      any(row["异常原因"].startswith("采集端找不到可用凭据") for row in exc_before["items"]))

# 认证失败回报：取一条已取用日志
status, logs = call("GET", f"/api/credential/access-logs?{q(account='acct-operator')}")
target_log = next(row for row in logs["items"] if row["认证结果"] == "待回报")
status, body = call("POST",
                    f"/api/credential/access-logs/{target_log['id']}/auth-result?{q(account='acct-operator')}",
                    {"认证结果": "失败", "备注": "采集端返回 401"})
check("认证失败回报成功", status == 200)
status, exc_after = call("GET", f"/api/endpoint-exception?{q(account='acct-operator', status='待处理')}")
check("异常清单出现认证失败记录",
      any("认证失败" in row["异常原因"] and row["引用端点"] == target_log["引用端点"]
          for row in exc_after["items"]))
status, windows = call("GET", f"/api/credential/windows?{q(account='acct-operator', keyword='AUTH-0001')}")
check("凭据抽屉同步显示失败窗口",
      any(row["失败窗口"] and row["凭证编号"] == "AUTH-0001" for row in windows["items"]))
# 工作台同一窗口：越权账号看不到该异常
status, exc_outsider = call("GET", f"/api/endpoint-exception?{q(account='acct-outsider')}")
check("越权账号工作台看不到他人凭据异常", exc_outsider["total"] == 0)
# 只读账号不能处理异常，属主可以闭环
exc_id = next(row["id"] for row in exc_after["items"] if "认证失败" in row["异常原因"])
status, body = call("POST", f"/api/endpoint-exception/{exc_id}/resolve?{q(account='acct-reader')}",
                    {"处理说明": "尝试关闭"})
check("只读账号处理异常被拒绝", status == 403)
status, body = call("POST", f"/api/endpoint-exception/{exc_id}/resolve?{q(account='acct-operator')}",
                    {"处理说明": "重新推送密钥后恢复"})
check("属主闭环异常成功", status == 200 and body["entry"]["处理状态"] == "已处理")

print("== 6. 轮换动作：新旧指纹与重叠窗口一起保存 ==")
status, body = call("POST", f"/api/credential/windows/5/rotate?{q(account='acct-operator')}",
                    {"凭证密钥": "secret-auth0002-rotated",
                     "新窗口开始": "2026-11-16T00:00:00",
                     "重叠结束": "2026-11-20T00:00:00",
                     "新窗口结束": "2026-12-20T00:00:00"})
check("AUTH-0002 轮换成功", status == 200, str(body))
new_window = body["entry"]
check("新窗口同时保存旧指纹与新指纹", bool(new_window["旧指纹"]) and bool(new_window["新指纹"])
      and new_window["旧指纹"] != new_window["新指纹"])
status, all_rows = call("GET", f"/api/credential/windows?{q(account='acct-operator', keyword='AUTH-0002')}")
# 主备端点都应有同指纹的新窗口
standby_new = [row for row in all_rows["items"]
               if row["引用端点"] == "EP-STANDBY-02" and row["轮换状态"] == "轮换中-新指纹"]
check("备用端点同步生成同指纹新窗口", len(standby_new) == 1
      and standby_new[0]["新指纹"] == new_window["新指纹"])
status, fetched = call("POST", f"/api/credential/fetch?{q(account='acct-operator')}",
                       {"凭证编号": "AUTH-0002", "引用端点": "EP-STANDBY-02"})
check("轮换后备用端点在授权窗口内取到新指纹",
      status == 200 and fetched["entry"]["绑定指纹"] == new_window["新指纹"])
# 非法时间轴
status, body = call("POST", f"/api/credential/windows/6/rotate?{q(account='acct-operator')}",
                    {"凭证密钥": "bad", "新窗口开始": "2026-12-01T00:00:00",
                     "重叠结束": "2026-11-18T00:00:00"})
check("不满足重叠时间轴的轮换被拒绝", status == 400)

print(f"\n结果：{PASS} 通过 / {FAIL} 失败")
sys.exit(1 if FAIL else 0)
