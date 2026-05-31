# Sensitive Leak Detector

Sensitive Leak Detector 是一个轻量级敏感数据泄露检测工具，用于在代码发布前、上线前检查或安全巡检时发现常见的密钥、配置文件、暴露接口和未授权 API 数据泄露。

工具默认会对命中的敏感值做脱敏展示，避免把完整密钥再次写入日志或报告。

## 功能

- 本地文件扫描：检测 GitHub Token、AWS Access Key、Slack Token、Stripe Key、Google API Key、JWT、数据库连接串、私钥块等。
- 高熵值检测：识别 `token`、`secret`、`api_key`、`password` 等敏感变量名后的疑似密钥。
- 常见泄露接口测试：检测 `.env`、`.git/config`、Swagger/OpenAPI、Spring Actuator、GraphQL introspection、数据库 dump、备份压缩包、phpinfo、Apache server-status 等常见暴露面。
- 重点 API 地址测试：检测常见 `/api/...` 接口是否未授权返回用户、订单、客户、配置、日志、Token 等敏感业务数据。
- 支持自定义 API 路径和路径文件，方便把前端 JS、Swagger、网关日志里发现的接口清单批量加入测试。
- 支持文本和 JSON 输出，适合本地使用或接入 CI。
- 无第三方运行依赖，Python 标准库即可运行。

## 安装

在仓库目录执行：

```powershell
python -m pip install .
```

也可以不安装，直接通过源码运行：

```powershell
$env:PYTHONPATH='src'
python -m sensitive_leak_detector .
```

## 本地文件扫描

扫描当前目录：

```powershell
sld .
```

输出 JSON：

```powershell
sld . --format json
```

显示检测动态：

```powershell
sld . -v
```

只在高危及以上发现时返回失败退出码：

```powershell
sld . --fail-on high
```

排除额外目录或文件名：

```powershell
sld . --exclude .venv --exclude generated --exclude "*.min.js"
```

## 网站泄露接口测试

对授权范围内的网站执行常见敏感接口探测：

```powershell
sld . --url https://example.com
```

显示接口探测过程，方便观察当前正在测试哪个地址：

```powershell
sld . --url https://example.com -v
```

当前内置探测包括：

- `/.env`
- `/.git/config`
- `/config.json`
- `/config.yml`
- `/backup.zip`
- `/database.sql`
- `/dump.sql`
- `/phpinfo.php`
- `/server-status`
- `/actuator/env`
- `/actuator/configprops`
- `/actuator/heapdump`
- `/swagger.json`
- `/swagger/v1/swagger.json`
- `/v2/api-docs`
- `/v3/api-docs`
- `/openapi.json`
- `/graphql` 的 GraphQL introspection 测试

## 重点 API 地址测试

很多数据泄露发生在 API 地址上，例如用户列表、订单列表、客户资料、配置接口、调试接口、日志接口未做鉴权。工具会默认测试一组高频 API 路径，例如：

- `/api/users`
- `/api/admin/users`
- `/api/customers`
- `/api/orders`
- `/api/accounts`
- `/api/config`
- `/api/settings`
- `/api/debug`
- `/api/logs`
- `/api/auth/user`
- `/api/me`
- `/api/profile`
- `/api/v1/users`
- `/api/v1/orders`
- `/api/v1/config`
- `/api/v2/users`
- `/api/v2/orders`

探测时会重点判断 JSON 响应中是否出现以下敏感业务字段：

- 账号与身份：`user_id`、`username`、`realname`、`name`
- 联系方式：`email`、`phone`、`mobile`
- 业务数据：`order`、`customer`、`amount`、`balance`、`address`
- 凭据字段：`password`、`token`、`secret`、`api_key`、`access_key`
- 证件和银行卡相关字段：`idcard`、`identity`、`cardno`、`bank`

添加单个自定义 API 路径：

```powershell
sld . --url https://example.com --api-path /api/internal/users
```

添加多个自定义 API 路径：

```powershell
sld . --url https://example.com --api-path /api/member/list --api-path /api/order/export
```

从文件批量读取 API 路径，每行一个路径，支持 `#` 注释：

```powershell
sld . --url https://example.com --api-path-file .\api-paths.txt
```

`api-paths.txt` 示例：

```text
# 用户与订单接口
/api/member/list
/api/order/list
/api/v1/customer/export
/admin/api/users
```

输出 JSON，方便接入自动化巡检：

```powershell
sld . --url https://example.com --api-path-file .\api-paths.txt --format json
```

配合 `-v` 可以看到每个 API 地址的探测状态：

```powershell
sld . --url https://example.com --api-path-file .\api-paths.txt --format json -v
```

接口探测只会发起普通 HTTP GET/POST 请求，不会进行绕过、爆破、利用或破坏性操作。请仅在你拥有授权的系统上使用。

## 退出码

- `0`：没有发现达到 `--fail-on` 阈值的问题。
- `1`：发现了达到 `--fail-on` 阈值的问题。
- `2`：命令参数错误。

## 示例输出

```text
No local sensitive data findings detected.

1 exposed endpoint finding(s) detected:
https://example.com/api/users [200] [high] api-sensitive-data - API endpoint may expose sensitive business or user data ("data":[{"user_id":1,"email":"a@example.com")
```

## 安全建议

如果发现真实敏感信息泄露，请立即：

- 下线或限制暴露接口访问。
- 为 API 增加身份认证、权限校验和最小字段返回。
- 轮换已经泄露的密钥、Token、密码或证书。
- 检查访问日志，确认是否有异常访问。
- 如果密钥进入了 git 历史，清理历史并重新发布。

本工具基于规则和内容特征检测，可能存在误报或漏报，适合作为发布前检查和日常巡检的一层防护。
