# Sensitive Leak Detector

Sensitive Leak Detector 是一个轻量级敏感数据泄露检测工具，用于在代码发布前或安全巡检时发现常见的密钥、配置文件和暴露接口。

工具默认会对命中的敏感值做脱敏展示，避免把完整密钥再次写入日志或报告。

## 功能

- 本地文件扫描：检测 GitHub Token、AWS Access Key、Slack Token、Stripe Key、Google API Key、JWT、数据库连接串、私钥块等。
- 高熵值检测：识别 `token`、`secret`、`api_key`、`password` 等敏感变量名后的疑似密钥。
- 常见泄露接口测试：检测 `.env`、`.git/config`、Swagger/OpenAPI、Spring Actuator、GraphQL introspection、数据库 dump、备份压缩包、phpinfo、Apache server-status 等常见暴露面。
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

只在高危及以上发现时返回失败退出码：

```powershell
sld . --fail-on high
```

排除额外目录或文件名：

```powershell
sld . --exclude .venv --exclude generated --exclude "*.min.js"
```

## 常见泄露接口测试

对授权范围内的网站执行常见敏感接口探测：

```powershell
sld . --url https://example.com
```

仅需要接口探测时，也可以把本地扫描路径指向一个空目录或当前项目目录：

```powershell
sld . --url https://example.com --format json
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

接口探测只会发起普通 HTTP GET/POST 请求，不会进行绕过、爆破、利用或破坏性操作。请仅在你拥有授权的系统上使用。

## 退出码

- `0`：没有发现达到 `--fail-on` 阈值的问题。
- `1`：发现了达到 `--fail-on` 阈值的问题。
- `2`：命令参数错误。

## 示例输出

```text
No local sensitive data findings detected.

1 exposed endpoint finding(s) detected:
https://example.com/.env [200] [critical] env-file - Exposed environment file (DB_PASSWORD=...)
```

## 安全建议

如果发现真实敏感信息泄露，请立即：

- 下线或限制暴露接口访问。
- 轮换已经泄露的密钥、Token、密码或证书。
- 检查访问日志，确认是否有异常访问。
- 如果密钥进入了 git 历史，清理历史并重新发布。

本工具基于规则和内容特征检测，可能存在误报或漏报，适合作为发布前检查和日常巡检的一层防护。
