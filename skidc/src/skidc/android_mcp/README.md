# Android MCP Bridge 对接说明

这个目录是 Skidc 的 Android 能力层，提供一个独立的 FastAPI HTTP 服务，用来让主系统控制 Android App、观察页面、导入抓包结果、做 APK 静态摘要分析、记录 Frida 证据，并暴露靶场信息。

注意：Android MCP 是“安卓能力接口层”，不是完整主系统。它不负责 Docker 部署、不负责调度 worker、不负责写入主系统 fact，也不负责最终报告生成。

## 当前已经实现的能力

当前 Android MCP MVP 已经提供：

- ADB 设备健康检查和设备列表。
- APK 安装、App 启动、App 停止、App 数据清理。
- UI 输入操作：点击、文本输入、滑动、按键、返回、Home。
- UI 观察能力：截图、UIAutomator XML/节点解析、当前 Activity、logcat 日志。
- Android 模拟器 HTTP 代理设置和清除。
- 网络证据保存，以及从 mitmproxy/Burp 等工具导入 JSON/JSONL 抓包结果。
- APK 静态字符串分析：提取 URL、API path、敏感关键字迹象、有价值文件、当前工具状态。
- Frida 证据记录接口，以及 Frida 脚本模板元信息。
- DVBA 和 BugBazaar 靶场 profile。

## 当前边界

已经实现：

```text
Android MCP HTTP API
ADB App 操作
UI 页面观察
模拟器代理设置
抓包结果导入接口
APK 轻量静态分析
Frida 证据接收接口
靶场 profile 暴露
```

暂未实现：

```text
Android MCP 的 Docker Compose 部署
mitmproxy 自动启动和实时抓包导入
Frida server 自动管理
Frida 自动 spawn / attach / hook 执行
DVBA / BugBazaar 自动化 runner
证据自动写回 Skidc fact / attack path
最终漏洞报告生成
```

一句话总结：Android 侧的能力接口已经准备好；系统集成层还需要负责部署它、调用它，并把结果持久化到主系统。

## 启动方式

在 `skidc` 包目录下启动 Android MCP：

```powershell
cd skidc
uv run skidc android-mcp --host 0.0.0.0 --port 8765 --device-id emulator-5554
```

如果实际 ADB 设备 id 不是 `emulator-5554`，请替换成真实设备 id。

服务地址：

```text
http://<android-mcp-host>:8765
```

本机查看接口文档：

```text
http://127.0.0.1:8765/docs
```

## 主系统对接方式

dispatcher 或 worker 需要注入环境变量：

```text
ANDROID_MCP_URL=http://<android-mcp-host>:8765
```

如果主系统跑在 Docker 中，而 Android MCP 跑在 Windows 宿主机上，Docker 容器里通常需要使用：

```text
ANDROID_MCP_URL=http://host.docker.internal:8765
```

dispatcher 配置需要使用 Android prompt 组：

```yaml
runtime:
  prompt_group: "android"
```

系统集成人员需要保证：

```text
1. worker 容器可以访问 ANDROID_MCP_URL。
2. Android MCP 服务可以访问 adb 和 Android 模拟器/设备。
3. Android MCP 返回的数据能被转换成 Skidc 的 fact / evidence / attack path。
```

## 接口清单

设备状态：

```text
GET /health
GET /devices
```

App 生命周期：

```text
POST /app/install
POST /app/start
POST /app/stop
POST /app/clear
```

输入操作：

```text
POST /input/tap
POST /input/text
POST /input/swipe
POST /input/key
POST /input/back
POST /input/home
```

页面观察：

```text
GET  /observe/ui
GET  /observe/activity
GET  /observe/screenshot
POST /observe/logcat
```

网络和代理：

```text
POST   /network/proxy/set
POST   /network/proxy/clear
GET    /network/history
POST   /network/events
POST   /network/import
DELETE /network/history
```

APK 静态摘要：

```text
POST   /reverse/analyze
GET    /reverse/reports
DELETE /reverse/reports
```

Frida 证据：

```text
GET    /frida/scripts
POST   /frida/observations
GET    /frida/observations
DELETE /frida/observations
```

靶场信息：

```text
GET /lab/profiles
```

## 联通性检查

在宿主机检查：

```bash
curl http://127.0.0.1:8765/health
curl http://127.0.0.1:8765/lab/profiles
curl http://127.0.0.1:8765/frida/scripts
```

在需要调用 Android MCP 的 Docker 容器里检查：

```bash
python -c "import urllib.request; print(urllib.request.urlopen('http://host.docker.internal:8765/lab/profiles', timeout=5).read().decode()[:300])"
```

## 建议的数据映射

系统集成时，建议把 Android MCP 的返回结果写回 Skidc fact。

网络证据：

```text
/network/history
/network/import
-> mobile_api fact
-> 记录 method、url、status_code、request_headers、response_headers、body preview
```

APK 静态分析：

```text
/reverse/analyze
-> mobile_reverse fact
-> 记录 endpoints、endpoint_paths、secret_indicators、interesting_files、tools
```

Frida 运行时证据：

```text
/frida/observations
-> mobile_runtime fact
-> 记录 package、script_id、event_type、summary、details
```

UI 和日志证据：

```text
/observe/ui
/observe/activity
/observe/logcat
-> mobile_ui 或 mobile_log fact
-> 记录当前页面节点、Activity、关键日志
```

## 示例请求

导入网络抓包证据：

```bash
curl -X POST http://127.0.0.1:8765/network/import \
  -H "Content-Type: application/json" \
  -d '{"source":"mitmproxy","content":"{\"events\":[{\"method\":\"GET\",\"url\":\"https://bank.test/api/profile\",\"status_code\":200}]}"}'
```

分析 APK：

```bash
curl -X POST http://127.0.0.1:8765/reverse/analyze \
  -H "Content-Type: application/json" \
  -d '{"apk_path":"D:\\targets\\dvba.apk"}'
```

记录 Frida 观察结果：

```bash
curl -X POST http://127.0.0.1:8765/frida/observations \
  -H "Content-Type: application/json" \
  -d '{"package":"com.demo.bank","script_id":"okhttp_request_observer","event_type":"http_request","summary":"Observed OkHttp request to profile endpoint","details":{"url":"https://bank.test/api/profile"}}'
```

设置模拟器 HTTP 代理：

```bash
curl -X POST http://127.0.0.1:8765/network/proxy/set \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1","port":8080}'
```

## 给 Docker / 系统集成人员的说明

以下内容需要在 Android MCP 之外完成：

```text
1. 在 Docker Compose 中增加 android-mcp 服务，或者让 worker 容器访问宿主机上的 Android MCP。
2. 给 dispatcher / worker 注入 ANDROID_MCP_URL。
3. 确保 Android MCP 运行环境能正常使用 adb。
4. 可选安装 jadx、apktool、frida、frida-tools、mitmproxy，用于增强移动端测试能力。
5. 把 Android MCP 返回结果转换成 Skidc fact、evidence、attack path 和报告数据。
```

## Frida 当前状态

Frida 在当前 MVP 中还不是完整自动化能力。

已经实现：

```text
Frida 脚本模板元信息
运行时观察结果记录
观察结果历史查询接口
```

暂未实现：

```text
frida-server 部署
frida attach / spawn
JS hook 执行
OkHttp / Retrofit / WebView / SSL pinning 自动 hook
hook 日志自动采集
```

在 Frida 执行 runner 完成前，可以先使用 `/frida/observations` 保存外部或人工 Frida 流程产生的证据。
