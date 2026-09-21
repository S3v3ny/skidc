# Android MCP Bridge 使用说明

这是 Skidc 的第一版 Android 目标扩展。它不是用来替代原来的 Web/API
测试能力，而是在现有系统上新增一个“移动端 App 控制面”，让原本的
`bootstrap -> reason -> explore -> fact` 调度流程也可以操作 Android 模拟器里的 App。

简单理解：

```text
原来：Agent 主要访问网页、接口、主机环境
现在：Agent 还可以启动 App、点击界面、读取 UI 树、截图、查看网络记录
```

## 它提供什么能力

这个 bridge 是一个小型 FastAPI 服务，用下面的命令启动：

```powershell
cd skidc
uv run skidc android-mcp --device-id emulator-5554 --host 127.0.0.1 --port 8765
```

它底层通过 `adb` 控制 Android 模拟器/真机，并暴露这些接口：

| 能力区域 | 接口 |
|---|---|
| 设备状态 | `GET /health`, `GET /devices` |
| App 控制 | `POST /app/install`, `/app/start`, `/app/stop`, `/app/clear` |
| 输入操作 | `POST /input/tap`, `/input/text`, `/input/swipe`, `/input/back`, `/input/home` |
| 页面观察 | `GET /observe/ui`, `/observe/activity`, `/observe/screenshot`, `POST /observe/logcat` |
| 网络记录 | `GET /network/history`, `POST /network/events`, `DELETE /network/history` |

第一版主要使用：

```text
ADB：连接设备、启动 App、输入点击、截图、读取日志
UIAutomator dump：导出当前 App 页面控件树
FastAPI：把这些能力包装成 HTTP 接口
```

后续可以继续叠加：

```text
Appium：更完整的自动化测试框架
OCR：识别截图里的文字
mitmproxy：自动导入 App 网络请求
Frida：更深层的 Hook、签名参数和运行时分析
```

## 怎么接入 Skidc

使用 [dispatch_android.example.yaml](dispatch_android.example.yaml)，关键配置是：

```yaml
runtime:
  prompt_group: "android"

common_env:
  ANDROID_MCP_URL: "http://127.0.0.1:8765"
```

这里的意思是：

```text
prompt_group: "android"
让 dispatcher 使用 Android 专用提示词。

ANDROID_MCP_URL
告诉 worker Android bridge 在哪里。
```

创建项目时，`origin` 可以描述 App 目标，例如：

```text
APK: D:\targets\demo.apk
Package: com.example.demo
Device: emulator-5554
Test accounts: user_a / user_b
Proxy: mitmproxy or Burp if configured
```

然后 Skidc 的流程仍然不变：

```text
reason 读取当前图谱
-> 生成 Android 相关 intent
-> explore 调用 Android bridge 操作 App
-> 把观察结果写回 fact
-> reason 再判断下一步或是否完成
```

Android prompt 组会引导 worker 在 `explore` 阶段调用 bridge，并把观察结果写成类似这样的 fact：

```json
{
  "description": "登录 user_a 后进入订单详情页，观察到 App 请求 /api/order/detail?order_id=1001，响应包含订单所有者信息",
  "scope": "mobile_api",
  "vuln_type": "business_logic",
  "severity": "medium"
}
```

## 第一版边界

这一版是最小可用版本，故意保持克制：

```text
不暴露任意 adb shell 执行
不默认做 Frida Hook
不默认做 OCR
不直接集成 Burp
不自动判断所有漏洞成立
```

它先解决最核心的问题：

```text
让 Agent 能控制 Android App
让 Agent 能观察 App 页面和状态
让 App 端发现可以写回 Skidc 的 fact-intent 图
```

这样就能和原有逻辑漏洞检测能力衔接起来：Android bridge 负责“进入和操作移动端业务流程”，reason/explore 负责“基于事实继续规划和判断”。

## 为什么它不是替代 Web 测试

这个模块的定位是新增目标类型：

```text
Web/API 测试：继续保留
Android App 测试：新增能力
混合目标：App 操作 + API 观察 + Web/API 验证
```

很多真实业务只有 App 入口，例如登录、订单、优惠券、积分、支付、设备绑定等。Android bridge 让 Skidc 可以覆盖这些移动端原生流程，而不是只停留在网页端。
## Mobile lab extension

The Android bridge now includes the first complete mobile-lab integration layer:

```text
Network evidence:
  GET /network/history
  POST /network/events
  POST /network/import
  DELETE /network/history

Proxy control:
  POST /network/proxy/set
  POST /network/proxy/clear

APK reverse summary:
  POST /reverse/analyze
  GET /reverse/reports
  DELETE /reverse/reports

Frida evidence:
  GET /frida/scripts
  POST /frida/observations
  GET /frida/observations
  DELETE /frida/observations

Lab profiles:
  GET /lab/profiles
```

Recommended first target: DVBA (Damn Vulnerable Bank). The intended flow is:

```text
1. Start the vulnerable backend and Android emulator.
2. Install/start the APK through /app/install and /app/start.
3. Point the emulator to mitmproxy or Burp with /network/proxy/set.
4. Let the agent operate registration, login, profile, balance, transfer, and transaction flows.
5. Import proxy JSON or JSONL through /network/import.
6. Run /reverse/analyze against the APK to collect endpoints, path strings, secret indicators, and tool status.
7. Store authorized Frida runtime findings through /frida/observations.
8. Feed UI, network, reverse, and runtime evidence back into the normal fact/intent/reason loop.
```

The target output is an evidence-backed mobile finding, not just "the app opened":

```json
{
  "target": "DVBA Android app",
  "flow": "user_a login -> view transactions -> user_b replay or modify object id",
  "evidence": {
    "ui": "screenshots and UIAutomator nodes",
    "network": "captured API request and response history",
    "reverse": "APK endpoints and sensitive string indicators",
    "runtime": "Frida observations when enabled"
  },
  "finding": "mobile UI reaches an API authorization flaw with reproducible request evidence"
}
```
