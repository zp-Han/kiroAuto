# Kiro AI 自动授权（Windows 可执行程序）

双击 `dist\KiroAutoApprove.exe` 即可运行，不需要安装 Python、PyQt 或 .NET SDK。

[English README](README.en.md)

程序 UI 自动跟随 Windows 显示语言：中文系统显示中文，其他语言环境显示英文。授权请求及命令内容可以是中文、英文或混合文本，识别不依赖命令内容的语言。

程序启动后会自动监听 Kiro IDE，识别 `Your approval is required to continue` 授权卡片并点击一次性 `Allow` 按钮。默认启用“完整授权”，不再逐次手工确认。关闭主窗口后程序会继续驻留系统托盘。

## 功能

- 完整授权默认开启；
- 主界面查询最近的授权、拦截和错误记录；
- 检测到但无法处理的请求会以 `unmatched`、`unresolved` 或 `error` 记录，不再静默遗漏；
- 可按结果筛选或按命令、窗口关键字搜索；
- 可选高风险命令保护，默认关闭；
- 可选开机自动启动；
- 托盘菜单支持打开、暂停/继续和退出；
- 审计日志位于 `%LOCALAPPDATA%\KiroAutoApprove\authorization-history.jsonl`。

程序只扫描进程名为 `Kiro` 的窗口，并要求 `Allow` 按钮附近存在 Kiro 授权语义。优先使用控件调用；只有前两种无障碍调用均不可用时，才使用从目标控件实时取得并校验的坐标，不使用固定坐标，也不会扫描其他应用。

识别采用多级兜底：授权文案、`PERMISSION NEEDED`、`Allow + Deny` 按钮结构及 Kiro 全窗口信号。点击优先使用 UI Automation，失败时使用经过窗口与控件校验的动态坐标；点击后还会确认原授权卡片已消失或切换，否则记录错误并继续重试。

## 使用

1. 双击 `dist\KiroAutoApprove.exe`。
2. 保持“完整授权”勾选。
3. 正常使用 Kiro；授权框出现后程序会自动处理。
4. 在主界面的“授权记录”中查阅结果。

完整授权意味着 Kiro 请求的命令会被直接允许。需要额外保护时，可勾选“拦截删库、递归删除等高风险命令”。

## 重新编译

修改 `src\Program.cs` 后运行：

```powershell
.\build.ps1
```

构建使用 Windows 自带的 .NET Framework C# 编译器，无第三方依赖。
