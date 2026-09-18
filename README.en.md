# Kiro AI Auto Approve (Windows)

Double-click `dist\KiroAutoApprove.exe` to run. Python, PyQt, and the .NET SDK are not required.

The UI follows the Windows display language automatically: Chinese Windows uses Chinese, and other locales use English. Authorization requests and command contents may be Chinese, English, or mixed; detection does not depend on the command language.

## Features

- Full authorization is enabled by default.
- Automatically recognizes Kiro authorization cards and activates `Allow`.
- Supports authorization text, `PERMISSION NEEDED`, and `Allow + Deny` structural detection.
- Scans every visible Kiro top-level window.
- Verifies that the original authorization card disappeared or changed after activation.
- Records `unmatched`, `unresolved`, and `error` results instead of silently missing failures.
- Includes searchable and filterable authorization history.
- Optional high-risk command protection and Windows startup.
- Continues running in the system tray after the main window closes.

Audit history is stored at `%LOCALAPPDATA%\KiroAutoApprove\authorization-history.jsonl`.

## Build

```powershell
.\build.ps1
```

The build uses the Windows .NET Framework C# compiler and has no third-party dependencies.

For UI testing, `KIRO_AUTO_APPROVE_LANG=en` or `KIRO_AUTO_APPROVE_LANG=zh` can override automatic language detection.
