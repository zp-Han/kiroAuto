[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSCommandPath
$source = Join-Path $projectRoot 'src\Program.cs'
$outputDirectory = Join-Path $projectRoot 'dist'
$output = Join-Path $outputDirectory 'KiroAutoApprove.exe'
$compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$uiaClient = 'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\UIAutomationClient\v4.0_4.0.0.0__31bf3856ad364e35\UIAutomationClient.dll'
$uiaTypes = 'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\UIAutomationTypes\v4.0_4.0.0.0__31bf3856ad364e35\UIAutomationTypes.dll'
$windowsBase = 'C:\Windows\Microsoft.NET\assembly\GAC_MSIL\WindowsBase\v4.0_4.0.0.0__31bf3856ad364e35\WindowsBase.dll'

if (-not (Test-Path -LiteralPath $compiler)) { throw "Windows C# compiler not found: $compiler" }
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

& $compiler /nologo /target:winexe /platform:x64 /optimize+ /out:$output `
    /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll `
    /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll `
    /reference:$uiaClient /reference:$uiaTypes /reference:$windowsBase $source

if ($LASTEXITCODE -ne 0) { throw "Compilation failed with exit code $LASTEXITCODE" }
Write-Host "Built: $output"
