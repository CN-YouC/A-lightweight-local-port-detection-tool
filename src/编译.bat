// 端口检测工具的构建脚本
// 用 .NET Framework 自带的 csc.exe 编译，不需要 Visual Studio
// 用法：双击本文件，或在 src 目录下执行

@echo off
chcp 65001 >nul
cd /d "%~dp0"

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo 找不到 csc.exe，本机可能没有安装 .NET Framework 4.x。
    pause
    exit /b 1
)

if not exist "%~dp0..\dist" mkdir "%~dp0..\dist"

"%CSC%" /nologo /target:winexe /codepage:65001 /optimize+ /platform:anycpu ^
 /out:"%~dp0..\dist\端口检测工具.exe" ^
 /win32manifest:"%~dp0app.manifest" ^
 /r:System.dll /r:System.Core.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Management.dll ^
 "%~dp0PortInspector.cs"

if errorlevel 1 (
    echo.
    echo 编译失败。
    pause
    exit /b 1
)

echo.
echo 编译完成：dist\端口检测工具.exe
pause
