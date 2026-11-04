@echo off
REM ═══════════════════════════════════════════════════════════════════
REM  RevalPack — Build Standalone EXE
REM  Requirements: Python 3.10+, pip
REM  Run this once on your Windows machine.
REM  Output: dist\RevalPack.exe  (double-click to launch)
REM ═══════════════════════════════════════════════════════════════════

echo.
echo  ██████╗ ███████╗██╗   ██╗ █████╗ ██╗     ██████╗  █████╗  ██████╗██╗  ██╗
echo  ██╔══██╗██╔════╝██║   ██║██╔══██╗██║     ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
echo  ██████╔╝█████╗  ██║   ██║███████║██║     ██████╔╝███████║██║     █████╔╝
echo  ██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══██║██║     ██╔═══╝ ██╔══██║██║     ██╔═██╗
echo  ██║  ██║███████╗ ╚████╔╝ ██║  ██║███████╗██║     ██║  ██║╚██████╗██║  ██╗
echo  ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
echo.
echo  Shieldient Security Revalidation Scanner — EXE Builder
echo  ═══════════════════════════════════════════════════════
echo.

echo [1/3] Installing dependencies...
pip install pyinstaller requests beautifulsoup4 urllib3 --quiet
if %ERRORLEVEL% NEQ 0 (
    echo [!] pip install failed. Make sure Python and pip are in PATH.
    pause & exit /b 1
)

echo [2/3] Building RevalPack.exe...
pyinstaller ^
  --onefile ^
  --windowed ^
  --name "RevalPack" ^
  --icon NONE ^
  --hidden-import "bs4" ^
  --hidden-import "urllib3" ^
  --hidden-import "requests" ^
  --hidden-import "certifi" ^
  revalpack_gui.py

echo [3/3] Checking output...
echo.
if exist dist\RevalPack.exe (
    echo ════════════════════════════════════════════
    echo  BUILD SUCCESS!
    echo  File: dist\RevalPack.exe
    echo  Size:
    for %%A in (dist\RevalPack.exe) do echo        %%~zA bytes
    echo.
    echo  Double-click dist\RevalPack.exe to launch.
    echo  Results saved to: revalpack_output\ folder
    echo ════════════════════════════════════════════
) else (
    echo [!] BUILD FAILED — check errors above.
)
echo.
pause
