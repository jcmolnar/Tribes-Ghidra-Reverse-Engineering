@echo off
REM Build freezefix.dll — 32-bit Tribes 1.40.655 dedicated-server freeze fix plugin.
REM 32-bit REQUIRED (target Tribes.exe is x86). Inject with re\injector\xtloader.exe.
REM Optional: pass a test threshold, e.g.  build_freezefix.bat 30   (rebase after 30s).
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86
if errorlevel 1 ( echo vcvarsall failed & exit /b 1 )
cd /d "%~dp0"
set THRESH=
if not "%~1"=="" set THRESH=/DFREEZE_THRESHOLD=%~1.0f
cl /nologo /LD /EHsc /O2 %THRESH% freezefix.cpp /Fe:freezefix.dll
if errorlevel 1 ( echo BUILD FAILED & exit /b 1 )
echo BUILD OK: freezefix.dll  %THRESH%
