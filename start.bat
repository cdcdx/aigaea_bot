@echo off
cd /d "%~dp0"

@REM echo *%VIRTUAL_ENV%*
if '%VIRTUAL_ENV%' neq '' (
    call .venv/Scripts/deactivate.bat
)

set PYTHON_HOME=%LOCALAPPDATA%\Programs\Python\Python311
echo %PATH% | findstr /C:%PYTHON_HOME% >nul
if %ERRORLEVEL% == 1 (
    echo %PYTHON_HOME%
    set PATH=%PYTHON_HOME%;%PYTHON_HOME%\Scripts;C:\WINDOWS\system32;C:\WINDOWS
)

if "%1%"=="init" (
    if exist .venv (
        echo Virtual Environment already exists
        call .venv/Scripts/activate.bat
        pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
    ) else (
        echo Install Virtual Environment ...
        python -m venv .venv
        call .venv/Scripts/activate.bat
        pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
    )
    @REM pause>nul
) else if "%1%"=="clear" (
    rmdir /s/q "__pycache__"
    rmdir /s/q "src/__pycache__"
    rmdir /s/q "utils/__pycache__"
    echo. > "data\logs\logging.log"
) else (
    echo Virtual Environment Activation ...
    call .venv/Scripts/activate.bat

    echo Launch the app ...
    python main.py %1 %2 %3 %4 %5 %6 %7 %8 %9
)
