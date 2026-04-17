@echo off
REM Solidify Quick Start Script (Windows)
REM Run this to set up the project

echo.
echo 🚀 Solidify Quick Start
echo ======================

REM Check Python version
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found. Please install Python 3.10+
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo ✅ Python version: %PYTHON_VERSION%

echo.
echo 📦 Setting up backend...
cd backend

REM Create virtual environment
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Copy environment file
if not exist ".env" (
    echo Creating .env file...
    copy .env.example .env
    echo ⚠️  Please edit .env and add your API keys!
)

echo ✅ Backend ready!

echo.
echo 🎨 Setting up frontend...
cd ..\frontend

if not exist "node_modules" (
    echo Installing frontend dependencies...
    call npm install
)

echo ✅ Frontend ready!

echo.
echo ======================
echo 🎉 Setup Complete!
echo.
echo Next steps:
echo 1. Edit backend^.env and add your GEMINI_API_KEY
echo 2. Run backend:  cd backend ^&^& venv\Scripts\activate.bat ^&^& uvicorn main:app --reload
echo 3. Run frontend: cd frontend ^&^& npm run dev
echo 4. Open http://localhost:5173
echo.
echo Happy auditing! 🔐
pause