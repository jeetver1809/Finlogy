@echo off
echo 🚀 Setting up Personal Finance Tracker...

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed. Please install Node.js (v16 or higher) and try again.
    pause
    exit /b 1
)

echo 📦 Installing dependencies...

REM Install root dependencies
call npm install

REM Install backend dependencies
echo 📦 Installing backend dependencies...
cd backend
call npm install
cd ..

REM Install frontend dependencies
echo 📦 Installing frontend dependencies...
cd frontend
call npm install
cd ..

REM Copy environment files
echo ⚙️ Setting up environment files...

if not exist "backend\.env" (
    copy "backend\.env.example" "backend\.env"
    echo ✅ Created backend\.env from example
    echo ⚠️ Please update the MONGODB_URI and JWT_SECRET in backend\.env
) else (
    echo ✅ Backend .env file already exists
)

if not exist "frontend\.env" (
    copy "frontend\.env.example" "frontend\.env"
    echo ✅ Created frontend\.env from example
) else (
    echo ✅ Frontend .env file already exists
)

echo.
echo 🎉 Setup complete!
echo.
echo 📋 Next steps:
echo 1. Update backend\.env with your MongoDB URI and JWT secret
echo 2. Start MongoDB (if using local installation)
echo 3. Run 'npm run dev' to start both servers
echo.
echo 🌐 The application will be available at:
echo    Frontend: http://localhost:3000
echo    Backend API: http://localhost:5000
echo.
echo 📚 For more information, see README.md
pause
