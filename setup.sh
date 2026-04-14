# SoliGuard Quick Start Script
# Run this to set up the project

echo "🚀 SoliGuard Quick Start"
echo "======================"

# Check Python version
python_version=$(python --version 2>&1 | grep -oP '\d+\.\d+')
required_version="3.10"

if (( $(echo "$python_version >= $required_version" | bc -l) )); then
    echo "✅ Python version: $python_version"
else
    echo "❌ Python 3.10+ required. Current: $python_version"
    exit 1
fi

# Backend Setup
echo ""
echo "📦 Setting up backend..."
cd backend

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python -m venv venv
fi

# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# source venv/Scripts/activate  # Windows

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Copy environment file
if [ ! -f ".env" ]; then
    echo "Creating .env file..."
    cp .env.example .env
    echo "⚠️  Please edit .env and add your API keys!"
fi

echo "✅ Backend ready!"

# Frontend Setup
echo ""
echo "🎨 Setting up frontend..."
cd ../frontend

if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi

echo "✅ Frontend ready!"

# Summary
echo ""
echo "======================"
echo "🎉 Setup Complete!"
echo ""
echo "Next steps:"
echo "1. Edit backend/.env and add your GEMINI_API_KEY"
echo "2. Run backend:  cd backend && source venv/bin/activate && uvicorn main:app --reload"
echo "3. Run frontend: cd frontend && npm run dev"
echo "4. Open http://localhost:5173"
echo ""
echo "Happy auditing! 🔐"