#!/usr/bin/env bash
# setup.sh - Automated setup for IT/OT Incident Response System
set -e

echo "=== IT/OT Incident Response System - Setup ==="

# Create required directories
mkdir -p data/alerts data/ot_context config engine ingestion models templates tests

# Set up Python virtual environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Virtual environment created."
fi

source venv/bin/activate

# Install dependencies
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "Dependencies installed."

# Create .env if it doesn't exist
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo ".env file created from .env.example - edit as needed."
fi

# Initialise database
python3 -c "from models.database import init_db; init_db(); print('Database initialised.')"

echo ""
echo "=== Setup Complete ==="
echo "Next steps:"
echo "  1. Edit .env with your settings"
echo "  2. source venv/bin/activate"
echo "  3. python3 simulate.py    # Run simulations"
echo "  4. python3 app.py         # Start the web dashboard"
echo "  5. pytest tests/ -v       # Run all unit tests"
