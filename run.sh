#!/bin/bash
echo "Installing dependencies..."
pip install -r requirements.txt
echo ""
echo "Starting InsightGuard API..."
echo "  API:    http://localhost:5000"
echo "  Stream: http://localhost:5000/api/stream"
echo "  Sim:    http://localhost:5000/api/events/simulate"
echo ""
PYTHONPATH=$(pwd) python application/app.py
