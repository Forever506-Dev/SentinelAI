@echo off
cd /d "%~dp0"
echo Starting SentinelAI Panel on port 3000...
npx next dev --port 3000
