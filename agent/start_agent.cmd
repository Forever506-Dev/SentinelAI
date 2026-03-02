@echo off
cd /d "%~dp0"
set RUST_LOG=sentinel_agent=debug
echo Starting SentinelAI Agent...
cargo run --release
