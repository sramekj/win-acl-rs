@echo off
setlocal enabledelayedexpansion

cd ..

set RUSTFMT_FILE=rustfmt.toml
set BACKUP_FILE=%RUSTFMT_FILE%.bak

echo Backing up %RUSTFMT_FILE%...
copy "%RUSTFMT_FILE%" "%BACKUP_FILE%" >nul

echo Uncommenting settings...
powershell -Command "(Get-Content '%RUSTFMT_FILE%') -replace '^(#\s*)(imports_granularity|group_imports)', '$2' | Set-Content '%RUSTFMT_FILE%'"

echo Running cargo fmt...
cargo +nightly fmt

echo Restoring original %RUSTFMT_FILE%...
move /Y "%BACKUP_FILE%" "%RUSTFMT_FILE%" >nul

echo Done.
pause
