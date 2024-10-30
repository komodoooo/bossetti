@echo off
reg add "HKEY_CLASSES_ROOT\*\shell\Scan with Bossetti\command" /ve /t REG_SZ /d "\"%APPDATA%\bossetti.exe\" \"%1\"" /f
