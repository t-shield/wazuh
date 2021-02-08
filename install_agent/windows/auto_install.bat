@REM Automated installation script for windows agent. Please replace SERVER_IP with Wazuh server ip

curl https://raw.githubusercontent.com/t-shield/wazuh/master/install_agent/windows/install_windows_agent.ps1 -o %userprofile%\Downloads\install_windows_agent.ps1
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& '%userprofile%\Downloads\install_windows_agent.ps1' SERVER_IP"
pause