# Usage: (run Powershell as administrator)
# .\install_windows_agent.ps1 -server <server_ip>

# get ip or hostname of wazuh server from argument
param (
  [string]$server = "127.0.0.1"
)

# Elevating previledge
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" `"$args`"" -Verb RunAs; exit }

# Initialize download client
$WebClient = New-Object System.Net.WebClient

function Remove-ItemSafely {
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(
    Mandatory=$true,
    ValueFromPipeline=$true,
    ValueFromPipelineByPropertyName=$true
  )]
  [String[]]
  $Path ,
  [Switch]
  $Recurse
)

  Process {
    foreach($p in $Path) {
      if(Test-Path $p) {
        Remove-Item $p -Recurse:$Recurse -Force -Confirm:$false
      }
    }
  }
}

function InstallSysmon {
  $InstallPath = "C:\Program Files\Sysmon"
  $ZippedPath = "$InstallPath\Sysmon.zip"
  $ExecutablePath = "$InstallPath\Sysmon64.exe"
  $ConfigPath = "$InstallPath\sysconfig.xml"
  Remove-ItemSafely $InstallPath -Recurse
  New-Item -ItemType "directory" -Path $InstallPath

  $WebClient.DownloadFile("https://download.sysinternals.com/files/Sysmon.zip", $ZippedPath)

  Expand-Archive -LiteralPath $ZippedPath -DestinationPath $InstallPath
  Remove-ItemSafely $ZippedPath

  $WebClient.DownloadFile("https://github.com/t-shield/wazuh/raw/master/install_agent/windows/sysconfig.xml", $ConfigPath)

  Start-Process -NoNewWindow -FilePath $ExecutablePath -Wait -ArgumentList "-accepteula -i `"$ConfigPath`""
}

function InstallWazuhAgent {
  $InstallPath = "C:\Program Files\WazuhAgent"
  $SetupExecutablePath = "$InstallPath\wazuh-agent-4.0.4-1.msi"
  Remove-ItemSafely $InstallPath -Recurse
  New-Item -ItemType "directory" -Path $InstallPath

  $WebClient.DownloadFile("https://packages.wazuh.com/4.x/windows/wazuh-agent-4.0.4-1.msi", $SetupExecutablePath)

  Start-Process msiexec.exe -NoNewWindow -ArgumentList "/i `"$SetupExecutablePath`" WAZUH_MANAGER=`"$server`" WAZUH_REGISTRATION_SERVER=`"$server`"" -Wait
}

InstallSysmon
InstallWazuhAgent

Read-Host -Prompt "Installation finished. Press ENTER to exit..."