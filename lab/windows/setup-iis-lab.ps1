param([Parameter(Mandatory=$true)][string]$CertsPath)
Install-WindowsFeature Web-Server -IncludeManagementTools
$root = Join-Path $CertsPath "root_ca.pem"
if (Test-Path $root) { Import-Certificate -FilePath $root -CertStoreLocation Cert:\LocalMachine\Root | Out-Null }
New-NetFirewallRule -DisplayName "Certificate Radar HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -ErrorAction SilentlyContinue | Out-Null
Write-Host "IIS lab base configured. Import leaf PFX files and create SNI bindings for the target names."
