param([Parameter(Mandatory=$true)][string]$CertsPath)
$ErrorActionPreference = "Stop"
Install-WindowsFeature Web-Server -IncludeManagementTools | Out-Null
Import-Module WebAdministration
$resolvedCerts = (Resolve-Path -LiteralPath $CertsPath).Path
$root = Join-Path $resolvedCerts "root_ca.pem"
if (Test-Path -LiteralPath $root) { Import-Certificate -FilePath $root -CertStoreLocation Cert:\LocalMachine\Root | Out-Null }
Get-Website | Where-Object Name -Like "RadarLab-*" | ForEach-Object { Remove-Website -Name $_.Name }
Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -Like "RadarLab-*" | Remove-Item
$targets = @("target,service_name,owner,criticality")
Get-ChildItem -LiteralPath $resolvedCerts -Filter "*.pfx" | ForEach-Object {
    $hostName = $_.BaseName
    $siteName = "RadarLab-$hostName"
    $sitePath = Join-Path "C:\inetpub\radarlab" $hostName
    New-Item -ItemType Directory -Path $sitePath -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $sitePath "index.html") -Value "Certificate Radar lab: $hostName"
    $cert = Import-PfxCertificate -FilePath $_.FullName -CertStoreLocation Cert:\LocalMachine\My
    $cert.FriendlyName = $siteName
    New-Website -Name $siteName -PhysicalPath $sitePath -Port 80 -HostHeader $hostName | Out-Null
    New-WebBinding -Name $siteName -Protocol https -Port 443 -HostHeader $hostName -SslFlags 1
    $bindingPath = "IIS:\SslBindings\!443!$hostName"
    if (Test-Path $bindingPath) { Remove-Item $bindingPath }
    New-Item $bindingPath -Thumbprint $cert.Thumbprint -SSLFlags 1 | Out-Null
    $targets += "$hostName,$siteName,,medium"
}
New-NetFirewallRule -DisplayName "Certificate Radar HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -ErrorAction SilentlyContinue | Out-Null
$targets += "dead.lab.local,Unreachable service,,medium"
$targets | Set-Content -LiteralPath (Join-Path $PSScriptRoot "targets_windows.csv") -Encoding UTF8
Write-Host "Certificate Radar IIS lab configured."
