# IIS am Windows Server 2019/2022 Server Core
> https://docs.microsoft.com/en-us/iis/manage/remote-administration/remote-administration-for-iis-manager

## Server Core - PowerShell
`PowerShell`
```PowerShell
Install-WindowsFeature -Name Web-Mgmt-Service -IncludeAllSubFeature
Install-WindowsFeature -Name Web-Server
Install-WindowsFeature -Name Web-Http-Redirect
Install-WindowsFeature -Name Web-Security -IncludeAllSubFeature
Install-WindowsFeature -Name Web-CGI
Install-WindowsFeature -Name Web-Custom-Logging, Web-Log-Libraries,Web-Request-Monitor, Web-Http-Tracing
Install-WindowsFeature -Name Web-Performance -IncludeAllSubFeature
Set-Service WMSVC -StartupType Automatic
Start-Service WMSVC
```
###  Remote Management aktivieren
`PowerShell`
```PowerShell
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name RequiresWindowsCredentials -Value 1 -Type DWORD -Force
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -Value 1 -Force
```
### Optional: Port für Remotemanagement ändern
> **Port 8172** is the default port for web management. By default, WMSVC is bound to all unassigned IP addresses on port 8172 using a self-signed certificate (WMSVC only communicates over HTTPS).
```cmd
REG add HKLM\Software\Microsoft\WebManagement\Server /v Port /t REG_DWORD /d 8888 /f
```
> Ändert den Port für das Remotemanagement von 8172 auf 8888 ab.
### Firewall-Regeln für Remote-Management am Server aktivieren
```PowerShell
Get-NetFirewallRule | ? Displaygroup -eq Windows-Remoteverwaltung | Enable-NetFirewallRule
netsh advfirewall firewall add rule name="IIS Remote Verwaltung" dir=in action=allow service=WMSVC
Restart-Computer -Force
```
## Security
> https://blog.stueber.de/posts/tls-unter-iis-10-absichern/

### TLS 1.0 und 1.1 deaktivieren in der Kommandozeile
`Kommandozeile`
```cmd 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v "Enabled" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v "Enabled" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v "Enabled" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v "Enabled" /t REG_DWORD /d 0 /f > nul 2>&1
:: starke Verschlüsselung .NET-Framework erzwingen
reg add HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 /V SchUseStrongCrypto /T REG_DWORD /D 1 /f >NUL 2>&1
reg add HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 /V SchUseStrongCrypto /T REG_DWORD /D 1 /reg:64 /f >NUL 2>&1
```
### Schwache kryptographische Verfahren am IIS-Webserver deaktivieren
`PowerShell`
```PowerShell
Get-TlsCipherSuite | Format-Table Name 
Disable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
Disable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_GCM_SHA384"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_GCM_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
```
# Root-CA-Zertifikatskette in XCA erstellen, exportieren als PKCS#12 Zertifikatskette (*.pfx) und am Webserver sowie an den Endgeräten importieren
## Server
### Variante Testzertifikat öffentlicher und privater Schlüssel am Server importieren

`1) Kommandozeile`
```cmd
curl -4 -L https://github.com/sale1977/iisconfig/raw/main/intranet.test.lab.pfx -o C:\Assets\IIS\intranet.test.lab.pfx --create-dirs
```
`2) PowerShell`
```PowerShell
$pwd = ConvertTo-SecureString -String "demo" -AsPlainText -Force
$Certificate = "C:\Assets\IIS\intranet.test.lab.pfx"
Import-PfxCertificate -Password $pwd -FilePath $Certificate -CertStoreLocation Cert:\LocalMachine\My -Exportable # optional if i want the private key to be exportable
```
## Client
Importieren Sie das Zertifikat der Vertrauenswürdigen Stammzertifizierungsstelle (Root CA) mit folgenden Syntax. Beachten Sie, dass Sie den Dateinamen je nach Konfiguration verändern müssen:

`1) Kommandozeile`
```cmd
curl -4 -L https://raw.githubusercontent.com/sale1977/iisconfig/main/Scharmer_Root_CA.crt -o C:\Assets\IIS\Scharmer_Root_CA.crt --create-dirs
```
`2) PowerShell`
```PowerShell
Import-Certificate -CertStoreLocation Cert:\LocalMachine\AuthRoot -FilePath C:\Assets\IIS\Scharmer_Root_CA.crt -Confirm:0
```

## HTML-Beispiel
```HTML
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <meta name="description" content="Free tutorials">
        <meta name="keywords" content="HTML, CSS, Test, Domain">
        <meta name="author" content="Alex Scharmer">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Demopage of Test.lab</title>
        <style>
            body {
                display: block;
                margin: 5% 10% 0 10%;
                 }
            h1 {color: grey; font-family: Georgia, serif; font-size: 46px;}
            p {font-family: "Lucida Console", "Courier New", monospace;}
            a:link { color:#0000FF; }
            .center {
              margin: auto;
              width: 50%;
              border: 0px solid #73AD21;
              padding: 15px; }
            .center p {
              margin: 0;
              position: absolute;
              top: 60%;
              left: 50%;
              -ms-transform: translate(-50%, -50%);
              transform: translate(-50%, -50%);
            }
        </style>
    </head>
    <body>
        <h1><b>Success!</b> The Test virtual host is working.</h1>
        <hr>
        <p><a href="https://www.hak-imst.ac.at">Example of a Website</a></p>
        <div class="center">
          <p><iframe width="600" height="450" src="https://www.youtube.com/embed/GC5E8ie2pdM" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe></p>
        </div>

    </body>
</html>
``` 

## Beispiel Webseite erstellen in PowerShell
`PowerShell`
```PowerShell
Enter-PSSession -Computer <Server-Name> -Credential <Administrator>
Import-Module WebAdministration
New-WebBinding -Name "Default Web Site" -Protocol https -port 443 -IPAddress "*"
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | where-Object {$_.subject -match "test.lab" | Select -First 1 }
(Get-WebBinding -Name "Default Web Site" -Port 443 -Protocol "https").AddSslCertificate($cert.Thumbprint, "my")
# $cert = (gci Cert:\LocalMachine\My | where {$_.Subject -match "test.lab"} | Select -First 1).Thumbprint
# New-Item -Path "IIS:\SslBindings\0.0.0.0!443" -Value $cert
# Get-Website -Name 'Default Web Site' | Stop-WebSite
# New-WebSite -Name 'Testinstance' -Port 80 -HostHeader www.test.lab -IPAddress "*" -PhysicalPath "C:\inetpub/wwwroot/testlab"
# New-WebBinding -Name 'Testinstance' -Port 80 -HostHeader test.lab -IPAddress "*"
# Get-Website -Name 'Testinstance' | Start-WebSite
Exit
```
## IIS Remoteverwaltung mit Windows Client
`PowerShell`
```PowerShell
Enable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerManagementTools" -All
```
### Installation IIS Manager for Remote Administration 1.2 am Client
`Kommandozeile`
```
curl -4 -L https://download.microsoft.com/download/2/4/3/24374C5F-95A3-41D5-B1DF-34D98FF610A3/Inetmgr1.2/inetmgr_amd64_de-DE.msi -o C:\Assets\IIS\inetmgr_amd64_de-DE.msi --create-dirs
msiexec -i C:\Assets\IIS\inetmgr_amd64_de-DE.msi /qb /norestart
```
> **Port 8172** is the default port for web management. By default, WMSVC is bound to all unassigned IP addresses on port 8172 using a self-signed 
> https://www.microsoft.com/en-us/download/details.aspx?id=41177
### Starten Sie den Internetinformationsdienste (IIS)-Manager
```
C:\Windows\System32\inetsrv\InetMgr.exe.
```

https://www.microsoft.com/web/downloads/platform.aspx
> Direct Download: https://go.microsoft.com/fwlink/?LinkId=287166

# HTTP auf HTTPS umleiten via Regeldatei
## Installation Module ReWrite am Server
`Kommandozeile`
```
curl -4 -L https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_de-DE.msi -o C:\Assets\IIS\rewrite_amd64_de-DE.msi --create-dirs
msiexec -i C:\Assets\IIS\rewrite_amd64_de-DE.msi /qb /norestart
```
> https://www.iis.net/downloads/microsoft/url-rewrite#additionalDownloads
https://techexpert.tips/iis/redirect-http-to-https-iis/
## Beispieldatei web.config am Server importieren
```XML
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <rewrite>
         <rules>
            <rule name="Redirect to HTTPS" stopProcessing="true">
               <match url="(.*)" />
               <conditions>
                        <add input="{HTTPS}" pattern="^OFF$" />
               </conditions>
               <action type="Redirect" url="https://{HTTP_HOST}{REQUEST_URI}" appendQueryString="false" redirectType="Permanent" />
            </rule>
         </rules>
      </rewrite>
   </system.webServer>
</configuration>
```
## Befehlszeile zum Herunterladen der Rewrite-Konfiguration am Server
`Kommandozeile`
```cmd
curl -4 -L https://raw.githubusercontent.com/sale1977/iisconfig/main/web.config -o C:\inetpub/wwwroot/web.config --create-dirs
```
> Hinweis: Unter Sites -> Default Web Site - SSL Einstellungen die Einstellung *SSL erforderlich* **deaktiviert** lassen.

# Datei hosts auf Client editieren und Website starten
`PowerShell`
```PowerShell
$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`n10.77.0.1`t`tintranet.test.lab" -Force
```
```PowerShell
Start-Process microsoft-edge:https://intranet.test.lab
```
