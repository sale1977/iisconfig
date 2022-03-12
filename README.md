# iisconfig# IIS am Windows Server 2019/2022 Server Core
https://docs.microsoft.com/en-us/iis/manage/remote-administration/remote-administration-for-iis-manager

## Server Core - PowerShell
```
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
```
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name RequiresWindowsCredentials -Value 1 -Type DWORD -Force
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -Value 1 -Force
REG add HKLM\Software\Microsoft\WebManagement\Server /v EnableRemoteManagement /t REG_DWORD /d 1 /f
Restart-Computer -Force
```
### Optional: Port für Remotemanagement ändern
> **Port 8172** is the default port for web management. By default, WMSVC is bound to all unassigned IP addresses on port 8172 using a self-signed certificate (WMSVC only communicates over HTTPS).
```
REG add HKLM\Software\Microsoft\WebManagement\Server /v Port /t REG_DWORD /d 8888 /f
```
> Ändert den Port für das Remotemanagement von 8172 auf 8888 ab.
### Firewall-Regeln für Remote-Management aktivieren
```
Get-NetFirewallRule | ? Displaygroup -eq Windows-Remoteverwaltung | Enable-NetFirewallRule
netsh advfirewall firewall add rule name="IIS Remote Verwaltung" dir=in action=allow service=WMSVC
```
## Security
> https://blog.stueber.de/posts/tls-unter-iis-10-absichern/

### TLS 1.0 und 1.1 deaktivieren in der Kommandozeile
```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v "Enabled" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v "Enabled" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v "Enabled" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v "Enabled" /t REG_DWORD /d 0 /f > nul 2>&1
:: starke Verschlüsselung .NET-Framework erzwingen
reg add HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 /V SchUseStrongCrypto /T REG_DWORD /D 1 /f >NUL 2>&1
reg add HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 /V SchUseStrongCrypto /T REG_DWORD /D 1 /reg:64 /f >NUL 2>&1
```
### Schwache kryptographische Verfahren deaktivieren
```
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
### Script
```
# Disable insecure/weak ciphers.
$insecureCiphers = @(
  'DES 56/56',
  'NULL',
  'RC2 128/128',
  'RC2 40/128',
  'RC2 56/128',
  'RC4 40/128',
  'RC4 56/128',
  'RC4 64/128',
  'RC4 128/128',
  'Triple DES 168'
)
Foreach ($insecureCipher in $insecureCiphers) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
  $key.SetValue('Enabled', 0, 'DWord')
  $key.close()
  Write-Host "Weak cipher $insecureCipher has been disabled."
}
 
# Enable new secure ciphers.
# - RC4: It is recommended to disable RC4, but you may lock out WinXP/IE8 if you enforce this. This is a requirement for FIPS 140-2.
# - 3DES: It is recommended to disable these in near future. This is the last cipher supported by Windows XP.
# - Windows Vista and before 'Triple DES 168' was named 'Triple DES 168/168' per https://support.microsoft.com/en-us/kb/245030
$secureCiphers = @(
  'AES 128/128',
  'AES 256/256'
)
Foreach ($secureCipher in $secureCiphers) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($secureCipher)
  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$secureCipher" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
  $key.close()
  Write-Host "Strong cipher $secureCipher has been enabled."
}
 
# Set hashes configuration.
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
 
$secureHashes = @(
  'SHA',
  'SHA256',
  'SHA384',
  'SHA512'
)
Foreach ($secureHash in $secureHashes) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($secureHash)
  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
  $key.close()
  Write-Host "Hash $secureHash has been enabled."
}
 
# Set KeyExchangeAlgorithms configuration.
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms' -Force | Out-Null
$secureKeyExchangeAlgorithms = @(
  'Diffie-Hellman',
  'ECDH',
  'PKCS'
)
Foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms', $true).CreateSubKey($secureKeyExchangeAlgorithm)
  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$secureKeyExchangeAlgorithm" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
  $key.close()
  Write-Host "KeyExchangeAlgorithm $secureKeyExchangeAlgorithm has been enabled."
}
 
# Microsoft Security Advisory 3174644 - Updated Support for Diffie-Hellman Key Exchange
# https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/3174644
Write-Host 'Configure longer DHE key shares for TLS servers.'
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -name 'ServerMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -name 'ClientMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null
 
# https://support.microsoft.com/en-us/help/3174644/microsoft-security-advisory-updated-support-for-diffie-hellman-key-exc
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -name 'ClientMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null
 
# Set cipher suites order as secure as possible (Enables Perfect Forward Secrecy).
$os = Get-WmiObject -class Win32_OperatingSystem
if ([System.Version]$os.Version -lt [System.Version]'10.0') {
  Write-Host 'Use cipher suites order for Windows 2008/2008R2/2012/2012R2.'
  $cipherSuitesOrder = @(
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
    # Below are the only AEAD ciphers available on Windows 2012R2 and earlier.
    # - RSA certificates need below ciphers, but ECDSA certificates (EV) may not.
    # - We get penalty for not using AEAD suites with RSA certificates.
    'TLS_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA',
    'TLS_RSA_WITH_AES_128_CBC_SHA'
  )
} else {
  Write-Host 'Use cipher suites order for Windows 10/2016 and later.'
  $cipherSuitesOrder = @(
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'
  )
}
$cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
# One user reported this key does not exists on Windows 2012R2. Cannot repro myself on a brand new Windows 2012R2 core machine. Adding this just to be save.
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -ErrorAction SilentlyContinue
New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value $cipherSuitesAsString -PropertyType 'String' -Force | Out-Null
 
# Exchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It
# https://blogs.technet.microsoft.com/exchange/2018/04/02/exchange-server-tls-guidance-part-2-enabling-tls-1-2-and-identifying-clients-not-using-it/
# New IIS functionality to help identify weak TLS usage
# https://cloudblogs.microsoft.com/microsoftsecure/2017/09/07/new-iis-functionality-to-help-identify-weak-tls-usage/
Write-Host 'Enable TLS 1.2 for .NET 3.5 and .NET 4.x'
New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node') {
  New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
}
 
# DefaultSecureProtocols Value	Decimal value  Protocol enabled
# 0x00000008                                8  Enable SSL 2.0 by default
# 0x00000020                               32  Enable SSL 3.0 by default
# 0x00000080                              128  Enable TLS 1.0 by default
# 0x00000200                              512  Enable TLS 1.1 by default
# 0x00000800                             2048  Enable TLS 1.2 by default
$defaultSecureProtocols = @(
  '2048'  # TLS 1.2
)
$defaultSecureProtocolsSum = ($defaultSecureProtocols | Measure-Object -Sum).Sum
 
# Update to enable TLS 1.2 as a default secure protocols in WinHTTP in Windows
# https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in
 
# Verify if hotfix KB3140245 is installed.
$file_version_winhttp_dll = (Get-Item $env:windir\System32\winhttp.dll).VersionInfo | % {("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart,$_.ProductMinorPart,$_.ProductBuildPart,$_.ProductPrivatePart)}
$file_version_webio_dll = (Get-Item $env:windir\System32\Webio.dll).VersionInfo | % {("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart,$_.ProductMinorPart,$_.ProductBuildPart,$_.ProductPrivatePart)}
if ([System.Version]$file_version_winhttp_dll -lt [System.Version]"6.1.7601.23375" -or [System.Version]$file_version_webio_dll -lt [System.Version]"6.1.7601.23375") {
  Write-Host 'WinHTTP: Cannot enable TLS 1.2. Please see https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in for system requirements.'
} else {
  Write-Host 'WinHTTP: Minimum system requirements are met.'
  Write-Host 'WinHTTP: Activate TLS 1.2 only.'
  New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name 'DefaultSecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
  if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node') {
    # WinHttp key seems missing in Windows 2019 for unknown reasons.
    New-Item 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name 'DefaultSecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
  }
}
 
Write-Host 'Windows Internet Explorer: Activate TLS 1.2 only.'
New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'SecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'SecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
```

### Script
```
# Disable Multi-Protocol Unified Hello
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'Multi-Protocol Unified Hello has been disabled.'
 
# Disable PCT 1.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'PCT 1.0 has been disabled.'
 
# Disable SSL 2.0 (PCI Compliance)
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 2.0 has been disabled.'
 
# NOTE: If you disable SSL 3.0 the you may lock out some people still using
# Windows XP with IE6/7. Without SSL 3.0 enabled, there is no protocol available
# for these people to fall back. Safer shopping certifications may require that
# you disable SSLv3.
#
# Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 3.0 has been disabled.'
 
# Disable TLS 1.0 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.0 has been disabled.'
 
# Add and Disable TLS 1.1 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.1 has been disabled.'
 
# Add and Enable TLS 1.2 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.2 has been enabled.'
``` 
# Re-create the ciphers key.
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Force | Out-Null
### Zertifikat vorher in XCA erstellen, exportieren als PKCS#12 Zertifikatskette (*.pfx) und am Webserver importieren
```
$pwd = ConvertTo-SecureString -String "demo" -AsPlainText -Force
Import-PfxCertificate -Password $pwd -FilePath "intranet.test.lab.pfx" -CertStoreLocation Cert:\LocalMachine\My -Exportable # optional if i want the private key to be exportable
```

## HTML-Beispiel
```
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
        </style>
    </head>
    <body>
        <h1><b>Success!</b> The Test virtual host is working.</h1>
        <hr>
        <p><a href="https://www.w3schools.com">Tutorials für WWW unter W3Schools.com</a></p>
    </body>
</html>
``` 

## Webseite erstellen
```
Enter-PSSession -Computer <Server-Name> -Credential <Administrator>
Import-Module WebAdministration
Get-Website -Name 'Default Web Site' | Stop-WebSite
New-WebSite -Name 'Testinstance' -Port 80 -HostHeader www.test.lab -IPAddress "*" -PhysicalPath "C:\inetpub/wwwroot/testlab"
New-WebBinding -Name 'Testinstance' -Port 80 -HostHeader test.lab -IPAddress "*"
Get-Website -Name 'Testinstance' | Start-WebSite
Exit
```
## Windows Client
> **Port 8172** is the default port for web management. By default, WMSVC is bound to all unassigned IP addresses on port 8172 using a self-signed certificate (WMSVC only communicates over HTTPS).
```
Enable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerManagementTools" -All
```
### IIS Manager for Remote Administration 1.2
```
curl -4 -L https://download.microsoft.com/download/2/4/3/24374C5F-95A3-41D5-B1DF-34D98FF610A3/Inetmgr1.2/inetmgr_amd64_de-DE.msi -o C:\Assets\IIS\inetmgr_amd64_de-DE.msi --create-dirs
msiexec -i C:\Assets\IIS\inetmgr_amd64_de-DE.msi /qb /norestart
```
> https://www.microsoft.com/en-us/download/details.aspx?id=41177
```
C:\Windows\System32\inetsrv\InetMgr.exe.
```

https://www.microsoft.com/web/downloads/platform.aspx
> Direct Download: https://go.microsoft.com/fwlink/?LinkId=287166

# HTTP auf HTTPS umleiten
https://www.iis.net/downloads/microsoft/url-rewrite#additionalDownloads
https://techexpert.tips/iis/redirect-http-to-https-iis/
```
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
```
curl -4 -L https://raw.githubusercontent.com/sale1977/iisconfig/main/web.config -o C:\inetpub/wwwroot/web.config --create-dirs
```

Require SSL nicht aktivieren!
