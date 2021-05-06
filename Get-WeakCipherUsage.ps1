# Get weak cipher usage (RC4 used in Domain environments). useful for On-Prem diagnostics, similar to MDI (cloud app sec) weak cupher usage report.
# Can be highly useful to assess if can move to AES only (see which systems still use RC4), as well as indication for potential Kerberoasting attack (with False Positives, since systems may generate downgrade TGS regardless of this attack).
# By default, queries all Domain Controllers' Security events logs (requires Event Log Readers or equivalent/DA).
# OPTIONAL: Can limit from a certain Time and Date (optional parameters), for shorter execution and avoid query overload in large environments/large Security Logs.
# OPTIONAL: If using an Event Forwarder to log 4769 (Kerberos TGS events) from all DCs - can also specify an Event Forwarding server.
# Comments: 1nTh35h311 (yossis@protonmail.com)

param (
        [cmdletbinding()]
        [string]$EventForwardingServer = $null,
        [datetime]$FromDate,
        [datetime]$FromTime,
        [ValidateSet("CONSOLE+CSV","CONSOLE+CSV+GRID","CONSOLE ONLY")]$Output = "CONSOLE+CSV+GRID"
    )

$CurrentEAP = $ErrorActionPreference
$ErrorActionPreference = "silentlycontinue"

$DCs = (([adsisearcher]'(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))').FindAll() | select -ExpandProperty properties).dnshostname

$FilterDC = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4769)]]</Select>
  </Query>
</QueryList>
'@

$FilterFwdEvents = @'
<QueryList>
  <Query Id="0" Path="ForwardedEvents">
    <Select Path="ForwardedEvents">*</Select>
  </Query>
</QueryList>
'@

if ($FromDate -and $FromTime)
{
[string]$Date = "$($FromDate.Year)-$($FromDate.Month)-$($FromDate.Day)"
[string]$Time = "$($FromTime.Hour):$($FromTime.Minute):$($FromTime.Second)"

$FilterDCFromDateTime = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[TimeCreated[@SystemTime&gt;='$($Date)T$($Time).000Z']]]</Select>
  </Query>
</QueryList>
"@

$FilterFwdEventsFromDateTime = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[TimeCreated[@SystemTime&gt;='$($Date)T$($Time).000Z']]]</Select>
  </Query>
</QueryList>
"@
}

$ReportName = "$(Get-Location)\WeakCipherUsage_$(get-date -Format ddMMyyyyHHmmss).csv"

if (!$EventForwardingServer)
    # query DCs Security event logs directly (default)
    {
        $Events = $DCs | ForEach-Object {
                $DC = $_;
                Write-Host "Fetching events from domain controller $DC..."
                if ($FromDate)
                    {
                        Get-WinEvent -FilterXml $FilterDCFromDateTime -ComputerName $DC
                    }
                else
                    {
                        Get-WinEvent -FilterXml $FilterDC -ComputerName $DC
                    }
            }
    }
else 
    # query an event forwarding log
    {
        Write-Host "Fetching events from Event Forwarder $EventForwardingServer..."
        if ($FromDate)
                    {
                        $Events = Get-WinEvent -FilterXml $FilterFwdEvents -ComputerName $EventForwardingServer
                    }
                else
                    {
                        $Events = Get-WinEvent -FilterXml $FilterFwdEventsFromDateTime -ComputerName $EventForwardingServer
                    }
    }

if (!$Events)
    {
        Write-Warning "No relevant events found. quiting."
        exit
    }

if ($Output -ne "CONSOLE ONLY") {
        $SW = New-Object System.IO.StreamWriter $ReportName
        $sw.AutoFlush = $true

        $sw.WriteLine('UserName,IP,IPv4,Computername,SPNUser,TimeCreated,SPNs,DC')
    }

$Events | foreach {
    If ((([xml]($_.ToXml())).event.eventdata.data)[5].'#text' -eq "0x17") { #RC4
        
        $UserName = (([xml]($_.ToXml())).event.eventdata.data)[0].'#text'
        $IP = ((([xml]($_.ToXml())).event.eventdata.data)[6].'#text')
        
        if ($IP -ne "::1")
            {
                $IP.Split(":") | ForEach-Object {if ([ipaddress]$_) { $IPv4 = $_}}
                $ComputerName = (Resolve-DnsName $IPv4).NameHost
            }
        else
            {
                $IPv4 = "N/A"
                $ComputerName = "localhost"
            }

        $TimeCreated = $_.timecreated
        $DC = $_.MachineName.ToUpper()

        $SPNUser = (([xml]($_.ToXml())).event.eventdata.data)[2].'#text'
        $SPNs = $([adsisearcher]"(samaccountname=$((([xml]($_.ToXml())).event.eventdata.data)[2].'#text'))").FindOne().Properties.serviceprincipalname

        Write-Host "RC4 usage by $UserName from IP $IP (IPv4: $IPv4, Hostname: $ComputerName) at $TimeCreated on Domain Controller $DC." -ForegroundColor Yellow
        Write-Host "SPN user (accessed Service Principal Name): $SPNUser" -ForegroundColor Yellow

        Write-Host "SPNs for $($SPNUser):`n $SPNs`n" -ForegroundColor Cyan

        if ($Output -ne "CONSOLE ONLY") {
                $sw.WriteLine("$UserName,$IP,$IPv4,$Computername,$SPNUser,$TimeCreated,$SPNs,$DC")
            }

        Clear-Variable UserName, IP, IPv4, Computername, SPNUser, TimeCreated, SPNs, DC
    }
}

<# appendix: all relevant ticket encryption values, to modify according to your needs
$Events | foreach {
    Switch ((([xml]($_.ToXml())).event.eventdata.data)[5].'#text')
    {       
        "0x1" {$Val = 'des-cbc-crc'}
        "0x2" {$Val = 'des-cbc-md4'}
        "0x3" {$Val = 'des-cbc-md5'}
        "0x4" {$Val = '[reserved]'}
        "0x5" {$Val = 'des3-cbc-md5'}
        "0x6" {$Val = '[reserved]'}
        "0x7" {$Val = 'des3-cbc-sha1'}
        "0x9" {$Val = 'dsaWithSHA1-CmsOID'}
        "0xa" {$Val = 'md5WithRSAEncryption-CmsOID'}
        "0xb" {$Val = 'sha1WithRSAEncryption-CmsOID'}
        "0xc" {$Val = 'rc2CBC-EnvOID'}
        "0xd" {$Val = 'rsaEncryption-EnvOID'}
        "0xe" {$Val = 'rsaES-OAEP-ENV-OID'}
        "0xf" {$Val = 'des-ede3-cbc-Env-OID'}
        "0x10" {$Val = 'des3-cbc-sha1-kd'}
        "0x11" {$Val = 'aes128-cts-hmac-sha1-96'}
        "0x12" {$Val = 'aes256-cts-hmac-sha1-96'}
        "0x17" {$Val = 'rc4-hmac'}
        "0x18" {$Val = 'rc4-hmac-exp'}
        "0x41" {$Val = 'subkey-keymaterial'}
    }
    $val.ToUpper()
}
#>

# Wrap up
if ($Output -ne "CONSOLE ONLY") {
        Write-Host "Report saved to $ReportName." -ForegroundColor Green

        $sw.Close()
        $sw.Dispose()
    }

Clear-Variable Events

if ($Output -eq "CONSOLE+CSV+GRID")
    {
        Import-Csv $ReportName | Out-GridView -Title "Weak Cipher Usage Report"
    }

$ErrorActionPreference = $CurrentEAP