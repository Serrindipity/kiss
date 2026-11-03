#requires -Version 5.1
<# Read-only domain inventory. Run with RSAT; -LocalHostChecks examines THIS Windows host. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$OutDirectory,
    [switch]$LocalHostChecks,
    [switch]$EffectivePasswordPolicies,
    [switch]$AllObjectAcls
)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutDirectory) { throw 'Use a new output directory.' }
$output = New-Item -ItemType Directory -Path $OutDirectory
# Evidence may contain directory notes and sensitive permissions: restrict the output folder.
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$acl = Get-Acl -LiteralPath $output.FullName
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $identity.User, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $output.FullName -AclObject $acl
$results = New-Object System.Collections.Generic.List[object]

function Save-Results {
    $document = [ordered]@{
        schema_version = 1; target = $Server; collector_host = $env:COMPUTERNAME
        identity = $identity.Name; updated_at = [DateTime]::UtcNow.ToString('o')
        results = @($results.ToArray())
    }
    $json = ConvertTo-Json -InputObject $document -Depth 16
    $tmp = Join-Path $output.FullName 'results.tmp'
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination (Join-Path $output.FullName 'results.json') -Force
}

function Invoke-Check([string]$Name, [scriptblock]$Action, [string]$Note, [string]$Target = $Server) {
    $record = [ordered]@{
        id = $Name; target = $Target; identity = $identity.Name
        time = [DateTime]::UtcNow.ToString('o'); status = 'completed'
        assessment = 'requires_review'; note = $Note
    }
    try { $record.data = @(& $Action) }
    catch {
        $record.status = 'error'
        if ($_.Exception -is [System.UnauthorizedAccessException] -or
            $_.CategoryInfo.Category -eq 'PermissionDenied') { $record.status = 'access_denied' }
        $record.error = $_.Exception.Message
    }
    $results.Add([pscustomobject]$record)
    Save-Results
    Write-Host ($Name + ': ' + $record.status)
}

function Read-ObjectAcl($Object) {
    $sd = $Object.nTSecurityDescriptor
    if ($null -eq $sd) { throw ('Security descriptor not returned: ' + $Object.DistinguishedName) }
    [pscustomobject]@{
        dn = $Object.DistinguishedName; owner = $sd.Owner
        rules = @($sd.Access | Select-Object @{n='trustee';e={$_.IdentityReference.Value}},
            @{n='rights';e={$_.ActiveDirectoryRights.ToString()}},
            @{n='type';e={$_.AccessControlType.ToString()}}, ObjectType, InheritedObjectType,
            IsInherited, @{n='inheritance';e={$_.InheritanceType.ToString()}})
    }
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $root = Get-ADRootDSE -Server $Server
    $domain = Get-ADDomain -Server $Server
    $base = $root.defaultNamingContext
    $config = $root.configurationNamingContext
} catch {
    $initialError = $_
    Invoke-Check 'ad-initialization' { throw $initialError } 'ActiveDirectory module, connectivity and a working current logon are required.'
    throw
}

Invoke-Check 'domain' {
    $domain | Select-Object DNSRoot, NetBIOSName, DomainSID, DomainMode,
        PDCEmulator, RIDMaster, InfrastructureMaster, DistinguishedName
} 'Domain identity and role holders.'
Invoke-Check 'forest' {
    Get-ADForest -Server $Server | Select-Object Name, ForestMode, Domains, GlobalCatalogs, SchemaMaster, DomainNamingMaster
} 'Forest scope can exceed the engagement scope; inventory only.'
Invoke-Check 'domain-controllers' {
    Get-ADDomainController -Filter * -Server $Server | Select-Object HostName, IPv4Address, Site, IsReadOnly, OperatingSystem
} 'DC inventory; no scans are launched against discovered systems.'
Invoke-Check 'default-password-policy' {
    Get-ADDefaultDomainPasswordPolicy -Server $Server | Select-Object ComplexityEnabled,
        ReversibleEncryptionEnabled, MinPasswordLength, PasswordHistoryCount,
        @{n='MinPasswordAge';e={$_.MinPasswordAge.ToString()}},
        @{n='MaxPasswordAge';e={$_.MaxPasswordAge.ToString()}}, LockoutThreshold,
        @{n='LockoutDuration';e={$_.LockoutDuration.ToString()}},
        @{n='LockoutObservationWindow';e={$_.LockoutObservationWindow.ToString()}}
} 'Effective domain default; fine-grained policies can override it.'
Invoke-Check 'fine-grained-policies' {
    Get-ADFineGrainedPasswordPolicy -Filter * -Server $Server |
        Select-Object Name, Precedence, AppliesTo, MinPasswordLength, ComplexityEnabled,
            ReversibleEncryptionEnabled, PasswordHistoryCount, LockoutThreshold
} 'Policy assignments, not necessarily each user effective policy.'
if ($EffectivePasswordPolicies) {
    Invoke-Check 'effective-password-policies' {
        Get-ADUser -Filter 'Enabled -eq $true' -Server $Server | ForEach-Object {
            $policy = Get-ADUserResultantPasswordPolicy -Identity $_ -Server $Server
            [pscustomobject]@{user=$_.SamAccountName; policy=if ($policy) {$policy.Name} else {'Domain default'}}
        }
    } 'One additional query per enabled user; opt-in for larger domains.'
}
Invoke-Check 'accounts' {
    Get-ADUser -Filter * -Server $Server -Properties Enabled, PasswordLastSet, LastLogonDate,
        PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, AllowReversiblePasswordEncryption,
        TrustedForDelegation, TrustedToAuthForDelegation, AccountNotDelegated, ServicePrincipalNames,
        MemberOf, Description, adminCount |
    Select-Object SamAccountName, DistinguishedName, Enabled, PasswordLastSet, LastLogonDate,
        PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, AllowReversiblePasswordEncryption,
        TrustedForDelegation, TrustedToAuthForDelegation, AccountNotDelegated, ServicePrincipalNames,
        MemberOf, Description, adminCount
} 'Descriptions may contain secrets. LastLogonDate is replicated and approximate; adminCount can be stale.'
Invoke-Check 'privileged-groups' {
    # SID selection avoids English/localized-name assumptions. Includes root-domain EAs if visible in this domain.
    $suffixes = '-(512|518|519|520|525|526|527|544|548|549|550|551|552)$'
    Get-ADGroup -Filter * -Server $Server | Where-Object {$_.SID.Value -match $suffixes} | ForEach-Object {
        $group = $_
        [pscustomobject]@{group=$group.Name; sid=$group.SID.Value
            members=@(Get-ADGroupMember -Identity $group -Recursive -Server $Server |
                Select-Object Name, SamAccountName, ObjectClass, DistinguishedName)}
    }
} 'Recursive membership. Cross-domain resolution failure is an error, not an empty safe group.'
Invoke-Check 'delegation' {
    Get-ADObject -Server $Server -LDAPFilter '(|(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(userAccountControl:1.2.840.113556.1.4.803:=524288))' -Properties sAMAccountName,userAccountControl,msDS-AllowedToDelegateTo,msDS-AllowedToActOnBehalfOfOtherIdentity |
    ForEach-Object {
        $rbcd = $_.'msDS-AllowedToActOnBehalfOfOtherIdentity'
        $sddl = $null
        if ($rbcd -is [byte[]]) {
            $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($rbcd, 0)
            $sddl = $descriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        } elseif ($null -ne $rbcd) {
            $sddl = $rbcd.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        }
        [pscustomobject]@{dn=$_.DistinguishedName; account=$_.sAMAccountName; uac=$_.userAccountControl
            destinations=$_.'msDS-AllowedToDelegateTo'; rbcd_sddl=$sddl}
    }
} 'Normal DC unconstrained delegation is expected. Review destination and modifying principals.'
Invoke-Check 'trusts' {
    Get-ADTrust -Filter * -Server $Server | Select-Object Name, Direction, IntraForest, ForestTransitive,
        SelectiveAuthentication, SIDFilteringForestAware, SIDFilteringQuarantined
} 'Configuration inventory; no cross-trust access is attempted.'
Invoke-Check 'domain-acl' {
    Read-ObjectAcl (Get-ADObject -Identity $base -Server $Server -Properties nTSecurityDescriptor)
} 'Review replication extended rights: 1131f6aa (Get Changes), 1131f6ad (Get Changes All), 89e95b76 (Filtered Set). ACL entries need effective-rights analysis.'
Invoke-Check 'sensitive-object-acls' {
    $filter = if ($AllObjectAcls) {'(objectClass=*)'} else {
        '(|(adminCount=1)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)(objectClass=msDS-GroupManagedServiceAccount))'
    }
    Get-ADObject -SearchBase $base -Server $Server -LDAPFilter $filter -Properties nTSecurityDescriptor |
        ForEach-Object { Read-ObjectAcl $_ }
} 'Preserves allow/deny, inheritance and object GUIDs. Does not label every write ACE exploitable. -AllObjectAcls expands to the entire domain.'
Invoke-Check 'gmsa-readers' {
    Get-ADServiceAccount -Filter * -Server $Server -Properties PrincipalsAllowedToRetrieveManagedPassword |
        Select-Object Name, DistinguishedName, PrincipalsAllowedToRetrieveManagedPassword
} 'Reader inventory only; does not retrieve managed passwords.'
Invoke-Check 'adcs-objects-and-acls' {
    Get-ADObject -SearchBase $config -Server $Server -LDAPFilter '(|(objectClass=pKICertificateTemplate)(objectClass=pKIEnrollmentService))' -Properties nTSecurityDescriptor,dNSHostName,certificateTemplates,pKIExtendedKeyUsage,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-RA-Signature |
    ForEach-Object {
        [pscustomobject]@{dn=$_.DistinguishedName; host=$_.dNSHostName; templates=$_.certificateTemplates
            eku=$_.pKIExtendedKeyUsage; name_flags=$_.'msPKI-Certificate-Name-Flag'
            enrollment_flags=$_.'msPKI-Enrollment-Flag'; signatures=$_.'msPKI-RA-Signature'
            acl=(Read-ObjectAcl $_)}
    }
} 'Enrollment permissions plus template properties. CA runtime policy and HTTP EPA are not established by this query.'
Invoke-Check 'sysvol-netlogon-acls' {
    foreach ($share in @('SYSVOL', 'NETLOGON')) {
        $path = '\\' + $Server + '\' + $share
        $permissions = Get-Acl -LiteralPath $path
        [pscustomobject]@{path=$path; owner=$permissions.Owner
            access=@($permissions.Access | Select-Object IdentityReference, FileSystemRights, AccessControlType, IsInherited)}
    }
} 'Root filesystem ACLs only. Child ACLs and SMB share permissions can differ; no write probes.'

if ($LocalHostChecks) {
    $local = $env:COMPUTERNAME
    Invoke-Check 'local-host-identity' {
        Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain, DomainRole
        Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, LastBootUpTime
    } 'These local checks examine the collector host, which may differ from -Server.' $local
    Invoke-Check 'local-hotfixes' {Get-HotFix | Select-Object HotFixID, InstalledOn, Description} 'Partial servicing inventory; not a complete CVE verdict.' $local
    Invoke-Check 'local-smb-config' {
        Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EncryptData, RejectUnencryptedAccess
    } 'Local server settings.' $local
    Invoke-Check 'local-shares' {
        Get-SmbShare | ForEach-Object {
            [pscustomobject]@{name=$_.Name; path=$_.Path; access=@(Get-SmbShareAccess -Name $_.Name)}
        }
    } 'Share permissions; filesystem permissions also apply.' $local
    Invoke-Check 'local-services' {
        Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, StartName, PathName
    } 'Review Spooler and unexpected services. Running service is not proof of a CVE.' $local
    Invoke-Check 'local-security-settings' {
        $paths = @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',
            'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint')
        foreach ($path in $paths) {
            if (Test-Path -LiteralPath $path) {
                $item = Get-ItemProperty -LiteralPath $path
                [pscustomobject]@{path=$path; values=($item | Select-Object LmCompatibilityLevel, NoLMHash,
                    RunAsPPL, UseLogonCredential, LDAPServerIntegrity, LdapEnforceChannelBinding,
                    RestrictDriverInstallationToAdministrators, NoWarningNoElevationOnInstall, UpdatePromptSettings)}
            } else { [pscustomobject]@{path=$path; state='not_present'} }
        }
    } 'Absent values require OS/default-policy interpretation. Does not test negotiated authentication.' $local
    Invoke-Check 'local-defender' {Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled, AntivirusSignatureLastUpdated} 'Third-party protection may be installed instead.' $local
    Invoke-Check 'local-firewall' {Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction} 'Profile settings; does not evaluate every effective firewall rule.' $local
    Invoke-Check 'local-token-privileges' {
        $text = & whoami.exe /priv /fo csv 2>&1
        if ($LASTEXITCODE -ne 0) { throw ($text -join "`n") }
        $text
    } 'Current token only; not all users rights assignments.' $local
    Invoke-Check 'local-audit-policy' {
        $text = & auditpol.exe /get '/category:*' /r 2>&1
        if ($LASTEXITCODE -ne 0) { throw ($text -join "`n") }
        $text
    } 'Raw effective audit policy CSV; labels depend on Windows language.' $local
}
Write-Host ('Evidence: ' + (Join-Path $output.FullName 'results.json'))
if (@($results | Where-Object {$_.status -in @('error','access_denied')}).Count -gt 0) { exit 1 }
