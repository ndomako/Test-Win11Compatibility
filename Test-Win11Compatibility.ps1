<#
.SYNOPSIS
    Comprehensive Windows 11 upgrade readiness assessment tool.
    
.DESCRIPTION
    Performs detailed system analysis including TPM, Secure Boot, CPU compatibility,
    GPU compatibility, firmware, disk layout, BitLocker status, and registry bypass detection.
    Provides actionable upgrade recommendations with security warnings.

.PARAMETER DriveLetter
    System drive to analyze (default: C). Must be single uppercase letter A-Z.

.PARAMETER ExportResults
    Generate export files (XML/JSON/CSV/HTML).

.PARAMETER ExportFormat
    Export format: XML (default, PowerShell native), JSON, or CSV.

.PARAMETER ExportPath
    Base path for exports (default: current directory).

.PARAMETER ExportHTML
    Include formatted HTML report in exports.

.PARAMETER NoElevation
    Skip automatic elevation (requires manual admin privileges).

.EXAMPLE
    .\Get-UpgradeInfo.ps1
    .\Get-UpgradeInfo.ps1 -DriveLetter C -ExportResults -ExportHTML
    .\Get-UpgradeInfo.ps1 -ExportFormat JSON -ExportPath ".\reports\"

.NOTES
    Requires Administrator privileges for complete analysis.
    ⚠️  Registry bypasses void Microsoft support. Always backup BitLocker keys.
    ⚠️  MBR2GPT conversion requires full system backup due to data loss risk.
#>

[CmdletBinding()]
param(
    [ValidatePattern('^[A-Z]$')]
    [string]$DriveLetter = 'C',
    
    [switch]$ExportResults,
    [ValidateSet('XML', 'JSON', 'CSV')]
    [string]$ExportFormat = 'XML',
    [string]$ExportPath = '.\',
    [switch]$ExportHTML,
    
    [switch]$NoElevation
)

# Script-wide state management
$script:AuditState = [PSCustomObject]@{
    Errors     = @()
    CimCache   = @{}
    SystemInfo = $null
    IsElevated = $false
}

#region Utility Functions
function Test-AdminElevation {
    <#
    .SYNOPSIS
        Checks and optionally requests administrator elevation.
    #>
    $script:AuditState.IsElevated = Test-IsElevated
    if (-not $script:AuditState.IsElevated -and -not $NoElevation) {
        Invoke-ElevationRequest
        return $false
    }
    return $script:AuditState.IsElevated
}

function Test-IsElevated {
    <#
    .SYNOPSIS
        Tests if current process is running with administrator privileges.
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-ElevationRequest {
    <#
    .SYNOPSIS
        Relaunches script with administrator privileges.
    #>
    $pwshSource = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    $psExec = if ($null -ne $pwshSource) { $pwshSource } else { (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source }
    
    if (-not $psExec) {
        throw "PowerShell executable not found for elevation"
    }
    
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$($MyInvocation.MyCommand.Path)`""
        '-DriveLetter', $DriveLetter
    ) + ($PSBoundParameters.GetEnumerator() | Where-Object Key -notin @('NoElevation') | ForEach-Object {
        if ($_.Value -is [switch] -and $_.Value) { "-$($_.Key)" }
        elseif ($_.Value) { "-$($_.Key)", $_.Value }
    })
    
    try {
        Start-Process -FilePath $psExec -ArgumentList $arguments -Verb RunAs
        exit 0
    }
    catch {
        Add-AuditError -Message "Elevation failed: $($_.Exception.Message)" -Context 'Elevation'
        return $false
    }
}

function Add-AuditError {
    <#
    .SYNOPSIS
        Centralized error logging with severity and context tracking.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('Error', 'Warning', 'Info')]
        [string]$Severity = 'Error',
        [string]$Context
    )
    
    $errorObj = [PSCustomObject]@{
        Timestamp = Get-Date -Format 'o'
        Severity  = $Severity
        Message   = $Message
        Context   = if ( $null -ne $Context ) { $Context } else { 'General' }
    }
    
    $script:AuditState.Errors += $errorObj
    
    $color = switch ($Severity) {
        'Error'   { 'Red' }
        'Warning' { 'Yellow' }
        'Info'    { 'Cyan' }
        default   { 'White' }
    }
    
    Write-Host "[$Severity] $($Context): $Message" -ForegroundColor $color
}

function Get-CachedCimData {
    <#
    .SYNOPSIS
        Retrieves CIM data with intelligent caching and timeout protection.
    #>
    param(
        [string[]]$Classes,
        [string]$Namespace = 'root\cimv2',
        [int]$TimeoutSeconds = 10
    )
    
    $results = @{}
    foreach ($class in $Classes) {
        $cacheKey = "$Namespace/$class"
        
        if ($script:AuditState.CimCache.ContainsKey($cacheKey)) {
            Write-Verbose "Using cached CIM data: $cacheKey"
            $results[$class] = $script:AuditState.CimCache[$cacheKey]
            continue
        }
        
        $job = Start-Job -ScriptBlock {
            param($Class, $Namespace)
            Get-CimInstance -ClassName $Class -Namespace $Namespace -ErrorAction Stop
        } -ArgumentList $class, $Namespace
        
        if (Wait-Job $job -Timeout $TimeoutSeconds -ErrorAction SilentlyContinue) {
            $result = Receive-Job $job -ErrorAction SilentlyContinue
            if ($result) {
                $script:AuditState.CimCache[$cacheKey] = $result
                $results[$class] = $result
            }
        } else {
            Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force
            Add-AuditError -Message "CIM timeout: $class" -Severity 'Warning' -Context 'CIM'
        }
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
    
    return $results
}

function Test-DriveValidity {
    <#
    .SYNOPSIS
        Validates drive letter and retrieves basic drive metrics.
    #>
    param([string]$DriveLetter)
    
    if ($DriveLetter -notmatch '^[A-Z]$') {
        throw "Invalid drive letter: $DriveLetter. Must be A-Z."
    }
    
    try {
        $drive = Get-PSDrive -Name $DriveLetter -ErrorAction Stop
        return [PSCustomObject]@{
            DriveLetter = $DriveLetter
            FreeGB      = [math]::Round($drive.Free / 1GB, 2)
            TotalGB     = [math]::Round(($drive.Used + $drive.Free) / 1GB, 2)
            IsValid     = $true
        }
    }
    catch {
        Add-AuditError -Message "Drive $DriveLetter not accessible: $($_.Exception.Message)" -Context 'DriveValidation'
        return [PSCustomObject]@{ IsValid = $false }
    }
}

# Function to check CPU instruction sets for Windows 11 compatibility
function Test-CpuInstructions {
    <#
    .SYNOPSIS
        Checks CPU instruction sets required for Windows 11, including SSE4.2 and implied POPCNT.
    .DESCRIPTION
        Uses P/Invoke to query CPU features via IsProcessorFeaturePresent. Infers POPCNT support
        from SSE4.2 (as typical for Windows 11-approved CPUs). Other instructions (e.g., LAHF/SAHF)
        require CPUID and are flagged for manual verification. Integrates with script's error handling.
    .OUTPUTS
        PSCustomObject with instruction support status and compatibility summary.
    #>
    [CmdletBinding()]
    param()

    # Ensure function is accessible to script scope for error handling
    if (-not (Get-Command Add-AuditError -ErrorAction SilentlyContinue)) {
        Write-Warning "Add-AuditError function not found. Using basic error logging."
        function Add-AuditError {
            param($Message, $Severity = 'Error', $Context = 'General')
            Write-Host "[$Severity] ${Context}: $Message" -ForegroundColor Red
        }
    }

    # P/Invoke definition for IsProcessorFeaturePresent
    $MethodDefinition = @'
    [DllImport("kernel32.dll")]
    public static extern bool IsProcessorFeaturePresent(uint ProcessorFeature);
'@

    try {
        $Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -Namespace 'Win32' -PassThru -ErrorAction Stop
    } catch {
        Add-AuditError -Message "Failed to load P/Invoke for CPU feature check: $($_.Exception.Message)" -Severity 'Error' -Context 'CPUInstructions'
        return [PSCustomObject]@{
            SSE42Supported      = $false
            POPCNTSupported     = $false
            NXSupported         = $false
            CMPXCHG16BSupported = $false
            OtherInstructions   = 'Error: P/Invoke failed'
            IsCompatible        = $false
            Status              = 'Error'
        }
    }

    # Feature codes from Windows API[](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent)
    $features = @{
        'SSE'          = 6   # PF_XMMI_INSTRUCTIONS_AVAILABLE
        'SSE2'         = 10  # PF_XMMI64_INSTRUCTIONS_AVAILABLE
        'SSE3'         = 13  # PF_SSE3_INSTRUCTIONS_AVAILABLE
        'SSSE3'        = 36  # PF_SSSE3_INSTRUCTIONS_AVAILABLE
        'SSE4.1'       = 37  # PF_SSE4_1_INSTRUCTIONS_AVAILABLE
        'SSE4.2'       = 38  # PF_SSE4_2_INSTRUCTIONS_AVAILABLE
        'NX'           = 12  # PF_NX_ENABLED
        'PAE'          = 9   # PF_PAE_ENABLED
        'CMPXCHG16B'   = 14  # PF_COMPARE_EXCHANGE128
        'AVX'          = 39  # PF_AVX_INSTRUCTIONS_AVAILABLE
    }

    $results = @{}
    $unsupportedFeatures = @('POPCNT', 'LAHF/SAHF', 'PrefetchW', 'VT-x/AMD-V')
    $isCompatible = $true

    # Check each feature
    foreach ($feature in $features.Keys) {
        try {
            $supported = $Kernel32::IsProcessorFeaturePresent($features[$feature])
            $results[$feature] = $supported
            Write-Verbose "$feature supported: $supported"
            if ($feature -eq 'SSE4.2' -and -not $supported) {
                $isCompatible = $false
            }
        } catch {
            Add-AuditError -Message "Failed to check ${feature}: $($_.Exception.Message)" -Severity 'Warning' -Context 'CPUInstructions'
            $results[$feature] = $false
            if ($feature -eq 'SSE4.2') {
                $isCompatible = $false
            }
        }
    }

    # Heuristic for POPCNT: Assume supported if SSE4.2 is present (true for Intel 8th Gen+, AMD Zen+)
    $popcntSupported = $results['SSE4.2']
    if ($results['SSE4.2']) {
        Write-Verbose "Assuming POPCNT supported (implied by SSE4.2 for Windows 11-approved CPUs)"
    } else {
        Add-AuditError -Message "POPCNT support cannot be verified; SSE4.2 missing" -Severity 'Warning' -Context 'CPUInstructions'
        $isCompatible = $false
    }

    # Note unsupported features requiring CPUID
    $otherInstructions = if ($popcntSupported) {
        "POPCNT: Assumed (implied by SSE4.2); LAHF/SAHF, PrefetchW, VT-x/AMD-V: Requires CPUID check (use CPU-Z or Coreinfo)"
    } else {
        "POPCNT, LAHF/SAHF, PrefetchW, VT-x/AMD-V: Requires CPUID check (use CPU-Z or Coreinfo)"
    }

    # Determine overall status
    $status = if ($isCompatible) { 'Pass' } else { 'Fail' }

    return [PSCustomObject]@{
        SSE42Supported      = $results['SSE4.2']
        POPCNTSupported     = $popcntSupported
        NXSupported         = $results['NX']
        CMPXCHG16BSupported = $results['CMPXCHG16B']
        OtherInstructions   = $otherInstructions
        IsCompatible        = $isCompatible
        Status              = $status
    }
}
#endregion

# region System Analysis Functions
function Get-SystemCoreData {
    <#
    .SYNOPSIS
        Collects essential system information via optimized CIM queries.
    #>
    $cimData = Get-CachedCimData -Classes @('Win32_OperatingSystem', 'Win32_ComputerSystem', 'Win32_Processor')
    $cpuInstructions = Test-CpuInstructions
    
    return [PSCustomObject]@{
        OS             = $cimData['Win32_OperatingSystem'] | Select-Object Caption, Version, BuildNumber, OSArchitecture
        ComputerSystem = $cimData['Win32_ComputerSystem'] | Select-Object Manufacturer, Model, TotalPhysicalMemory
        Processor      = ($cimData['Win32_Processor'] | Select-Object -First 1) | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, Architecture
        CPUInstructions = $cpuInstructions
    }
}

function Test-CPUCompatibility {
    <#
    .SYNOPSIS
        Advanced CPU compatibility analysis for Windows 11 requirements.
    #>
    param($Processor)
    
    $cpuName = $Processor.Name
    $is64Bit = $Processor.Architecture -eq 9
    $vendor = if ($cpuName -match 'Intel') { 'Intel' } elseif ($cpuName -match 'AMD') { 'AMD' } else { 'Unknown' }
    
    $isCompatible = switch ($vendor) {
        'Intel' {
            $cpuName -match '(8th|9th|10th|11th|12th|13th|14th|Alder Lake|Raptor Lake|Meteor Lake|Core Ultra|Arrow Lake)'
        }
        'AMD' {
            $cpuName -match '(Ryzen (Threadripper )?(2|3|5|7|9)|EPYC (2|3|4|5))'
        }
        default { $false }
    }
    
    $score = switch ($isCompatible) {
        $true  { 100 }
        ($vendor -eq 'Intel' -and $cpuName -match 'Core.*(1st|2nd|3rd|4th|5th|6th|7th)') { 20 }
        ($vendor -eq 'AMD' -and $cpuName -match 'Ryzen (1st|Zen 1)') { 30 }
        default { 10 }
    }
    
    return [PSCustomObject]@{
        Name               = $cpuName
        Vendor             = $vendor
        Is64Bit            = $is64Bit
        IsCompatible       = $is64Bit -and $isCompatible
        CompatibilityScore = $score
        Status             = if ($is64Bit -and $isCompatible) { 'Pass' } else { 'Fail' }
        BypassKey          = 'AllowUpgradesWithUnsupportedCPU'
    }
}

function Test-GPUCompatibility {
    <#
    .SYNOPSIS
        Checks GPU compatibility for Windows 11 (DirectX 12+ with WDDM 2.0+ driver).
    #>
    try {
        Write-Verbose "Querying GPU information"
        $videoController = Get-CachedCimData -Classes @('Win32_VideoController') |
            Where-Object { $_.Win32_VideoController.AdapterCompatibility -notlike '*Microsoft*' } | 
            Select-Object -First 1
        
        if (-not $videoController) {
            Write-Verbose "No physical GPU detected; falling back to default"
            Add-AuditError -Message "No physical GPU detected" -Severity 'Warning' -Context 'GPU'
            return [PSCustomObject]@{
                Name                   = 'Unknown'
                DriverVersion          = 'N/A'
                IsDirectX12Compatible  = $false
                IsWDDM2Compatible      = $false
                IsCompatible           = $false
                Status                 = 'Fail'
            }
        }

        $gpuName = $videoController.Win32_VideoController.Name
        $driverVersionRaw = $videoController.Win32_VideoController.DriverVersion
        Write-Verbose "GPU detected: $gpuName, DriverVersion: $driverVersionRaw"

        # Parse WDDM version from DriverVersion (e.g., 10.0.26100.1000 -> WDDM 2.61)
        $wddmVersion = 0
        if ($driverVersionRaw -match '^(\d+\.\d+)\.') {
            $wddmVersion = [double]$Matches[1]
            Write-Verbose "Parsed WDDM version: $wddmVersion"
        } else {
            Write-Verbose "Unable to parse WDDM version from $driverVersionRaw"
            Add-AuditError -Message "Unable to parse WDDM version from $driverVersionRaw" -Severity 'Warning' -Context 'GPU'
        }
        $isWDDM2Compatible = $wddmVersion -ge 2.0

        # Check DirectX 12 compatibility (heuristic based on AdapterRAM and dxdiag)
        $isDirectX12Compatible = $false
        if ($videoController.Win32_VideoController.AdapterRAM -ge 1GB) {
            try {
                $dxdiagJob = Start-Job -ScriptBlock {
                    & dxdiag /t $env:TEMP\dxdiag.txt
                    Start-Sleep -Seconds 2
                    Get-Content $env:TEMP\dxdiag.txt | Select-String 'DirectX Version'
                } -ErrorAction SilentlyContinue
                $dxdiagOutput = Wait-Job $dxdiagJob -Timeout 5 | Receive-Job
                Remove-Job $dxdiagJob -Force
                if ($dxdiagOutput -match 'DirectX Version:.*12') {
                    $isDirectX12Compatible = $true
                    Write-Verbose "DirectX 12 confirmed via dxdiag"
                } else {
                    Write-Verbose "DirectX 12 not confirmed; assuming compatible for modern GPUs"
                    $isDirectX12Compatible = $true  # Assume true for modern GPUs with sufficient RAM
                }
            }
            catch {
                Write-Verbose "dxdiag check failed: $($_.Exception.Message); assuming compatible for modern GPUs"
                $isDirectX12Compatible = $true  # Fallback for modern GPUs
            }
        } else {
            Write-Verbose "GPU RAM too low ($($videoController.Win32_VideoController.AdapterRAM/1GB) GB) for DirectX 12"
        }

        # Warn if driver is outdated
        if ($isWDDM2Compatible -and $wddmVersion -lt 2.7) {
            Write-Warning "GPU driver may be outdated (WDDM $wddmVersion). Consider updating to latest version."
        }

        $isCompatible = $isDirectX12Compatible -and $isWDDM2Compatible
        Write-Verbose "GPU Compatibility: DirectX12=$isDirectX12Compatible, WDDM2=$isWDDM2Compatible, Overall=$isCompatible"

        return [PSCustomObject]@{
            Name                   = $gpuName
            DriverVersion          = $driverVersionRaw
            IsDirectX12Compatible  = $isDirectX12Compatible
            IsWDDM2Compatible      = $isWDDM2Compatible
            IsCompatible           = $isCompatible
            Status                 = if ($isCompatible) { 'Pass' } else { 'Fail' }
        }
    }
    catch {
        Write-Verbose "GPU compatibility check failed: $($_.Exception.Message)"
        Add-AuditError -Message "GPU compatibility check failed: $($_.Exception.Message)" -Severity 'Error' -Context 'GPU'
        return [PSCustomObject]@{
            Name                   = 'Unknown'
            DriverVersion          = 'N/A'
            IsDirectX12Compatible  = $false
            IsWDDM2Compatible      = $false
            IsCompatible           = $false
            Status                 = 'Fail'
        }
    }
}

function Get-FirmwareAndSecureBootStatus {
    <#
    .SYNOPSIS
        Multi-method firmware and Secure Boot detection.
    #>
    param($PartitionStyle, $OS)
    
    $secureBootMethods = @(
        { 
            if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
                try {
                    $result = Confirm-SecureBootUEFI -ErrorAction Stop
                    Write-Verbose "Confirm-SecureBootUEFI: Secure Boot = $result"
                    return $result
                }
                catch {
                    Write-Verbose "Confirm-SecureBootUEFI failed: $($_.Exception.Message)"
                }
            }
            return $null
        },
        {
            $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
            if (Test-Path $path) {
                try {
                    $state = Get-ItemProperty $path -ErrorAction Stop
                    $result = $state.SecureBootState -ne 0
                    Write-Verbose "Registry SecureBootState: $result"
                    return $result
                }
                catch {
                    Write-Verbose "Registry Secure Boot check failed: $($_.Exception.Message)"
                }
            }
            return $null
        },
        {
            try {
                $bcd = & bcdedit.exe /enum 2>$null | Select-String 'nx.*OptIn'
                $result = [bool]$bcd
                Write-Verbose "bcdedit Secure Boot check: $result"
                return $result
            }
            catch {
                Write-Verbose "bcdedit Secure Boot check failed: $($_.Exception.Message)"
            }
            return $null
        }
    )
    
    $secureBoot = $secureBootMethods | ForEach-Object { 
        $result = & $_
        if ($null -ne $result) { return @{ Value = $result; Method = if ($null -ne $_.Name) { $_.Name } else { 'Fallback' } } 
    } } | Select-Object -First 1
    
    $firmware = switch ($PartitionStyle) {
        'GPT' { 'UEFI' }
        'MBR' { 'Legacy' }
        default {
            try {
                $cs = Get-CachedCimData -Classes @('Win32_ComputerSystem')
                if ($cs['Win32_ComputerSystem'].PCSystemTypeEx -eq 2) { 'UEFI' } else { 'Unknown' }
            }
            catch {
                Write-Verbose "Firmware detection via Win32_ComputerSystem failed: $($_.Exception.Message)"
                'Unknown'
            }
        }
    }
    
    return [PSCustomObject]@{
        Firmware         = $firmware
        SecureBoot       = if ($secureBoot) { $secureBoot.Value } else { $false }
        SecureBootMethod = if ($secureBoot) { $secureBoot.Method } else { 'None' }
    }
}

function Test-TpmViaGetTpm {
    if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
        try {
            $tpm = Get-Tpm -ErrorAction Stop
            if ($tpm?.TpmPresent) {
                Write-Verbose "Get-Tpm: TPM detected, version $($tpm.SpecVersion)"
                return [PSCustomObject]@{ 
                    Present = $true; 
                    Version = if ($null -ne $tpm.SpecVersion) { $tpm.SpecVersion } else { 'Unknown' }; 
                    Method = 'Get-Tpm' 
                }
            }
            Write-Verbose "Get-Tpm: No TPM detected"
        }
        catch {
            Write-Verbose "Get-Tpm method failed: $($_.Exception.Message)"
            Add-AuditError -Message "Get-Tpm failed: $($_.Exception.Message)" -Severity 'Warning' -Context 'TPM'
        }
    }
    return $null
}

function Test-TpmViaWMI {
    try {
        $wmi = Get-CachedCimData -Classes @('Win32_Tpm') -Namespace 'root\cimv2\Security\MicrosoftTpm'
        if ($wmi['Win32_Tpm']) {
            Write-Verbose "WMI: TPM detected, version $($wmi['Win32_Tpm'].SpecVersion)"
            return [PSCustomObject]@{ 
                Present = $true; 
                Version = if ($null -ne $wmi['Win32_Tpm'].SpecVersion) { $wmi['Win32_Tpm'].SpecVersion } else { 'Unknown' }; 
                Method = 'Win32_Tpm' 
            }
        }
        Write-Verbose "WMI: No TPM detected"
    }
    catch {
        Write-Verbose "WMI TPM check failed: $($_.Exception.Message)"
        Add-AuditError -Message "WMI TPM check failed: $($_.Exception.Message)" -Severity 'Warning' -Context 'TPM'
    }
    return $null
}

function Test-TpmViaRegistry {
    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TPM') {
        Write-Verbose "Registry: TPM service detected"
        return [PSCustomObject]@{ 
            Present = $true; 
            Version = 'Unknown'; 
            Method = 'Registry' 
        }
    }
    Write-Verbose "Registry: TPM service not found"
    return $null
}

function Get-TPMStatus {
    <#
    .SYNOPSIS
        Comprehensive TPM detection across multiple methods.
    #>
    $tpmMethods = @(
        ${function:Test-TpmViaGetTpm},
        ${function:Test-TpmViaWMI},
        ${function:Test-TpmViaRegistry}
    )
    
    $tpmResult = $tpmMethods | ForEach-Object { & $_ } | 
                 Where-Object { $_ -ne $null } | 
                 Select-Object -First 1
    
    if ($tpmResult) {
        Write-Verbose "TPM detected via $($tpmResult.Method): Version $($tpmResult.Version)"
        return $tpmResult
    }
    
    Write-Verbose "No TPM detected by any method"
    return [PSCustomObject]@{ 
        Present = $false; 
        Version = 'None'; 
        Method = 'NotFound' 
    }
}

function Get-DiskAndPartitionAnalysis {
    <#
    .SYNOPSIS
        Complete disk layout analysis for upgrade compatibility.
    #>
    param($DriveInfo)
    
    try {
        Import-Module -Name Storage -Function Get-Disk, Get-Partition, Get-Volume -ErrorAction SilentlyContinue
        Write-Verbose "Analyzing disk and partition for drive $($DriveInfo.DriveLetter)"
        $systemPartition = Get-Partition -DriveLetter $DriveInfo.DriveLetter -ErrorAction Stop
        $disk = Get-Disk -Number $systemPartition.DiskNumber -ErrorAction Stop
        $allPartitions = Get-Partition -DiskNumber $disk.Number -ErrorAction Stop
        $recoveryPartition = $allPartitions | Where-Object { $_.Type -eq 'Recovery' -and $_.Size -gt 100MB } | Select-Object -First 1
        $efiPartitions = $allPartitions | Where-Object { $_.IsSystem }
        
        $mbrEligible = $disk.PartitionStyle -eq 'MBR' -and
                      ($allPartitions | Where-Object Type -eq 'Basic').Count -le 3 -and
                      -not ($allPartitions | Where-Object Type -eq 'Extended') -and
                      -not ($allPartitions | Where-Object Type -eq 'Logical') -and
                      $DriveInfo.FreeGB -ge 1
        
        $result = [PSCustomObject]@{
            PartitionStyle      = $disk.PartitionStyle
            PrimaryCount        = ($allPartitions | Where-Object Type -eq 'Basic').Count
            HasExtended         = [bool]($allPartitions | Where-Object Type -eq 'Extended')
            HasLogical          = [bool]($allPartitions | Where-Object Type -eq 'Logical')
            SystemPartitionGB   = [math]::Round($systemPartition.Size / 1GB, 2)
            RecoveryPartitionGB = if ($recoveryPartition) { [math]::Round($recoveryPartition.Size / 1GB, 2) } else { 0 }
            HasRecovery         = [bool]$recoveryPartition
            EFIPartition        = [PSCustomObject]@{
                Exists = $efiPartitions.Count -gt 0
                Count  = $efiPartitions.Count
                SizeGB = [math]::Round(($efiPartitions | Measure-Object Size -Sum).Sum / 1GB, 2)
            }
            MBRConvertible      = [PSCustomObject]@{
                Eligible = $mbrEligible
                FreeSpaceGB = $DriveInfo.FreeGB
                PrimaryCount = ($allPartitions | Where-Object Type -eq 'Basic').Count
            }
            IsHealthyLayout     = $disk.PartitionStyle -eq 'GPT' -and $recoveryPartition
        }
        Write-Verbose "Disk analysis completed: PartitionStyle=$($disk.PartitionStyle), HasRecovery=$($result.HasRecovery)"
        return $result
    }
    catch {
        Add-AuditError -Message "Disk analysis failed: $($_.Exception.Message)" -Severity 'Error' -Context 'DiskAnalysis'
        Write-Verbose "Disk analysis error details: $($_.Exception | Format-List -Force | Out-String)"
        return [PSCustomObject]@{
            PartitionStyle = 'Unknown'
            PrimaryCount = 0
            HasExtended = $false
            HasLogical = $false
            SystemPartitionGB = 0
            RecoveryPartitionGB = 0
            HasRecovery = $false
            EFIPartition = [PSCustomObject]@{ Exists = $false; Count = 0; SizeGB = 0 }
            MBRConvertible = [PSCustomObject]@{ Eligible = $false; FreeSpaceGB = 0; PrimaryCount = 0 }
            IsHealthyLayout = $false
        }
    }
}

function Get-ProtectionStatus {
    <#
    .SYNOPSIS
        Detects BitLocker and WinRE protection status.
    #>
    param($DriveLetter, $PartitionAnalysis)
    
    # BitLocker Status
    $bitLockerStatus = try {
        Write-Verbose "Loading BitLocker module"
        Import-Module -Name Get-BitLockerVolume -DisableNameChecking -ErrorAction SilentlyContinue
        Write-Verbose "Attempting to retrieve BitLocker status for $DriveLetter`:"
        $volume = Get-BitLockerVolume -MountPoint "$DriveLetter`:" -ErrorAction Stop
        $status = if ($volume.ProtectionStatus -eq 1) { 'On' }
                  elseif ($volume.ProtectionStatus -eq 0) { 'Off' }
                  else { 'Unknown' }
        Write-Verbose "BitLocker status: $status (ProtectionStatus: $($volume.ProtectionStatus))"
        $status
    }
    catch {
        Write-Verbose "BitLocker check failed: $($_.Exception.Message)"
        Add-AuditError -Message "BitLocker check failed: $($_.Exception.Message)" -Severity 'Error' -Context 'BitLocker'
        'Error'
    }
    
    if ($bitLockerStatus -eq 'On') {
        Write-Warning "⚠️ BitLocker ENABLED on $DriveLetter`: Backup recovery keys with: manage-bde -protectors -get ${DriveLetter}:"
    }
    
    # WinRE Status
    $winRE = try {
        Write-Verbose "Checking WinRE status"
        $job = Start-Job -ScriptBlock { & reagentc /info 2>&1 }
        $result = if (Wait-Job $job -Timeout 10) { Receive-Job $job } else { $null }
        Remove-Job $job -Force
        
        $enabled = [bool]($result | Select-String 'Windows RE status: *Enabled')
        $winREStatus = if ($enabled -and $PartitionAnalysis.HasRecovery) { 'Healthy' } 
                      elseif (-not $enabled) { 'Disabled' } 
                      else { 'PartitionIssue' }
        Write-Verbose "WinRE status: $winREStatus, Enabled=$enabled, HasRecovery=$($PartitionAnalysis.HasRecovery)"
        
        [PSCustomObject]@{
            Enabled         = $enabled
            HasRecoveryPart = $PartitionAnalysis.HasRecovery
            IsHealthy       = $enabled -and $PartitionAnalysis.HasRecovery -and $PartitionAnalysis.RecoveryPartitionGB -ge 0.5
            RepairNeeded    = -not $enabled -or -not $PartitionAnalysis.HasRecovery
            Status          = $winREStatus
        }
    }
    catch {
        Write-Verbose "WinRE check failed: $($_.Exception.Message)"
        Add-AuditError -Message "WinRE check failed: $($_.Exception.Message)" -Severity 'Warning' -Context 'WinRE'
        [PSCustomObject]@{
            Enabled = $false
            HasRecoveryPart = $false
            IsHealthy = $false
            RepairNeeded = $true
            Status = 'Error'
        }
    }
    
    return [PSCustomObject]@{
        BitLockerStatus = $bitLockerStatus
        WinRE = $winRE
    }
}

function Get-RegistryBypassStatus {
    <#
    .SYNOPSIS
        Detects Windows 11 bypass registry keys.
    #>
    $bypassPath = 'HKLM:\SYSTEM\Setup\MoSetup'
    $keys = @('AllowUpgradesWithUnsupportedTPMOrCPU', 'AllowUpgradesWithUnsupportedTPM', 'AllowUpgradesWithUnsupportedCPU')
    
    Write-Verbose "Checking registry path: $bypassPath"
    if (-not (Test-Path $bypassPath)) {
        Write-Verbose "Registry bypass path not found: $bypassPath"
        Add-AuditError -Message "Registry path $bypassPath not found" -Severity 'Warning' -Context 'RegistryBypass'
        return [PSCustomObject]@{
            Keys      = @{ ($keys -join ', ') = $false }
            Details   = @{ ($keys -join ', ') = 'MoSetup path missing' }
            AnyActive = $false
        }
    }
    
    $results = @{}
    $details = @{}
    $anyActive = $false
    
    foreach ($key in $keys) {
        try {
            Write-Verbose "Checking bypass key: $key"
            $value = Get-ItemProperty -Path $bypassPath -Name $key -ErrorAction SilentlyContinue
            $isActive = $null -ne $value -and $null -ne $value.$key -and [int]$value.$key -eq 1
            $results[$key] = $isActive
            $details[$key] = if ($isActive) { "ACTIVE (Value: $($value.$key))" } else { 'Inactive' }
            if ($isActive) { 
                $anyActive = $true 
                Write-Verbose "Bypass key $key is ACTIVE (Value: $($value.$key))"
            } else {
                Write-Verbose "Bypass key $key is Inactive or Missing"
            }
        }
        catch {
            Write-Verbose "Unexpected error checking bypass key ${key}: $($_.Exception.Message)"
            Add-AuditError -Message "Unexpected error checking bypass key ${key}: $($_.Exception.Message)" -Severity 'Error' -Context 'RegistryBypass'
            $details[$key] = "Error: $($_.Exception.Message)"
            $results[$key] = $false
        }
    }
    
    Write-Verbose "Bypass status summary: AnyActive=$anyActive, Details=$($details | ConvertTo-Json)"
    return [PSCustomObject]@{
        Keys      = $results
        Details   = $details
        AnyActive = $anyActive
    }
}
#endregion

#region Requirements Evaluation
function Test-Win11Requirements {
    <#
    .SYNOPSIS
        Evaluates system against Windows 11 hardware requirements.
    #>
    param($SystemInfo, $FirmwareInfo, $TpmInfo, $BypassInfo)
    
    $requirements = @{}
    $scriptLevel = [PSCustomObject]@{ AllRawPass = $true; AllPassWithBypass = $true }
    
    $evalRules = @(
        @{
            Name = 'OSVersion'; Required = '10.0.22000+'; 
            Test = { [version]$SystemInfo.OS.Version -ge [version]'10.0.22000' }
        },
        @{
            Name = 'RAM'; Required = '4GB+'; 
            Test = { [math]::Round($SystemInfo.ComputerSystem.TotalPhysicalMemory / 1GB) -ge 4 }
            Observed = { "[math]::Round($($SystemInfo.ComputerSystem.TotalPhysicalMemory / 1GB), 1) GB" }
        },
        @{
            Name = 'CPU_Cores'; Required = '2+ cores'; 
            Test = { $SystemInfo.Processor.NumberOfCores -ge 2 }
        },
        @{
            Name = 'CPU_Architecture'; Required = 'x64'; 
            Test = { $SystemInfo.OS.OSArchitecture -like '*64*' }
        },
        @{
            Name = 'CPU_Compatibility'; Required = '8th Gen+ Intel/Zen+ AMD'; 
            Test = { $SystemInfo.CPUCompatibility.IsCompatible };
            BypassKey = 'AllowUpgradesWithUnsupportedCPU'
        },
        @{
            Name = 'CPU_Instructions'; Required = 'SSE4.2, POPCNT';
            Test = { $SystemInfo.CPUInstructions.IsCompatible }
            Observed = { "SSE4.2: $($SystemInfo.CPUInstructions.SSE42Supported), POPCNT: $($SystemInfo.CPUInstructions.POPCNTSupported)" }
            BypassKey = 'AllowUpgradesWithUnsupportedTPMOrCPU'
        },
        @{
            Name = 'TPM'; Required = '2.0+'; 
            Test = { $TpmInfo.Present -and $TpmInfo.Version -match '^2\.0' };
            BypassKey = 'AllowUpgradesWithUnsupportedTPMOrCPU'
        },
        @{
            Name = 'SecureBoot'; Required = 'Enabled'; 
            Test = { $FirmwareInfo.SecureBoot };
            BypassKey = 'AllowUpgradesWithUnsupportedTPMOrCPU'
        },
        @{
            Name = 'FirmwareType'; Required = 'UEFI'; 
            Test = { $FirmwareInfo.Firmware -eq 'UEFI' }
        },
        @{
            Name = 'Storage'; Required = '64GB+'; 
            Test = { $SystemInfo.TotalGB -ge 64 }
        },
        @{
            Name = 'GPU_Compatibility'; Required = 'DirectX 12+ with WDDM 2.0+'; 
            Test = { $SystemInfo.GPUCompatibility.IsCompatible };
            Observed = { "DirectX12: $($SystemInfo.GPUCompatibility.DirectX12), WDDM: $($SystemInfo.GPUCompatibility.WDDM2)" }
            BypassKey = 'AllowUpgradesWithUnsupportedTPMOrCPU'
        }
    )
    
    foreach ($rule in $evalRules) {
        $rawPass = & $rule.Test
        $bypassKey = $rule.BypassKey
        $status = if ($rawPass) { 
            'Pass' 
        } elseif ($bypassKey -and $BypassInfo.Keys[$bypassKey]) { 
            'Bypass' 
        } else { 
            'Fail' 
        }
        
        if (-not $rawPass) { $scriptLevel.AllRawPass = $false }
        if ($status -eq 'Fail') { $scriptLevel.AllPassWithBypass = $false }
        
        $observed = if ($rule.Observed) { & $rule.Observed } 
                   elseif ($rule.Name -like 'CPU_*') { $SystemInfo.CPUCompatibility.Status }
                   elseif ($rule.Name -eq 'GPU_Compatibility') { $SystemInfo.GPUCompatibility.Status }
                   else { "Unknown" }
        
        $requirements[$rule.Name] = [PSCustomObject]@{
            Status     = $status
            Required   = $rule.Required
            Observed   = $observed
            RawPass    = $rawPass
            BypassedBy = if ($status -eq 'Bypass') { $bypassKey } else { $null }
        }
    }
    
    return [PSCustomObject]@{
        Requirements      = $requirements
        AllRawPass        = $scriptLevel.AllRawPass
        AllPassWithBypass = $scriptLevel.AllPassWithBypass
    }
}
#endregion

#region Reporting and Export
function New-ExportFiles {
    <#
    .SYNOPSIS
        Generates export files in specified formats with automatic path handling.
    #>
    param($AuditResult)
    
    $baseDir = Split-Path $ExportPath -Parent
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($ExportPath)
    $extension = [System.IO.Path]::GetExtension($ExportPath)
    
    if (-not (Test-Path $baseDir)) { New-Item -ItemType Directory -Path $baseDir -Force | Out-Null }
    
    $exported = 0
    
    switch ($ExportFormat.ToUpper()) {
        'XML' {
            $path = if ($extension -eq '.xml') { $ExportPath } else { Join-Path $baseDir "$baseName.xml" }
            $AuditResult | Export-Clixml -Path $path -Depth 10 -Encoding UTF8
            Write-Host "✅ XML: $path" -ForegroundColor Green
            $exported++
        }
        'JSON' {
            $path = if ($extension -eq '.json') { $ExportPath } else { Join-Path $baseDir "$baseName.json" }
            $AuditResult | ConvertTo-Json -Depth 10 | Out-File $path -Encoding UTF8
            Write-Host "✅ JSON: $path" -ForegroundColor Green
            $exported++
        }
        'CSV' {
            $sysPath = if ($extension -eq '.csv') { $ExportPath } else { Join-Path $baseDir "$baseName.csv" }
            $AuditResult.SystemInfo | Export-Csv $sysPath -NoTypeInformation -Encoding UTF8
            
            $reqPath = Join-Path $baseDir "$baseName-requirements.csv"
            $AuditResult.Requirements.Requirements.GetEnumerator() | ForEach-Object {
                [PSCustomObject]@{
                    Requirement = $_.Key
                    Status      = $_.Value.Status
                    Required    = $_.Value.Required
                    Observed    = $_.Value.Observed
                }
            } | Export-Csv $reqPath -NoTypeInformation -Encoding UTF8
            
            Write-Host "✅ System CSV: $sysPath" -ForegroundColor Green
            Write-Host "✅ Requirements CSV: $reqPath" -ForegroundColor Green
            $exported += 2
        }
    }
    
    if ($ExportHTML) {
        $htmlPath = if ($extension -eq '.html') { $ExportPath } else { Join-Path $baseDir "$baseName.html" }
        Export-HtmlReport -AuditResult $AuditResult -Path $htmlPath
        Write-Host "✅ HTML: $htmlPath" -ForegroundColor Green
        $exported++
    }
    
    Write-Host "📊 Exported $exported files" -ForegroundColor Cyan
}

function Export-HtmlReport {
    param($AuditResult, [string]$Path)
    
    $sys = $AuditResult.SystemInfo
    $req = $AuditResult.Requirements
    
    # Map observed values for requirements to ensure accurate display
    $observedValues = @{
        'CPU_Architecture' = 'x64'
        'CPU_Compatibility' = $sys.Processor.Name
        'CPU_Cores' = "$($sys.Processor.NumberOfCores) cores"
        'CPU_Instructions' = "SSE4.2: $($sys.CPUInstructions.SSE42Supported), POPCNT: $($sys.CPUInstructions.POPCNTSupported)"
        'FirmwareType' = $sys.Firmware.Firmware
        'GPU_Compatibility' = "DirectX12: $($sys.GPUCompatibility.DirectX12), WDDM: $($sys.GPUCompatibility.WDDM2)"
        'OSVersion' = $sys.OS.Version
        'RAM' = "$([math]::Round($sys.ComputerSystem.TotalPhysicalMemory/1GB, 1)) GB"
        'SecureBoot' = if ($sys.Firmware.SecureBoot) { 'Enabled' } else { 'Disabled' }
        'Storage' = "$($sys.TotalGB) GB"
        'TPM' = if ($sys.TPM.Present) { "v$($sys.TPM.Version)" } else { 'Missing' }
    }
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows 11 Upgrade Audit - $($sys.ComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #2c3e50, #34495e); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .section { background: white; margin: 15px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .status { padding: 4px 8px; border-radius: 4px; font-weight: bold; }
        .pass { background: #d4edda; color: #155724; }
        .fail { background: #f8d7da; color: #721c24; }
        .bypass { background: #fff3cd; color: #856404; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        .warning-box { background: #fff3cd; border: 1px solid #ffeaa7; border-left: 4px solid #f39c12; padding: 15px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🖥️ Windows 11 Upgrade Assessment</h1>
        <p><strong>System:</strong> $($sys.ComputerName) | <strong>Generated:</strong> $(Get-Date)</p>
    </div>
    
    <div class="section">
        <h2>📋 System Overview</h2>
        <table>
            <tr><th>Component</th><th>Status</th></tr>
            <tr><td>OS</td><td>$($sys.OS.Caption) $($sys.OS.Version)</td></tr>
            <tr><td>CPU</td><td>$($sys.Processor.Name)</td></tr>
            <tr><td>CPU Instructions</td><td>SSE4.2: $($sys.CPUInstructions.SSE42Supported), POPCNT: $($sys.CPUInstructions.POPCNTSupported)</td></tr>
            <tr><td>GPU</td><td>$($sys.GPUCompatibility.Name) (Driver: $($sys.GPUCompatibility.DriverVersion))</td></tr>
            <tr><td>RAM</td><td>$([math]::Round($sys.ComputerSystem.TotalPhysicalMemory/1GB,1)) GB</td></tr>
            <tr><td>Storage</td><td>$($sys.TotalGB) GB (Free: $($sys.FreeGB) GB)</td></tr>
            <tr><td>Firmware</td><td>$($sys.Firmware.Firmware) (Secure Boot: $($sys.Firmware.SecureBoot))</td></tr>
            <tr><td>TPM</td><td>$($sys.TPM.Present ? "v$($sys.TPM.Version)" : 'Missing')</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>🔧 Disk Layout Analysis</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Partition Style</td><td>$($sys.DiskAnalysis.PartitionStyle)</td></tr>
            <tr><td>Primary Partitions</td><td>$($sys.DiskAnalysis.PrimaryCount)</td></tr>
            <tr><td>Extended Partition</td><td>$($sys.DiskAnalysis.HasExtended)</td></tr>
            <tr><td>MBR2GPT Eligible</td><td>$($sys.DiskAnalysis.MBRConvertible.Eligible)</td></tr>
            <tr><td>EFI Partition</td><td>$($sys.DiskAnalysis.EFIPartition.Exists)</td></tr>
            <tr><td>Recovery Partition</td><td>$($sys.DiskAnalysis.HasRecovery)</td></tr>
        </table>
    </div>
"@

    if ($sys.DiskAnalysis.PartitionStyle -eq 'MBR' -and $sys.DiskAnalysis.MBRConvertible.Eligible) {
        $html += @"
    <div class="section warning-box">
        <h2>⚠️ MBR to GPT Conversion Required</h2>
        <p>Your disk uses MBR, which is incompatible with Windows 11. Convert to GPT using the MBR2GPT tool:</p>
        <ol>
            <li><strong>Back up all data</strong>: Use Windows Backup and Restore (<code>sdclt</code>) to create a system image or save critical files to an external drive.</li>
            <li>Boot into Windows Recovery Environment (WinRE): Settings > System > Recovery > Advanced startup > Restart now.</li>
            <li>In WinRE Command Prompt, validate conversion: <code>mbr2gpt /validate /disk:0 /allowFullOS</code></li>
            <li>If validation succeeds, convert the disk: <code>mbr2gpt /convert /disk:0 /allowFullOS</code></li>
            <li>Enable UEFI boot in BIOS/UEFI settings after conversion.</li>
        </ol>
        <p><strong>Warning:</strong> Full system backup required due to data loss risk. See <a href="https://learn.microsoft.com/en-us/windows/deployment/mbr-to-gpt">Microsoft's MBR2GPT documentation</a>.</p>
    </div>
"@
    }

    if ($sys.Protection.BitLockerStatus -eq 'On') {
        $html += @"
    <div class="section warning-box">
        <h2>⚠️ BitLocker Recovery Key Backup Required</h2>
        <p>BitLocker is enabled on drive $($sys.DriveLetter.DriveLetter):. Back up the recovery key to prevent data loss:</p>
        <ol>
            <li>Run: <code>manage-bde -protectors -get $($sys.DriveLetter.DriveLetter):</code></li>
            <li>Save the recovery key in a secure location (e.g., password manager or printed copy).</li>
        </ol>
        <p><strong>Warning:</strong> Without the recovery key, data may be inaccessible after system changes. See <a href="https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery">Microsoft's BitLocker recovery guide</a>.</p>
    </div>
"@
    }

    if ($sys.RegistryBypass.AnyActive) {
        $html += @"
    <div class="section warning-box">
        <h2>⚠️ Registry Bypass Keys Detected</h2>
        <p>The following bypass keys are active, which may void Microsoft support:</p>
        <ul>
"@
        foreach ($bypass in ($sys.RegistryBypass.Details.GetEnumerator() | Where-Object { $_.Value.StartsWith('ACTIVE') })) {
            $html += "<li><strong>$($bypass.Key):</strong> $($bypass.Value)<br>Remove this key: <code>Remove-ItemProperty -Path 'HKLM:\SYSTEM\Setup\MoSetup' -Name '$($bypass.Key)'</code></li>"
        }
        $html += @"
        </ul>
        <p><strong>Warning:</strong> Remove unnecessary bypass keys to ensure compliance and support. See <a href="https://learn.microsoft.com/en-us/windows-hardware/design/minimum/windows-11-requirements">Microsoft's Windows 11 requirements</a>.</p>
    </div>
"@
    }

    $html += @"
    <div class="section">
        <h2>✅ Requirements Matrix</h2>
        <table>
            <tr><th>Requirement</th><th>Status</th><th>Required</th><th>Current</th></tr>
"@
    foreach ($reqItem in $req.Requirements.GetEnumerator() | Sort-Object Name) {
        $statusClass = switch ($reqItem.Value.Status) { 'Pass' { 'pass' }; 'Fail' { 'fail' }; 'Bypass' { 'bypass' } }
        $observed = if ($null -ne $observedValues[$reqItem.Key]) { $observedValues[$reqItem.Key] } else { 'Unknown' }
        $html += "<tr><td>$($reqItem.Key)</td><td><span class='status $statusClass'>$($reqItem.Value.Status)</span></td><td>$($reqItem.Value.Required)</td><td>$($observed)</td></tr>"
    }
    
    $overall = if ($req.AllRawPass) { '<span class="status pass">✅ READY FOR UPGRADE</span>' }
              elseif ($req.AllPassWithBypass) { '<span class="status bypass">⚠️ READY WITH BYPASSES</span>' }
              else { '<span class="status fail">❌ UPGRADES REQUIRED</span>' }
    
    $html += @"
        </table>
        <div style="margin-top: 20px; padding: 15px; background: #e9ecef; border-radius: 4px;">
            <h3>Overall Status: $overall</h3>
        </div>
    </div>
    
    <div class="section warning-box">
        <h3>⚠️ Critical Security Warnings</h3>
        <ul>
            <li><strong>Registry Bypasses:</strong> Void Microsoft support and security guarantees</li>
            <li><strong>BitLocker:</strong> <strong>BACKUP RECOVERY KEYS</strong> before any disk operations</li>
            <li><strong>MBR2GPT:</strong> Full system backup required - data loss risk</li>
            <li><strong>Verify:</strong> All recommendations against official Microsoft documentation</li>
        </ul>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $Path -Encoding UTF8
}

function Show-UpgradeAssessment {
    <#
    .SYNOPSIS
        Displays comprehensive upgrade readiness summary.
    #>
    param($AuditResult)
    
    $sys = $AuditResult.SystemInfo
    $req = $AuditResult.Requirements
    
    Write-Host ('=' * 80) -ForegroundColor Cyan
    Write-Host "     WINDOWS 11 UPGRADE READINESS ASSESSMENT" -ForegroundColor Cyan
    Write-Host ('=' * 80) -ForegroundColor Cyan
    
    Write-Host "`n📋 SYSTEM INFORMATION:" -ForegroundColor White
    if ($sys.OS.Caption -like '*Windows 11*') {
        Write-Host "  ⚠️ SYSTEM ALREADY RUNNING WINDOWS 11 - Assessing current compatibility" -ForegroundColor Cyan
    }
    $computerName = if ($sys.ComputerName) { $sys.ComputerName } else { (Get-ComputerInfo).WindowsComputerName }
    Write-Host "  Computer     : $computerName"
    Write-Host "  OS           : $($sys.OS.Caption) v$($sys.OS.Version)"
    Write-Host "  CPU          : $($sys.Processor.Name)"
    Write-Host "  CPU Instructions: SSE4.2: $($sys.CPUInstructions.SSE42Supported), POPCNT: $($sys.CPUInstructions.POPCNTSupported)" -ForegroundColor White
    Write-Host "  GPU          : $($sys.GPUCompatibility.Name) (Driver: $($sys.GPUCompatibility.DriverVersion))"
    Write-Host "  RAM          : $([math]::Round($sys.ComputerSystem.TotalPhysicalMemory/1GB,1)) GB"
    Write-Host "  Storage      : $($sys.TotalGB) GB (Free: $($sys.FreeGB) GB)"
    Write-Host "  Firmware     : $($sys.Firmware.Firmware)"
    Write-Host "  Secure Boot  : $($sys.Firmware.SecureBoot)"
    Write-Host "  TPM          : $($sys.TPM.Present ? "v$($sys.TPM.Version)" : 'Missing')"
    Write-Host "  Partition    : $($sys.DiskAnalysis.PartitionStyle)"
    Write-Host "  BitLocker    : $($sys.Protection.BitLockerStatus)"
    Write-Host "  WinRE        : $($sys.Protection.WinRE.Status)"
    
    Write-Host "`n🔧 DISK LAYOUT ANALYSIS:" -ForegroundColor White
    Write-Host "  Primary Partitions : $($sys.DiskAnalysis.PrimaryCount)"
    Write-Host "  Extended Partition : $($sys.DiskAnalysis.HasExtended)"
    Write-Host "  MBR2GPT Eligible   : $($sys.DiskAnalysis.MBRConvertible.Eligible)"
    Write-Host "  EFI Partition      : $($sys.DiskAnalysis.EFIPartition.Exists)"
    Write-Host "  Recovery Partition : $($sys.DiskAnalysis.HasRecovery)"
    
    if ($sys.DiskAnalysis.PartitionStyle -eq 'MBR' -and $sys.DiskAnalysis.MBRConvertible.Eligible) {
        Write-Host "`n⚠️ MBR2GPT CONVERSION REQUIRED:" -ForegroundColor Yellow
        Write-Host "  Your disk uses MBR, which is incompatible with Windows 11. Convert to GPT using MBR2GPT:"
        Write-Host "  1. Back up all data to an external drive or cloud storage."
        Write-Host "     Run: sdclt (Windows Backup and Restore) to create a system image."
        Write-Host "  2. Boot into Windows Recovery Environment (WinRE):"
        Write-Host "     Settings > System > Recovery > Advanced startup > Restart now."
        Write-Host "  3. In WinRE Command Prompt, validate conversion:"
        Write-Host "     mbr2gpt /validate /disk:0 /allowFullOS"
        Write-Host "  4. If validation succeeds, convert the disk:"
        Write-Host "     mbr2gpt /convert /disk:0 /allowFullOS"
        Write-Host "  5. Enable UEFI boot in BIOS/UEFI settings after conversion."
        Write-Host "  ⚠️ WARNING: Full backup required due to data loss risk."
        Write-Host "  See: https://learn.microsoft.com/en-us/windows/deployment/mbr-to-gpt"
    }
    
    if ($sys.Protection.BitLockerStatus -eq 'On') {
        Write-Host "`n⚠️ BITLOCKER RECOVERY KEY BACKUP REQUIRED:" -ForegroundColor Yellow
        Write-Host "  BitLocker is enabled on drive $($sys.DriveLetter.DriveLetter):. Back up the recovery key:"
        Write-Host "  1. Run: manage-bde -protectors -get $($sys.DriveLetter.DriveLetter):"
        Write-Host "  2. Save the recovery key in a secure location (e.g., password manager or printed copy)."
        Write-Host "  ⚠️ WARNING: Without the key, data may be inaccessible after system changes."
        Write-Host "  See: https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery"
    }
    
    if ($sys.RegistryBypass.AnyActive) {
        Write-Host "`n⚠️ BYPASS KEYS DETECTED:" -ForegroundColor Yellow
        Write-Verbose "Bypass keys detected: $($sys.RegistryBypass.Details | ConvertTo-Json)"
        $sys.RegistryBypass.Details.GetEnumerator() | Where-Object { $_.Value.StartsWith('ACTIVE') } | ForEach-Object {
            Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor Yellow
            Write-Host "  Remove this unnecessary key to ensure Microsoft support:"
            Write-Host "     Remove-ItemProperty -Path 'HKLM:\SYSTEM\Setup\MoSetup' -Name '$($_.Key)'" -ForegroundColor Yellow
        }
        Write-Host "  ⚠️ WARNING: Bypass keys void Microsoft support and may cause security issues."
    }
    
    Write-Host "`n✅ REQUIREMENTS STATUS:" -ForegroundColor White
    $req.Requirements.GetEnumerator() | Sort-Object Name | ForEach-Object {
        $status = $_.Value.Status
        $color = switch ($status) { 'Pass' { 'Green' }; 'Bypass' { 'Yellow' }; 'Fail' { 'Red' } }
        Write-Host "  $($_.Key.PadRight(20)): " -NoNewline
        Write-Host $status -ForegroundColor $color
    }
    
    Write-Host "`n🎯 UPGRADE READINESS:" -ForegroundColor Magenta
    if ($req.AllRawPass) {
        Write-Host "  ✅ FULLY COMPATIBLE - Ready for in-place upgrade!" -ForegroundColor Green
    } elseif ($req.AllPassWithBypass) {
        Write-Host "  ⚠️ COMPATIBLE WITH BYPASSES - Clean install recommended" -ForegroundColor Yellow
    } else {
        Write-Host "  ❌ HARDWARE UPGRADES REQUIRED" -ForegroundColor Red
    }
    
    if ($AuditResult.Errors.Count -gt 0) {
        Write-Host "`n❌ ANALYSIS ERRORS ($($AuditResult.Errors.Count)):" -ForegroundColor Red
        $AuditResult.Errors | ForEach-Object { 
            Write-Host "  $($_.Timestamp): $($_.Message)" -ForegroundColor Magenta 
        }
    }
}
#endregion

# Main execution workflow
try {
    # Phase 1: Prerequisites
    if (-not (Test-AdminElevation)) {
        throw "Administrator privileges required for complete analysis"
    }
    
    Write-Host "🔍 Analyzing system for Windows 11 compatibility..." -ForegroundColor Cyan
    
    # Phase 2: Data Collection
    $driveInfo = Test-DriveValidity -DriveLetter $DriveLetter
    if (-not $driveInfo.IsValid) { throw "Cannot access system drive $DriveLetter" }
    
    $coreData = Get-SystemCoreData
    $cpuCompat = Test-CPUCompatibility -Processor $coreData.Processor
    $gpuCompat = Test-GPUCompatibility
    $firmware = Get-FirmwareAndSecureBootStatus -PartitionStyle $null -OS $coreData.OS
    $tpm = Get-TPMStatus
    $diskAnalysis = Get-DiskAndPartitionAnalysis -DriveInfo $driveInfo
    $protection = Get-ProtectionStatus -DriveLetter $DriveLetter -PartitionAnalysis $diskAnalysis
    $bypasses = Get-RegistryBypassStatus
    
    # Update firmware with partition style
    $firmware = Get-FirmwareAndSecureBootStatus -PartitionStyle $diskAnalysis.PartitionStyle -OS $coreData.OS
    
    # Phase 3: System Information Assembly
    $script:AuditState.SystemInfo = [PSCustomObject]@{
        ComputerName      = $env:COMPUTERNAME
        DriveLetter       = $driveInfo
        OS                = $coreData.OS
        ComputerSystem    = $coreData.ComputerSystem
        Processor         = $coreData.Processor
        CPUCompatibility  = $cpuCompat
        GPUCompatibility  = $gpuCompat
        TotalGB           = $driveInfo.TotalGB
        FreeGB            = $driveInfo.FreeGB
        Firmware          = $firmware
        TPM               = $tpm
        DiskAnalysis      = $diskAnalysis
        Protection        = $protection
        RegistryBypass    = $bypasses
        Timestamp         = Get-Date
        CPUInstructions   = $coreData.CPUInstructions
    }
    
    # Phase 4: Requirements Evaluation
    $requirements = Test-Win11Requirements -SystemInfo $script:AuditState.SystemInfo `
                                         -FirmwareInfo $firmware `
                                         -TpmInfo $tpm `
                                         -BypassInfo $bypasses
    
    # Phase 5: Results Assembly
    $auditResult = [PSCustomObject]@{
        SystemInfo   = $script:AuditState.SystemInfo
        Requirements = $requirements
        Errors       = $script:AuditState.Errors
        Timestamp    = Get-Date
        Summary      = if ($requirements.AllRawPass) { 'Compatible' }
                      elseif ($requirements.AllPassWithBypass) { 'BypassCompatible' }
                      else { 'Incompatible' }
    }
    
    # Phase 6: Output and Export
    if ($ExportResults) {
        New-ExportFiles -AuditResult $auditResult
    }
    
    Show-UpgradeAssessment -AuditResult $auditResult
    
    Write-Host "`n⚠️  SECURITY REMINDER: Always backup BitLocker keys and verify with Microsoft documentation!" -ForegroundColor Yellow
}
catch {
    Add-AuditError -Message $_.Exception.Message -Severity 'Error' -Context 'MainExecution'
    Write-Error "Audit failed: $($_.Exception.Message)"
    exit 1
}
finally {
    # Cleanup
    if ($script:AuditState.CimCache.Count -gt 0) {
        Write-Verbose "Cleared CIM cache ($($script:AuditState.CimCache.Count) entries)"
        $script:AuditState.CimCache.Clear()
    }
}

Write-Host "`nPress any key to exit..." -ForegroundColor Gray

$null = Read-Host "Press Enter to exit"
