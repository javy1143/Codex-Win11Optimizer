#requires -Version 5.1
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    [System.Windows.Forms.MessageBox]::Show(
        'Please run this tool as Administrator.',
        'Dell Optimizer',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
    exit 1
}

$palette = @{
    Background = [System.Drawing.Color]::FromArgb(17, 27, 38)
    Panel      = [System.Drawing.Color]::FromArgb(22, 42, 61)
    Accent     = [System.Drawing.Color]::FromArgb(18, 138, 226)
    Accent2    = [System.Drawing.Color]::FromArgb(9, 96, 158)
    Text       = [System.Drawing.Color]::FromArgb(235, 242, 248)
    Muted      = [System.Drawing.Color]::FromArgb(148, 163, 184)
    Gray       = [System.Drawing.Color]::FromArgb(92, 101, 113)
}

$global:LogEntries = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )

    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $global:LogEntries.Add($line)
    if ($script:txtLog) {
        $script:txtLog.AppendText($line + [Environment]::NewLine)
        $script:txtLog.SelectionStart = $script:txtLog.TextLength
        $script:txtLog.ScrollToCaret()
    }
}

function Invoke-RegistrySet {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [object]$Value,
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord')]
        [string]$PropertyType = 'DWord'
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
}

function Invoke-ServiceStartupChange {
    param(
        [string]$Name,
        [ValidateSet('Automatic', 'Manual', 'Disabled')]
        [string]$StartupType
    )

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Log "Service $Name not found; skipping." 'WARN'
        return
    }

    Set-Service -Name $Name -StartupType $StartupType
    if ($StartupType -eq 'Disabled' -and $service.Status -eq 'Running') {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    }
    Write-Log "Service $Name set to $StartupType."
}

function Reset-WindowsUpdateComponents {
    $services = 'wuauserv', 'bits', 'cryptSvc', 'msiserver'
    foreach ($svc in $services) {
        Write-Log "Stopping $svc..."
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    }

    $sdPath = Join-Path $env:windir 'SoftwareDistribution'
    $catPath = Join-Path $env:windir 'System32\catroot2'

    if (Test-Path $sdPath) {
        $target = "$sdPath.bak_$(Get-Date -Format 'yyyyMMddHHmmss')"
        Rename-Item -Path $sdPath -NewName (Split-Path $target -Leaf) -Force
        Write-Log "Renamed SoftwareDistribution to $(Split-Path $target -Leaf)."
    }

    if (Test-Path $catPath) {
        $target = "$catPath.bak_$(Get-Date -Format 'yyyyMMddHHmmss')"
        Rename-Item -Path $catPath -NewName (Split-Path $target -Leaf) -Force
        Write-Log "Renamed catroot2 to $(Split-Path $target -Leaf)."
    }

    foreach ($svc in $services) {
        Write-Log "Starting $svc..."
        Start-Service -Name $svc -ErrorAction SilentlyContinue
    }
}

function Remove-DirectoryContent {
    param([string]$Path)
    if (Test-Path $Path) {
        Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Cleared $Path"
    }
}

$tweaks = @(
    [pscustomobject]@{ Category = 'Privacy'; Name = 'Disable Activity History'; Description = 'Disable Timeline and cloud upload of user activity.'; Action = {
        Invoke-RegistrySet -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Value 0
        Invoke-RegistrySet -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Value 0
        Invoke-RegistrySet -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'UploadUserActivities' -Value 0
    } }
    [pscustomobject]@{ Category = 'Privacy'; Name = 'Disable Game DVR & Xbox telemetry'; Description = 'Stop game background capture and GameDVR.'; Action = {
        Invoke-RegistrySet -Path 'HKCU:\System\GameConfigStore' -Name 'GameDVR_Enabled' -Value 0
        Invoke-RegistrySet -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'AppCaptureEnabled' -Value 0
        Invoke-RegistrySet -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Name 'AllowGameDVR' -Value 0
    } }
    [pscustomobject]@{ Category = 'Privacy'; Name = 'Limit consumer background apps'; Description = 'Restrict noisy consumer app background execution.'; Action = {
        $apps = @('Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.MicrosoftSolitaireCollection')
        foreach ($app in $apps) {
            Get-AppxPackage -AllUsers -Name $app -ErrorAction SilentlyContinue | ForEach-Object {
                $sid = 'S-1-15-2-1'
                $base = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\$($_.PackageFamilyName)"
                Invoke-RegistrySet -Path $base -Name 'Disabled' -Value 1
                Invoke-RegistrySet -Path $base -Name 'DisabledByUser' -Value 1
                Invoke-RegistrySet -Path $base -Name 'UserSid' -Value $sid -PropertyType String
            }
        }
    } }
    [pscustomobject]@{ Category = 'Privacy'; Name = 'Disable Storage Sense'; Description = 'Disable automatic temporary file cleanup.'; Action = {
        Invoke-RegistrySet -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name '01' -Value 0
    } }
    [pscustomobject]@{ Category = 'Privacy'; Name = 'Disable ads, spotlight, and tips'; Description = 'Turn off content suggestions and ad personalization.'; Action = {
        Invoke-RegistrySet -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0
        Invoke-RegistrySet -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'RotatingLockScreenEnabled' -Value 0
        Invoke-RegistrySet -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'RotatingLockScreenOverlayEnabled' -Value 0
        Invoke-RegistrySet -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338389Enabled' -Value 0
        Invoke-RegistrySet -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338388Enabled' -Value 0
    } }
    [pscustomobject]@{ Category = 'Privacy'; Name = 'Minimum diagnostic data'; Description = 'Set telemetry to required and disable inking/typing data collection.'; Action = {
        Invoke-RegistrySet -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 1
        Invoke-RegistrySet -Path 'HKCU:\Software\Microsoft\Input\TIPC' -Name 'Enabled' -Value 0
        Invoke-RegistrySet -Path 'HKCU:\Software\Microsoft\Personalization\Settings' -Name 'AcceptedPrivacyPolicy' -Value 0
    } }
    [pscustomobject]@{ Category = 'Privacy'; Name = 'Disable web search in Start'; Description = 'Keep Start search local-only.'; Action = {
        Invoke-RegistrySet -Path 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' -Name 'DisableSearchBoxSuggestions' -Value 1
        Invoke-RegistrySet -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -Value 1
    } }
    [pscustomobject]@{ Category = 'Privacy'; Name = 'Disable location and sensors'; Description = 'Disable location services and sensor access.'; Action = {
        Invoke-RegistrySet -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Value 1
        Invoke-RegistrySet -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableSensors' -Value 1
        Invoke-RegistrySet -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableWindowsLocationProvider' -Value 1
    } }
    [pscustomobject]@{ Category = 'Privacy'; Name = 'Disable Teredo & Wi-Fi Sense'; Description = 'Disable Teredo and hotspot auto-connect behaviors.'; Action = {
        Invoke-RegistrySet -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Value 8
        Invoke-RegistrySet -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting' -Name 'Value' -Value 0
        Invoke-RegistrySet -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots' -Name 'Value' -Value 0
    } }
    [pscustomobject]@{ Category = 'Privacy'; Name = 'Disable Recall (Windows 11)'; Description = 'Disable Recall / AI snapshotting features if present.'; Action = {
        Invoke-RegistrySet -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' -Name 'DisableAIDataAnalysis' -Value 1
        Invoke-RegistrySet -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' -Name 'TurnOffWindowsCopilot' -Value 1
    } }

    [pscustomobject]@{ Category = 'Performance'; Name = 'Clean temporary files'; Description = 'Clear Windows and user temp directories.'; Action = {
        Remove-DirectoryContent -Path $env:TEMP
        Remove-DirectoryContent -Path (Join-Path $env:windir 'Temp')
    } }
    [pscustomobject]@{ Category = 'Performance'; Name = 'Disable hibernation'; Description = 'Turn off hiberfil.sys.'; Action = {
        & powercfg.exe /hibernate off | Out-Null
        Write-Log 'Hibernation disabled.'
    } }
    [pscustomobject]@{ Category = 'Performance'; Name = 'Optimize non-essential services'; Description = 'Set select services to Manual/Disabled startup.'; Action = {
        $manualServices = 'DiagTrack', 'MapsBroker', 'WSearch', 'WbioSrvc', 'WerSvc'
        $disabledServices = 'RemoteRegistry', 'Fax', 'AJRouter', 'XblGameSave', 'XboxNetApiSvc'
        foreach ($svc in $manualServices) { Invoke-ServiceStartupChange -Name $svc -StartupType Manual }
        foreach ($svc in $disabledServices) { Invoke-ServiceStartupChange -Name $svc -StartupType Disabled }
    } }
    [pscustomobject]@{ Category = 'Performance'; Name = 'Set TcpNoDelay'; Description = 'Reduce packet aggregation latency.'; Action = {
        $ifaces = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -ErrorAction SilentlyContinue
        foreach ($iface in $ifaces) {
            Invoke-RegistrySet -Path $iface.PSPath -Name 'TcpNoDelay' -Value 1
            Invoke-RegistrySet -Path $iface.PSPath -Name 'TcpAckFrequency' -Value 1
        }
    } }
    [pscustomobject]@{ Category = 'Performance'; Name = 'Flush DNS cache'; Description = 'Clear local DNS resolver cache.'; Action = {
        & ipconfig.exe /flushdns | Out-Null
        Write-Log 'DNS cache flushed.'
    } }

    [pscustomobject]@{ Category = 'Debloat'; Name = 'Debloat Microsoft Edge policies'; Description = 'Disable shopping assistant, wallet, and first-run experience.'; Action = {
        $edgePolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Invoke-RegistrySet -Path $edgePolicy -Name 'EdgeShoppingAssistantEnabled' -Value 0
        Invoke-RegistrySet -Path $edgePolicy -Name 'WalletDonationEnabled' -Value 0
        Invoke-RegistrySet -Path $edgePolicy -Name 'ShowRecommendationsEnabled' -Value 0
        Invoke-RegistrySet -Path $edgePolicy -Name 'HideFirstRunExperience' -Value 1
    } }
    [pscustomobject]@{ Category = 'Debloat'; Name = 'Disable Adobe background services'; Description = 'Disable Adobe update and integrity services.'; Action = {
        $adobeServices = 'AdobeARMservice', 'AGSService', 'AdobeUpdateService'
        foreach ($svc in $adobeServices) {
            Invoke-ServiceStartupChange -Name $svc -StartupType Disabled
        }
    } }
    [pscustomobject]@{ Category = 'Debloat'; Name = 'Rename Adobe Desktop Service binary'; Description = 'Rename Adobe Desktop Service executable to prevent launch.'; Action = {
        $possiblePaths = @(
            'C:\Program Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe',
            'C:\Program Files (x86)\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe'
        )
        foreach ($path in $possiblePaths) {
            if (Test-Path $path) {
                $newPath = [IO.Path]::Combine([IO.Path]::GetDirectoryName($path), 'Adobe Desktop Service.disabled.exe')
                Rename-Item -Path $path -NewName ([IO.Path]::GetFileName($newPath)) -Force
                Write-Log "Renamed $path"
            }
        }
    } }

    [pscustomobject]@{ Category = 'Maintenance'; Name = 'Run DISM health repair'; Description = 'Run DISM restorehealth scan.'; Action = {
        & dism.exe /Online /Cleanup-Image /RestoreHealth
    } }
    [pscustomobject]@{ Category = 'Maintenance'; Name = 'Run SFC scan'; Description = 'Run system file checker.'; Action = {
        & sfc.exe /scannow
    } }
    [pscustomobject]@{ Category = 'Maintenance'; Name = 'Reset Windows Update components'; Description = 'Reset SoftwareDistribution and catroot2.'; Action = {
        Reset-WindowsUpdateComponents
    } }
    [pscustomobject]@{ Category = 'Maintenance'; Name = 'Clean Teams/Outlook caches'; Description = 'Clear Teams caches and Outlook secure temp.'; Action = {
        $cachePaths = @(
            "$env:APPDATA\Microsoft\Teams",
            "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache",
            "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\Content.Outlook"
        )
        foreach ($cachePath in $cachePaths) {
            Remove-DirectoryContent -Path $cachePath
        }
    } }
)

$script:tweakLookup = @{}
foreach ($tweak in $tweaks) {
    $script:tweakLookup[$tweak.Name] = $tweak
}

$form = [System.Windows.Forms.Form]::new()
$form.Text = 'Dell Laptop Optimization Tool'
$form.Size = [System.Drawing.Size]::new(1024, 700)
$form.MinimumSize = [System.Drawing.Size]::new(1024, 700)
$form.MaximumSize = [System.Drawing.Size]::new(1024, 700)
$form.StartPosition = 'CenterScreen'
$form.BackColor = $palette.Background
$form.ForeColor = $palette.Text
$form.Font = [System.Drawing.Font]::new('Segoe UI', 9.5)
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
$form.MaximizeBox = $false

$header = [System.Windows.Forms.Label]::new()
$header.Text = 'Dell Laptop Optimization Tool'
$header.Font = [System.Drawing.Font]::new('Segoe UI Semibold', 18)
$header.ForeColor = $palette.Accent
$header.AutoSize = $true
$header.Location = [System.Drawing.Point]::new(18, 12)
$form.Controls.Add($header)

$subtitle = [System.Windows.Forms.Label]::new()
$subtitle.Text = 'No-scroll layout: all options visible by category tabs at startup size'
$subtitle.ForeColor = $palette.Muted
$subtitle.AutoSize = $true
$subtitle.Location = [System.Drawing.Point]::new(20, 46)
$form.Controls.Add($subtitle)

$leftPanel = [System.Windows.Forms.Panel]::new()
$leftPanel.Location = [System.Drawing.Point]::new(16, 72)
$leftPanel.Size = [System.Drawing.Size]::new(650, 580)
$leftPanel.BackColor = $palette.Panel
$form.Controls.Add($leftPanel)

$tabs = [System.Windows.Forms.TabControl]::new()
$tabs.Location = [System.Drawing.Point]::new(10, 10)
$tabs.Size = [System.Drawing.Size]::new(630, 505)
$tabs.Font = [System.Drawing.Font]::new('Segoe UI', 9)
$leftPanel.Controls.Add($tabs)

$tabMap = @{}
$checkListMap = @{}
$categories = @('Privacy', 'Performance', 'Debloat', 'Maintenance')
foreach ($category in $categories) {
    $tab = [System.Windows.Forms.TabPage]::new($category)
    $tab.BackColor = $palette.Panel
    $tab.ForeColor = $palette.Text

    $checkedList = [System.Windows.Forms.CheckedListBox]::new()
    $checkedList.Location = [System.Drawing.Point]::new(10, 10)
    $checkedList.Size = [System.Drawing.Size]::new(595, 420)
    $checkedList.CheckOnClick = $true
    $checkedList.BackColor = [System.Drawing.Color]::FromArgb(18, 34, 50)
    $checkedList.ForeColor = $palette.Text
    $checkedList.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

    foreach ($tweak in ($tweaks | Where-Object Category -eq $category)) {
        [void]$checkedList.Items.Add($tweak.Name)
    }

    $descLabel = [System.Windows.Forms.Label]::new()
    $descLabel.Location = [System.Drawing.Point]::new(10, 438)
    $descLabel.Size = [System.Drawing.Size]::new(595, 35)
    $descLabel.ForeColor = $palette.Muted
    $descLabel.Text = 'Select an item to view details.'

    $checkedList.Add_SelectedIndexChanged({
        if ($this.SelectedItem) {
            $name = [string]$this.SelectedItem
            $tweak = $script:tweakLookup[$name]
            if ($tweak) {
                $this.Parent.Controls[1].Text = $tweak.Description
            }
        }
    })

    $tab.Controls.Add($checkedList)
    $tab.Controls.Add($descLabel)
    [void]$tabs.TabPages.Add($tab)

    $tabMap[$category] = $tab
    $checkListMap[$category] = $checkedList
}

$btnSelectAll = [System.Windows.Forms.Button]::new()
$btnSelectAll.Text = 'Select All (Tab)'
$btnSelectAll.Size = [System.Drawing.Size]::new(150, 34)
$btnSelectAll.Location = [System.Drawing.Point]::new(10, 530)
$btnSelectAll.BackColor = $palette.Accent
$btnSelectAll.ForeColor = $palette.Text
$btnSelectAll.FlatStyle = 'Flat'
$btnSelectAll.Add_Click({
    $activeCategory = $tabs.SelectedTab.Text
    $list = $checkListMap[$activeCategory]
    for ($i = 0; $i -lt $list.Items.Count; $i++) {
        $list.SetItemChecked($i, $true)
    }
})
$leftPanel.Controls.Add($btnSelectAll)

$btnClear = [System.Windows.Forms.Button]::new()
$btnClear.Text = 'Clear (Tab)'
$btnClear.Size = [System.Drawing.Size]::new(120, 34)
$btnClear.Location = [System.Drawing.Point]::new(168, 530)
$btnClear.BackColor = $palette.Accent2
$btnClear.ForeColor = $palette.Text
$btnClear.FlatStyle = 'Flat'
$btnClear.Add_Click({
    $activeCategory = $tabs.SelectedTab.Text
    $list = $checkListMap[$activeCategory]
    for ($i = 0; $i -lt $list.Items.Count; $i++) {
        $list.SetItemChecked($i, $false)
    }
})
$leftPanel.Controls.Add($btnClear)

$btnSelectEverything = [System.Windows.Forms.Button]::new()
$btnSelectEverything.Text = 'Select All (Global)'
$btnSelectEverything.Size = [System.Drawing.Size]::new(170, 34)
$btnSelectEverything.Location = [System.Drawing.Point]::new(296, 530)
$btnSelectEverything.BackColor = $palette.Gray
$btnSelectEverything.ForeColor = $palette.Text
$btnSelectEverything.FlatStyle = 'Flat'
$btnSelectEverything.Add_Click({
    foreach ($category in $categories) {
        $list = $checkListMap[$category]
        for ($i = 0; $i -lt $list.Items.Count; $i++) {
            $list.SetItemChecked($i, $true)
        }
    }
})
$leftPanel.Controls.Add($btnSelectEverything)

$btnClearEverything = [System.Windows.Forms.Button]::new()
$btnClearEverything.Text = 'Clear (Global)'
$btnClearEverything.Size = [System.Drawing.Size]::new(160, 34)
$btnClearEverything.Location = [System.Drawing.Point]::new(474, 530)
$btnClearEverything.BackColor = [System.Drawing.Color]::FromArgb(78, 88, 100)
$btnClearEverything.ForeColor = $palette.Text
$btnClearEverything.FlatStyle = 'Flat'
$btnClearEverything.Add_Click({
    foreach ($category in $categories) {
        $list = $checkListMap[$category]
        for ($i = 0; $i -lt $list.Items.Count; $i++) {
            $list.SetItemChecked($i, $false)
        }
    }
})
$leftPanel.Controls.Add($btnClearEverything)

$rightPanel = [System.Windows.Forms.Panel]::new()
$rightPanel.Location = [System.Drawing.Point]::new(678, 72)
$rightPanel.Size = [System.Drawing.Size]::new(330, 580)
$rightPanel.BackColor = $palette.Panel
$form.Controls.Add($rightPanel)

$btnRun = [System.Windows.Forms.Button]::new()
$btnRun.Text = 'Run Selected Optimizations'
$btnRun.Size = [System.Drawing.Size]::new(308, 40)
$btnRun.Location = [System.Drawing.Point]::new(11, 10)
$btnRun.BackColor = $palette.Accent
$btnRun.ForeColor = $palette.Text
$btnRun.FlatStyle = 'Flat'
$rightPanel.Controls.Add($btnRun)

$btnExport = [System.Windows.Forms.Button]::new()
$btnExport.Text = 'Export Log'
$btnExport.Size = [System.Drawing.Size]::new(308, 34)
$btnExport.Location = [System.Drawing.Point]::new(11, 56)
$btnExport.BackColor = $palette.Gray
$btnExport.ForeColor = $palette.Text
$btnExport.FlatStyle = 'Flat'
$rightPanel.Controls.Add($btnExport)

$txtLog = [System.Windows.Forms.TextBox]::new()
$txtLog.Multiline = $true
$txtLog.ReadOnly = $true
$txtLog.ScrollBars = 'Vertical'
$txtLog.Location = [System.Drawing.Point]::new(11, 98)
$txtLog.Size = [System.Drawing.Size]::new(308, 470)
$txtLog.BackColor = [System.Drawing.Color]::FromArgb(10, 17, 27)
$txtLog.ForeColor = $palette.Text
$txtLog.Font = [System.Drawing.Font]::new('Consolas', 8.8)
$rightPanel.Controls.Add($txtLog)
$script:txtLog = $txtLog

$btnRun.Add_Click({
    $selectedTweaks = [System.Collections.Generic.List[object]]::new()

    foreach ($category in $categories) {
        $list = $checkListMap[$category]
        foreach ($selectedName in $list.CheckedItems) {
            $name = [string]$selectedName
            $tweak = $script:tweakLookup[$name]
            if ($tweak) {
                $selectedTweaks.Add($tweak)
            }
        }
    }

    if ($selectedTweaks.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Please choose at least one optimization.', 'No Selection') | Out-Null
        return
    }

    foreach ($tweak in $selectedTweaks) {
        Write-Log "Running: $($tweak.Category) :: $($tweak.Name)"
        try {
            & $tweak.Action
            Write-Log "Completed: $($tweak.Name)" 'SUCCESS'
        }
        catch {
            Write-Log "Failed: $($tweak.Name) :: $($_.Exception.Message)" 'ERROR'
        }
    }

    [System.Windows.Forms.MessageBox]::Show('Selected optimizations completed. Review log for details.', 'Done') | Out-Null
})

$btnExport.Add_Click({
    $dialog = [System.Windows.Forms.SaveFileDialog]::new()
    $dialog.Filter = 'Log files (*.log)|*.log|Text files (*.txt)|*.txt'
    $dialog.FileName = "DellOptimizer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $global:LogEntries | Set-Content -Path $dialog.FileName -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show('Log exported successfully.', 'Export Complete') | Out-Null
    }
})

Write-Log 'Ready. Use category tabs. No scrolling required for optimization lists in default window size.'
[void]$form.ShowDialog()
