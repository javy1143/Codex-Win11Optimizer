# Dell Laptop Optimization Tool (PowerShell + WinForms)

This repository contains a Windows Forms optimization utility script for Dell laptops:

- **File:** `DellOptimizer.ps1`
- **Tech:** Windows PowerShell 5.1 + .NET WinForms
- **UI Theme:** Blue/gray palette inspired by the provided logo colors (without embedding the logo image)
- **Layout:** Fixed startup window with **no scrolling required** for optimization lists (organized in category tabs)

## Included Optimization Packs

1. **Privacy Optimizations**
   - Activity History
   - Game DVR/Xbox telemetry
   - Consumer background apps
   - Storage Sense
   - Ads, Spotlight, suggestions
   - Diagnostic data minimum
   - Web search in Start
   - Location and sensors
   - Teredo and Wi-Fi Sense
   - Recall/Copilot policy controls

2. **Performance Optimizations**
   - Temp cleanup
   - Hibernation disable
   - Non-essential service startup changes
   - TcpNoDelay/TcpAckFrequency
   - DNS flush

3. **Debloat Optimizations**
   - Edge policy debloat
   - Adobe service disable
   - Adobe Desktop Service binary rename

4. **Maintenance & Repair Tasks**
   - DISM restore health
   - SFC scan
   - Windows Update component reset
   - Teams/Outlook cache cleanup

## Usage

1. Open **PowerShell as Administrator**.
2. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\DellOptimizer.ps1
```

3. Use the tabs to move between categories.
4. Select desired optimization items.
5. Click **Run Selected Optimizations**.
6. Review the built-in log pane or click **Export Log**.

## Notes

- Some optimizations are policy/registry based and may require reboot or sign-out to fully apply.
- Service names and Adobe component paths may vary by system/software version.
- Use carefully in managed enterprise environments where central policy may override local settings.
