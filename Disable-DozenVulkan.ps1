<#
.SYNOPSIS
    Disables or nukes Mesa Dozen Vulkan wrapper JSON files & Registry keys in Microsoft OpenCL/OpenGL/Vulkan Compatibility Pack.

.DESCRIPTION
    Based on https://github.com/arminask/windows-arm-apps/issues/118
    On Windows 11 on ARM (Snapdragon X Elite, X Plus, 8cx), the OpenCL/OpenGL Compatibility Pack (Microsoft.D3DMappingLayers)
    includes Mesa Dozen (dzn), a Vulkan-to-D3D12 wrapper. Dozen is incapable of running DXVK and overrides native Adreno Vulkan drivers.

    This script disables Dozen via:
      1. Setting Vulkan Loader registry entries for Dozen to 1 (Disabled).
      2. Attempting live Win32 API file move/delete.
      3. If live file move is locked by Windows AppX kernel filters, automatically scheduling
         MOVEFILE_DELAY_UNTIL_REBOOT (PendingFileRenameOperations) so Windows renames/nukes
         the 6 files at boot time before security filters load.

    Target Files:
      - dzn_icd.arm64.json
      - dzn_icd.x64.json
      - dzn_icd.x86.json
      - dzn_layer.arm64.json
      - dzn_layer.x64.json
      - dzn_layer.x86.json

.PARAMETER Action
    Specifies the action to perform: 'Rename' (default/disable), 'Delete' (nuke), or 'Restore'.

.PARAMETER Extension
    The extension to append when renaming (default: '.disabled').

.PARAMETER Force
    Skip confirmation prompts.

.PARAMETER InstallTask
    Installs a simple boot-time (ONSTART) Scheduled Task under SYSTEM.

.PARAMETER RemoveTask
    Uninstalls the Scheduled Task.

.PARAMETER AddToPath
    Adds the script folder to System PATH so it can be called from any command prompt.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Rename', 'Delete', 'Restore')]
    [string]$Action = 'Rename',

    [Parameter()]
    [string]$Extension = '.disabled',

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$InstallTask,

    [Parameter()]
    [switch]$RemoveTask,

    [Parameter()]
    [switch]$AddToPath
)

# Ensure script is running as Administrator
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isSystem = $identity.IsSystem

if (-not ($isAdmin -or $isSystem)) {
    Write-Warning "Administrator rights required. Attempting to relaunch PowerShell as Administrator..."
    try {
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        if ($Action) { $arguments += " -Action $Action" }
        if ($Extension -ne '.disabled') { $arguments += " -Extension `"$Extension`"" }
        if ($Force) { $arguments += " -Force" }
        if ($InstallTask) { $arguments += " -InstallTask" }
        if ($RemoveTask) { $arguments += " -RemoveTask" }
        if ($AddToPath) { $arguments += " -AddToPath" }
        Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
        exit
    } catch {
        Write-Error "Failed to elevate privileges. Please run PowerShell as Administrator."
        exit 1
    }
}

# Add script folder to System PATH if requested
if ($AddToPath) {
    $scriptDir = Split-Path -Path $PSCommandPath -Parent
    try {
        $envPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if ($envPath -notlike "*$scriptDir*") {
            [Environment]::SetEnvironmentVariable("Path", "$envPath;$scriptDir", "Machine")
            Write-Host "[+] Added '$scriptDir' to System PATH environment variable." -ForegroundColor Green
        } else {
            Write-Host "[i] '$scriptDir' is already in System PATH." -ForegroundColor Gray
        }
    } catch {
        Write-Host "[ERROR] Failed to update PATH: $_" -ForegroundColor Red
    }
}

# Manage Boot-Only Scheduled Task (ONSTART)
if ($InstallTask) {
    $scriptPath = $PSCommandPath
    $taskName = "AutoNukeDozenVulkan"
    Write-Host "[+] Installing Boot-Only Scheduled Task '$taskName'..." -ForegroundColor Cyan

    $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Action $Action -Force"
    
    # Remove any existing legacy tasks
    $null = cmd.exe /c "schtasks /Delete /TN `"$taskName`" /F >nul 2>&1"
    $null = cmd.exe /c "schtasks /Delete /TN `"${taskName}_AppXEvent`" /F >nul 2>&1"
    $null = cmd.exe /c "schtasks /Delete /TN `"${taskName}_Daily`" /F >nul 2>&1"

    # Create clean ONSTART task
    $res = cmd.exe /c "schtasks /Create /TN `"$taskName`" /TR `"$cmd`" /SC ONSTART /RU `"NT AUTHORITY\SYSTEM`" /RL HIGHEST /F"

    Write-Host "[SUCCESS] Boot-Only Auto-Nuke Task installed!" -ForegroundColor Green
    Write-Host "          Runs once at system boot to ensure Dozen remains disabled." -ForegroundColor Gray
}

if ($RemoveTask) {
    $taskName = "AutoNukeDozenVulkan"
    try {
        $null = cmd.exe /c "schtasks /Delete /TN `"$taskName`" /F >nul 2>&1"
        $null = cmd.exe /c "schtasks /Delete /TN `"${taskName}_AppXEvent`" /F >nul 2>&1"
        $null = cmd.exe /c "schtasks /Delete /TN `"${taskName}_Daily`" /F >nul 2>&1"
        Write-Host "[+] Scheduled Task removed." -ForegroundColor Green
    } catch {}
}

# Compile C# Win32 API helper for MoveFileEx & Token Privileges
$Definition = @"
using System;
using System.Runtime.InteropServices;

public class Win32Ops {
    [Flags]
    public enum MoveFileFlags {
        MOVEFILE_REPLACE_EXISTING = 0x00000001,
        MOVEFILE_COPY_ALLOWED = 0x00000002,
        MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004,
        MOVEFILE_WRITE_THROUGH = 0x00000008
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, MoveFileFlags dwFlags);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TOKEN_PRIVILEGES {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }

    public static void EnablePrivileges() {
        string[] privileges = new string[] {
            "SeTakeOwnershipPrivilege",
            "SeRestorePrivilege",
            "SeBackupPrivilege",
            "SeSecurityPrivilege"
        };

        IntPtr hToken;
        if (OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out hToken)) {
            foreach (string priv in privileges) {
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Attributes = 2;
                if (LookupPrivilegeValue(null, priv, out tp.Luid)) {
                    AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                }
            }
        }
    }

    public static bool MoveLiveOrScheduleReboot(string src, string dst, out bool isRebootScheduled) {
        isRebootScheduled = false;
        bool success = MoveFileEx(src, dst, MoveFileFlags.MOVEFILE_REPLACE_EXISTING);
        if (!success) {
            success = MoveFileEx(src, dst, MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT | MoveFileFlags.MOVEFILE_REPLACE_EXISTING);
            if (success) {
                isRebootScheduled = true;
            }
        }
        return success;
    }

    public static bool DeleteLiveOrScheduleReboot(string path, out bool isRebootScheduled) {
        isRebootScheduled = false;
        bool success = MoveFileEx(path, null, MoveFileFlags.MOVEFILE_REPLACE_EXISTING);
        if (!success) {
            success = MoveFileEx(path, null, MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT);
            if (success) {
                isRebootScheduled = true;
            }
        }
        return success;
    }
}
"@

try {
    Add-Type -TypeDefinition $Definition -ErrorAction SilentlyContinue
    [Win32Ops]::EnablePrivileges()
} catch {}

$TargetFilenames = @(
    'dzn_icd.arm64.json',
    'dzn_icd.x64.json',
    'dzn_icd.x86.json',
    'dzn_layer.arm64.json',
    'dzn_layer.x64.json',
    'dzn_layer.x86.json'
)

$WindowsAppsPath = "$env:ProgramFiles\WindowsApps"
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Dozen Vulkan ICD & Layer Disabler / Nuker Script" -ForegroundColor Cyan
Write-Host "  Target: Microsoft.D3DMappingLayers & Vulkan Registry" -ForegroundColor Cyan
Write-Host "  Action: $Action (Identity: $($identity.Name))" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------
# STEP 1: Vulkan Loader Registry Scan & Disabling
# ------------------------------------------------------------------
Write-Host "[1/2] Scanning Vulkan Loader Registry entries..." -ForegroundColor Cyan

$VulkanRegKeys = @(
    "HKLM:\SOFTWARE\Vulkan\Drivers",
    "HKLM:\SOFTWARE\WOW6432Node\Vulkan\Drivers",
    "HKLM:\SOFTWARE\Khronos\Vulkan\Drivers",
    "HKLM:\SOFTWARE\WOW6432Node\Khronos\Vulkan\Drivers",
    "HKLM:\SOFTWARE\Vulkan\ImplicitLayers",
    "HKLM:\SOFTWARE\WOW6432Node\Vulkan\ImplicitLayers",
    "HKLM:\SOFTWARE\Khronos\Vulkan\ImplicitLayers",
    "HKLM:\SOFTWARE\WOW6432Node\Khronos\Vulkan\ImplicitLayers",
    "HKLM:\SOFTWARE\Vulkan\ExplicitLayers",
    "HKLM:\SOFTWARE\WOW6432Node\Vulkan\ExplicitLayers",
    "HKLM:\SOFTWARE\Khronos\Vulkan\ExplicitLayers",
    "HKLM:\SOFTWARE\WOW6432Node\Khronos\Vulkan\ExplicitLayers",
    "HKCU:\SOFTWARE\Vulkan\Drivers",
    "HKCU:\SOFTWARE\Khronos\Vulkan\Drivers",
    "HKCU:\SOFTWARE\Vulkan\ImplicitLayers",
    "HKCU:\SOFTWARE\Khronos\Vulkan\ImplicitLayers",
    "HKCU:\SOFTWARE\Vulkan\ExplicitLayers",
    "HKCU:\SOFTWARE\Khronos\Vulkan\ExplicitLayers"
)

$regModifiedCount = 0

foreach ($regPath in $VulkanRegKeys) {
    if (Test-Path $regPath) {
        try {
            $keyProps = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).PSObject.Properties
            foreach ($prop in $keyProps) {
                if ($prop.Name -like "*dzn*" -or $prop.Name -like "*D3DMappingLayers*") {
                    if ($Action -eq 'Rename' -or $Action -eq 'Delete') {
                        Set-ItemProperty -Path $regPath -Name $prop.Name -Value 1 -Type DWord -ErrorAction SilentlyContinue
                        Write-Host "    [REGISTRY DISABLED] $($prop.Name) = 1" -ForegroundColor Yellow
                        $regModifiedCount++
                    } elseif ($Action -eq 'Restore') {
                        Set-ItemProperty -Path $regPath -Name $prop.Name -Value 0 -Type DWord -ErrorAction SilentlyContinue
                        Write-Host "    [REGISTRY RESTORED] $($prop.Name) = 0" -ForegroundColor Green
                        $regModifiedCount++
                    }
                }
            }
        } catch {}
    }
}
if ($regModifiedCount -eq 0) {
    Write-Host "    [i] No active DZN Vulkan registry entries found." -ForegroundColor Gray
}

# ------------------------------------------------------------------
# STEP 2: File System Manifest Processing (Live + Reboot Fallback)
# ------------------------------------------------------------------
Write-Host ""
Write-Host "[2/2] Processing WindowsApps manifest files..." -ForegroundColor Cyan

if (Test-Path -Path $WindowsAppsPath) {
    $cmd = "takeown /f `"$WindowsAppsPath`" /a /d y >nul 2>&1 & icacls `"$WindowsAppsPath`" /grant Administrators:F /c >nul 2>&1"
    $null = cmd.exe /c $cmd
}

$TargetFolders = [System.Collections.Generic.List[string]]::new()

if (Test-Path -Path $WindowsAppsPath) {
    $foundDirs = Get-ChildItem -Path $WindowsAppsPath -Filter "Microsoft.D3DMappingLayers_*" -Directory -ErrorAction SilentlyContinue
    foreach ($dir in $foundDirs) {
        if (-not $TargetFolders.Contains($dir.FullName)) {
            $TargetFolders.Add($dir.FullName)
        }
    }
}

try {
    $packages = Get-AppxPackage -AllUsers -Name "*D3DMappingLayers*" -ErrorAction SilentlyContinue
    foreach ($pkg in $packages) {
        if ($pkg.InstallLocation -and (Test-Path $pkg.InstallLocation) -and (-not $TargetFolders.Contains($pkg.InstallLocation))) {
            $TargetFolders.Add($pkg.InstallLocation)
        }
    }
} catch {}

if ($TargetFolders.Count -eq 0) {
    Write-Host "[!] No Microsoft.D3DMappingLayers installation folders found under '$WindowsAppsPath'." -ForegroundColor Yellow
} else {
    Write-Host "[+] Found $($TargetFolders.Count) D3DMappingLayers folder(s):" -ForegroundColor Green
    foreach ($folder in $TargetFolders) {
        Write-Host "    - $folder" -ForegroundColor Gray
    }
}
Write-Host ""

$liveCount = 0
$rebootCount = 0
$skippedCount = 0
$failedCount = 0

foreach ($folder in $TargetFolders) {
    Write-Host "[*] Processing folder: $folder" -ForegroundColor Cyan

    $cmd = "takeown /f `"$folder`" /a /d y >nul 2>&1 & icacls `"$folder`" /grant Administrators:F /c >nul 2>&1"
    $null = cmd.exe /c $cmd

    foreach ($name in $TargetFilenames) {
        if ($Action -eq 'Restore') {
            $targetPath = Join-Path $folder "$name$Extension"
            $destPath = Join-Path $folder $name
            if (Test-Path -Path $targetPath) {
                if ($Force -or $PSCmdlet.ShouldProcess($targetPath, "Restore to $name")) {
                    try { (Get-Item -Path $targetPath -Force).Attributes = 'Normal' } catch {}
                    $isReboot = $false
                    $res = [Win32Ops]::MoveLiveOrScheduleReboot($targetPath, $destPath, [ref]$isReboot)
                    if ($res) {
                        if ($isReboot) {
                            Write-Host "    [SCHEDULED ON REBOOT] $name$Extension -> $name" -ForegroundColor Yellow
                            $rebootCount++
                        } else {
                            Write-Host "    [RESTORED LIVE] $name$Extension -> $name" -ForegroundColor Green
                            $liveCount++
                        }
                    } else {
                        Write-Host "    [ERROR] Failed to restore $name$Extension" -ForegroundColor Red
                        $failedCount++
                    }
                }
            } else {
                $skippedCount++
            }
        } elseif ($Action -eq 'Rename') {
            $targetPath = Join-Path $folder $name
            $newName = "$name$Extension"
            $destPath = Join-Path $folder $newName

            if (Test-Path -Path $targetPath) {
                if ($Force -or $PSCmdlet.ShouldProcess($targetPath, "Rename to $newName")) {
                    try { (Get-Item -Path $targetPath -Force).Attributes = 'Normal' } catch {}
                    $isReboot = $false
                    $res = [Win32Ops]::MoveLiveOrScheduleReboot($targetPath, $destPath, [ref]$isReboot)
                    if ($res) {
                        if ($isReboot) {
                            Write-Host "    [SCHEDULED ON REBOOT] $name -> $newName" -ForegroundColor Yellow
                            $rebootCount++
                        } else {
                            Write-Host "    [DISABLED LIVE] $name -> $newName" -ForegroundColor Green
                            $liveCount++
                        }
                    } else {
                        Write-Host "    [ERROR] Failed to disable $name" -ForegroundColor Red
                        $failedCount++
                    }
                }
            } elseif (Test-Path -Path $destPath) {
                Write-Host "    [ALREADY DISABLED] $newName" -ForegroundColor DarkGray
                $skippedCount++
            } else {
                $skippedCount++
            }
        } elseif ($Action -eq 'Delete') {
            $targetPath = Join-Path $folder $name
            $disabledPath = Join-Path $folder "$name$Extension"

            $filesToDelete = @()
            if (Test-Path -Path $targetPath) { $filesToDelete += $targetPath }
            if (Test-Path -Path $disabledPath) { $filesToDelete += $disabledPath }

            if ($filesToDelete.Count -gt 0) {
                foreach ($fileToDelete in $filesToDelete) {
                    if ($Force -or $PSCmdlet.ShouldProcess($fileToDelete, "Delete/Nuke file")) {
                        try { (Get-Item -Path $fileToDelete -Force).Attributes = 'Normal' } catch {}
                        $isReboot = $false
                        $res = [Win32Ops]::DeleteLiveOrScheduleReboot($fileToDelete, [ref]$isReboot)
                        if ($res) {
                            if ($isReboot) {
                                Write-Host "    [SCHEDULED FOR NUKE ON REBOOT] $(Split-Path $fileToDelete -Leaf)" -ForegroundColor Yellow
                                $rebootCount++
                            } else {
                                Write-Host "    [NUKED LIVE] $(Split-Path $fileToDelete -Leaf)" -ForegroundColor Red
                                $liveCount++
                            }
                        } else {
                            Write-Host "    [ERROR] Failed to nuke $(Split-Path $fileToDelete -Leaf)" -ForegroundColor Red
                            $failedCount++
                        }
                    }
                }
            } else {
                $skippedCount++
            }
        }
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Execution Summary" -ForegroundColor Cyan
Write-Host "  Registry entries updated:  $regModifiedCount" -ForegroundColor Green
Write-Host "  Files processed live:      $liveCount" -ForegroundColor Green
Write-Host "  Files scheduled on reboot: $rebootCount" -ForegroundColor Yellow
Write-Host "  Files skipped/not found:   $skippedCount" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan

if ($rebootCount -gt 0) {
    Write-Host "[!] $rebootCount file(s) are scheduled for renaming/nuking in Windows Kernel on next system restart." -ForegroundColor Yellow
    Write-Host "    Please restart your computer to finalize disabling Mesa Dozen." -ForegroundColor Yellow
} else {
    Write-Host "[+] Done! You can verify Vulkan status using 'vulkaninfo.exe' or 'Vulkan CapsViewer'." -ForegroundColor Green
}
