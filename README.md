# Nuke Dozen Vulkan (`Disable-DozenVulkan.ps1`)

PowerShell script to disable Mesa Dozen (`dzn`) Vulkan manifests on Snapdragon laptops running Windows 11, fixing DXVK support while keeping OpenGL and OpenCL compatibility intact.

## Background

Microsoft includes the **OpenCL, OpenGL & Vulkan Compatibility Pack** (`Microsoft.D3DMappingLayers`) on Windows 11 on ARM. This package includes Mesa Dozen (`dzn`), a Vulkan-to-D3D12 wrapper.

As noted in the [DXVK documentation](https://github.com/doitsujin/dxvk/wiki/Windows#dozen), Dozen cannot run DXVK and breaks Vulkan applications on Snapdragon devices equipped with native Adreno Vulkan drivers.

Uninstalling the entire compatibility pack breaks OpenGL support for legacy apps. This script specifically disables or removes the 6 Dozen Vulkan manifest files so DXVK and Vulkan apps run directly on native Adreno drivers.

## Targeted Files

- `dzn_icd.arm64.json`
- `dzn_icd.x64.json`
- `dzn_icd.x86.json`
- `dzn_layer.arm64.json`
- `dzn_layer.x64.json`
- `dzn_layer.x86.json`

## Usage

Run PowerShell as Administrator:

### Disable / Rename Manifests (Default)
```powershell
.\Disable-DozenVulkan.ps1
```

### Delete / Nuke Manifests
```powershell
.\Disable-DozenVulkan.ps1 -Action Delete
```

### Install Startup Task & Add to PATH
Automatically checks and disables Dozen once at system boot to handle Microsoft Store updates:
```powershell
.\Disable-DozenVulkan.ps1 -InstallTask -AddToPath
```

### Restore Original Manifests
```powershell
.\Disable-DozenVulkan.ps1 -Action Restore
```

## License

[MIT](LICENSE)
