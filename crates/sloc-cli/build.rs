// Embeds Windows PE version information and an application manifest into
// oxide-sloc.exe at build time using rc.exe (MSVC) or windres (MinGW).
// Silently no-ops on non-Windows targets and when neither tool is available.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    embed_windows_resources();
}

fn embed_windows_resources() {
    let out = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out = std::path::Path::new(&out);

    let ver = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let parts: Vec<u16> = ver
        .split('.')
        .filter_map(|s| s.parse().ok())
        .chain(std::iter::repeat(0))
        .take(4)
        .collect();
    let ver_commas = format!("{},{},{},{}", parts[0], parts[1], parts[2], parts[3]);
    let ver_dots = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3]);

    // Write the application manifest so rc.exe can reference it by path.
    let manifest_path = out.join("oxide-sloc.manifest");
    std::fs::write(&manifest_path, make_manifest(&ver_dots)).ok();
    let manifest_str = manifest_path
        .to_str()
        .unwrap_or("")
        .replace('\\', "/");

    let rc_content = make_rc(&ver_commas, &ver_dots, &manifest_str);
    let rc_path = out.join("oxide-sloc.rc");
    std::fs::write(&rc_path, &rc_content).ok();

    let is_msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");

    if is_msvc {
        // MSVC target: rc.exe → .res → link.exe takes .res directly.
        let res_path = out.join("oxide-sloc.res");
        if try_rc_exe(&rc_path, &res_path) {
            println!("cargo:rustc-link-arg={}", res_path.display());
            return;
        }
    } else {
        // GNU target (MinGW / x86_64-pc-windows-gnu): windres → COFF .o → GNU ld.
        let obj_path = out.join("oxide-sloc-res.o");
        if try_windres_coff(&rc_path, &obj_path) {
            println!("cargo:rustc-link-arg={}", obj_path.display());
            return;
        }
    }

    // Cross-env fallback: try the other tool in case of non-standard setups.
    let res_path = out.join("oxide-sloc-fb.res");
    if try_rc_exe(&rc_path, &res_path) {
        println!("cargo:rustc-link-arg={}", res_path.display());
        return;
    }
    let obj_path = out.join("oxide-sloc-fb.o");
    if try_windres_coff(&rc_path, &obj_path) {
        println!("cargo:rustc-link-arg={}", obj_path.display());
        return;
    }

    println!("cargo:warning=oxide-sloc: PE version info not embedded (rc.exe and windres not found — install Windows SDK or MinGW)");
}

fn make_manifest(ver_dots: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="{v}" name="NimaShafie.oxide-sloc" type="win32"/>
  <description>oxide-sloc local code metrics workbench</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges>
      <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
    </requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>
      <supportedOS Id="{{1f676c76-80e1-4239-95bb-83d0f6d0da78}}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">permonitorv2,permonitor</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"#,
        v = ver_dots
    )
}

fn make_rc(ver_commas: &str, ver_dots: &str, manifest_path: &str) -> String {
    // Numeric constants avoid requiring #include <winver.h>:
    //   FILEOS  0x00040004 = VOS_NT_WINDOWS32
    //   FILETYPE 0x00000001 = VFT_APP
    format!(
        r#"
VS_VERSION_INFO VERSIONINFO
FILEVERSION {vc}
PRODUCTVERSION {vc}
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x00040004L
FILETYPE 0x00000001L
FILESUBTYPE 0x0L
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName",      "Nima Shafie"
      VALUE "FileDescription",  "oxide-sloc -- local code metrics workbench"
      VALUE "FileVersion",      "{vd}"
      VALUE "InternalName",     "oxide-sloc"
      VALUE "LegalCopyright",   "Copyright 2024 Nima Shafie. AGPL-3.0-or-later."
      VALUE "OriginalFilename", "oxide-sloc.exe"
      VALUE "ProductName",      "oxide-sloc"
      VALUE "ProductVersion",   "{vd}"
      VALUE "URL",              "https://github.com/NimaShafie/oxide-sloc"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x0409, 0x04B0
  END
END

1 24 "{mp}"
"#,
        vc = ver_commas,
        vd = ver_dots,
        mp = manifest_path,
    )
}

fn try_rc_exe(rc: &std::path::Path, res: &std::path::Path) -> bool {
    // Try rc.exe on PATH first, then common Windows SDK locations.
    let mut candidates = vec!["rc.exe".to_string()];
    if let Some(sdk_rc) = find_winsdk_rc() {
        candidates.push(sdk_rc);
    }
    for candidate in &candidates {
        if std::process::Command::new(candidate)
            .args(["/nologo", "/fo", res.to_str().unwrap_or(""), rc.to_str().unwrap_or("")])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn try_windres_coff(rc: &std::path::Path, obj: &std::path::Path) -> bool {
    // windres with --output-format=coff produces a COFF object GNU ld can link directly.
    std::process::Command::new("windres")
        .args([
            rc.to_str().unwrap_or(""),
            "--output-format=coff",
            "-o",
            obj.to_str().unwrap_or(""),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn find_winsdk_rc() -> Option<String> {
    let kits = std::path::Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    if !kits.exists() {
        return None;
    }
    let mut versions: Vec<_> = std::fs::read_dir(kits)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    versions.sort();
    let rc = versions.last()?.join("x64").join("rc.exe");
    if rc.exists() { rc.to_str().map(str::to_string) } else { None }
}
