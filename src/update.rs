use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::exec;

const REPO: &str = "openape-ai/escapes";
const GITHUB_API: &str = "https://api.github.com/repos";

pub fn self_update() -> Result<(), Error> {
    let current = env!("CARGO_PKG_VERSION");
    eprintln!("escapes v{current} — checking for updates…");

    // 1. Fetch latest release from GitHub
    let url = format!("{GITHUB_API}/{REPO}/releases/latest");
    let release: serde_json::Value = ureq::get(&url)
        .set("Accept", "application/vnd.github+json")
        .set("User-Agent", "escapes-updater")
        .call()
        .map_err(|e| Error::Update(format!("failed to check for updates: {e}")))?
        .into_json()
        .map_err(|e| Error::Update(format!("invalid release JSON: {e}")))?;

    let latest = release["tag_name"]
        .as_str()
        .ok_or_else(|| Error::Update("missing tag_name in release".into()))?
        .strip_prefix('v')
        .unwrap_or(release["tag_name"].as_str().unwrap());

    if latest == current {
        eprintln!("already up to date (v{current})");
        return Ok(());
    }

    eprintln!("updating v{current} → v{latest}");

    // 2. Determine platform
    let target = target_triple()?;
    let tarball_name = format!("escapes-v{latest}-{target}.tar.gz");
    let checksums_name = "checksums-sha256.txt";

    // 3. Find asset URLs
    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| Error::Update("no assets in release".into()))?;

    let tarball_url = find_asset_url(assets, &tarball_name)?;
    let checksums_url = find_asset_url(assets, checksums_name)?;

    // 4. Download checksum file
    let checksums_text = download_text(&checksums_url)?;

    // 5. Find expected checksum for our tarball
    let expected_hash = checksums_text
        .lines()
        .find(|line| line.contains(&tarball_name))
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(|| Error::Update(format!("checksum not found for {tarball_name}")))?
        .to_string();

    // 6. Download tarball
    eprintln!("downloading {tarball_name}…");
    let tarball_bytes = download_bytes(&tarball_url)?;

    // 7. Verify checksum
    let actual_hash = hex::encode(Sha256::digest(&tarball_bytes));
    if actual_hash != expected_hash {
        return Err(Error::Update(format!(
            "checksum mismatch: expected {expected_hash}, got {actual_hash}"
        )));
    }
    eprintln!("checksum verified");

    // 8. Extract binary from tarball
    let new_binary = extract_binary(&tarball_bytes, latest, target)?;

    // 9. Get own path
    let self_path = std::env::current_exe()
        .map_err(|e| Error::Update(format!("cannot determine own path: {e}")))?
        .canonicalize()
        .map_err(|e| Error::Update(format!("cannot canonicalize own path: {e}")))?;

    // 10. Elevate to root (via saved set-user-ID)
    exec::elevate()?;

    // 11. Atomic replace
    let new_path = self_path.with_extension("new");
    fs::write(&new_path, &new_binary)
        .map_err(|e| Error::Update(format!("failed to write {}: {e}", new_path.display())))?;

    // Set ownership and permissions (root:wheel, 4755)
    set_setuid_root(&new_path)?;

    // Atomic rename
    fs::rename(&new_path, &self_path)
        .map_err(|e| Error::Update(format!("failed to replace binary: {e}")))?;

    eprintln!("updated to v{latest}");
    Ok(())
}

fn target_triple() -> Result<&'static str, Error> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu"),
        (os, arch) => Err(Error::Update(format!("unsupported platform: {os}/{arch}"))),
    }
}

fn find_asset_url(assets: &[serde_json::Value], name: &str) -> Result<String, Error> {
    assets
        .iter()
        .find(|a| a["name"].as_str() == Some(name))
        .and_then(|a| a["browser_download_url"].as_str())
        .map(String::from)
        .ok_or_else(|| Error::Update(format!("asset '{name}' not found in release")))
}

fn download_text(url: &str) -> Result<String, Error> {
    ureq::get(url)
        .set("User-Agent", "escapes-updater")
        .call()
        .map_err(|e| Error::Update(format!("download failed: {e}")))?
        .into_string()
        .map_err(|e| Error::Update(format!("invalid response: {e}")))
}

fn download_bytes(url: &str) -> Result<Vec<u8>, Error> {
    let response = ureq::get(url)
        .set("User-Agent", "escapes-updater")
        .call()
        .map_err(|e| Error::Update(format!("download failed: {e}")))?;

    let mut bytes = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| Error::Update(format!("failed to read response: {e}")))?;
    Ok(bytes)
}

fn extract_binary(tarball: &[u8], version: &str, target: &str) -> Result<Vec<u8>, Error> {
    use flate2::read::GzDecoder;
    use std::io::Cursor;

    let decoder = GzDecoder::new(Cursor::new(tarball));
    let mut archive = tar::Archive::new(decoder);

    let expected_path = format!("escapes-v{version}-{target}/escapes");

    for entry in archive
        .entries()
        .map_err(|e| Error::Update(format!("failed to read tarball: {e}")))?
    {
        let mut entry =
            entry.map_err(|e| Error::Update(format!("failed to read tar entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| Error::Update(format!("invalid tar path: {e}")))?
            .to_path_buf();

        if path == PathBuf::from(&expected_path) {
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .map_err(|e| Error::Update(format!("failed to read binary from tarball: {e}")))?;
            return Ok(buf);
        }
    }

    Err(Error::Update(format!(
        "binary not found in tarball at {expected_path}"
    )))
}

fn set_setuid_root(path: &PathBuf) -> Result<(), Error> {
    // chown root:wheel (uid 0, gid 0)
    std::os::unix::fs::chown(path, Some(0), Some(0))
        .map_err(|e| Error::Update(format!("failed to chown: {e}")))?;

    // chmod 4755 (setuid + rwxr-xr-x)
    fs::set_permissions(path, fs::Permissions::from_mode(0o4755))
        .map_err(|e| Error::Update(format!("failed to chmod: {e}")))?;

    Ok(())
}
