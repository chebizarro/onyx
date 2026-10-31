#[cfg(not(target_os = "android"))]
use keyring::Entry;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use percent_encoding::percent_decode_str;
#[cfg(not(target_os = "android"))]
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
#[cfg(not(target_os = "android"))]
use std::thread;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use walkdir::WalkDir;

// OpenCode server process management
struct OpenCodeServerState {
    process: Option<Child>,
    port: Option<u16>,
}

impl Default for OpenCodeServerState {
    fn default() -> Self {
        Self {
            process: None,
            port: None,
        }
    }
}

type SharedOpenCodeServerState = Arc<Mutex<OpenCodeServerState>>;

/// The configured notebook root, in the spelling the user chose (settings.json),
/// held in process so that every vault command validates against *this* and
/// never against a root the caller hands over per call (SV-40). It follows the
/// configuration surface the user also sees: the persisted setting at startup,
/// then `save_settings` / `set_vault_scope`. That removes silent per-call root
/// selection; it does not stop a hostile webview from reconfiguring the notebook
/// through those same commands — a natively authorised folder picker is the
/// follow-up that would.
#[derive(Default)]
struct VaultScopeState {
    notebook: Option<String>,
}

type SharedVaultScope = Arc<Mutex<VaultScopeState>>;

fn configured_notebook(state: &SharedVaultScope) -> Result<String, String> {
    state
        .lock()
        .notebook
        .clone()
        .ok_or_else(|| "No vault is configured".to_string())
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AppSettings {
    #[serde(default)]
    pub vault_path: Option<String>,
    #[serde(default)]
    pub show_terminal: bool,
}

fn get_config_dir_with_app(app: &AppHandle) -> PathBuf {
    #[cfg(target_os = "android")]
    {
        // On Android, use the app's data directory
        app.path()
            .app_data_dir()
            .unwrap_or_else(|_| PathBuf::from("/data/data/com.onyxnotes.dev/files"))
            .join("config")
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app; // Unused on desktop
        // Try multiple sources for home directory to handle various launch contexts
        // This is important on Windows where HOME may not be set when launched via protocol handler
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| {
                // Last resort: use dirs crate which handles platform-specific logic
                dirs::home_dir()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| ".".to_string())
            });
        PathBuf::from(home).join(".config").join("onyx")
    }
}



#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PlatformInfo {
    pub platform: String,
    pub default_vault_path: Option<String>,
}

#[tauri::command]
fn get_platform_info(app: AppHandle) -> PlatformInfo {
    let platform = if cfg!(target_os = "android") {
        "android".to_string()
    } else if cfg!(target_os = "ios") {
        "ios".to_string()
    } else if cfg!(target_os = "macos") {
        "macos".to_string()
    } else if cfg!(target_os = "windows") {
        "windows".to_string()
    } else {
        "linux".to_string()
    };

    let default_vault_path = if cfg!(target_os = "android") || cfg!(target_os = "ios") {
        // On mobile, use the app's data directory
        app.path()
            .app_data_dir()
            .ok()
            .map(|p| p.join("Onyx").to_string_lossy().to_string())
    } else {
        // On desktop, use Documents/Onyx
        app.path()
            .document_dir()
            .ok()
            .map(|p| p.join("Onyx").to_string_lossy().to_string())
    };

    PlatformInfo {
        platform,
        default_vault_path,
    }
}

fn get_settings_path(app: &AppHandle) -> PathBuf {
    get_config_dir_with_app(app).join("settings.json")
}

/// Read the configured vault path from settings.json exactly as the user spelled
/// it, without resolving symlinks.
///
/// This is the spelling the frontend sends with every path, so it is the one to
/// hand `validate_vault_path`. Canonicalizing the vault first breaks the check in
/// the other direction: with `~/Vault -> /mnt/data/Vault` the roots collapse to
/// `/mnt/data/Vault` while the requested path is still `~/Vault/...`, and nothing
/// matches. `validate_vault_path` adds the canonical spelling as a second allowed
/// root, so passing the settings spelling accepts both and passing the canonical
/// one accepts only itself.
fn get_configured_vault_setting(app: &AppHandle) -> Option<String> {
    let settings_path = get_settings_path(app);
    let content = fs::read_to_string(&settings_path).ok()?;
    let settings: AppSettings = serde_json::from_str(&content).ok()?;
    settings.vault_path
}

/// Resolve `.` and `..` components without touching the filesystem, so that a
/// symlink in the middle of the path is left intact rather than followed.
///
/// A leading `..` that would climb above the root is an error: it is the one
/// shape that lets a caller escape the vault lexically.
fn lexically_normalize(path: &Path) -> Result<PathBuf, String> {
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                // `pop` returns false once we are back at the prefix/root.
                if !resolved.pop() {
                    return Err(format!(
                        "Invalid path: '{}' climbs above the filesystem root",
                        path.display()
                    ));
                }
            }
            other => resolved.push(other.as_os_str()),
        }
    }
    Ok(resolved)
}

/// Validates that a path is within the allowed vault directory.
/// Returns the normalized path if valid, or an error if path traversal is detected.
///
/// Containment is decided **lexically**, not by `canonicalize()`. Canonicalizing
/// first resolves symlinks, so a directory the user deliberately linked into
/// their vault (`Vault/Projects -> ~/Projects/onyx`) resolved to a path outside
/// the vault and every file under it was rejected — while still being listed in
/// the sidebar, because the tree builder never canonicalized. Linked folders are
/// an intentional grant by the person who created the link, so we follow them;
/// `..` escapes are still rejected, which is what the traversal guard is for.
///
/// **Callers must use the returned `PathBuf` and never the string they passed in.**
/// This is the whole of the rule's safety, not hygiene. `..` after a symlink hop
/// normalizes differently from how the OS would resolve it — e.g.
/// `<vault>/links/dir-outside/../../outside/notes/x.md` is allowed and names
/// `<vault>/outside/notes/x.md`, while the OS would have resolved it against the
/// link's target and reached somewhere else entirely. A caller that validates
/// `&p` and then touches `&p` is checking one path and operating on another.
/// All current call sites use the return value; a new one that does not is an
/// immediate escape, and nothing but this comment enforces it.
fn validate_vault_path(path: &str, vault_path: &str) -> Result<PathBuf, String> {
    contain_in_vault(path, vault_path).map(|(normalized, _root)| normalized)
}

/// The vault-relative remainder of `path` under the same lexical containment
/// rule as `validate_vault_path`: empty for the root itself, otherwise only
/// `Normal` components. This is what the managed (no-follow) primitives walk,
/// component by component, from the canonical root.
fn vault_relative_path(path: &str, vault_path: &str) -> Result<PathBuf, String> {
    let (normalized, root) = contain_in_vault(path, vault_path)?;
    Ok(normalized
        .strip_prefix(&root)
        .map(Path::to_path_buf)
        .unwrap_or_default())
}

/// Lexical containment: returns the normalized path together with the root
/// spelling it was found under. See `validate_vault_path` for the rule.
fn contain_in_vault(path: &str, vault_path: &str) -> Result<(PathBuf, PathBuf), String> {
    let path = Path::new(path);
    let vault = Path::new(vault_path);

    if path.is_relative() {
        return Err(format!(
            "Invalid path: '{}' must be absolute",
            path.display()
        ));
    }

    let normalized_path = lexically_normalize(path)?;
    let normalized_vault = lexically_normalize(vault)?;

    // The vault itself may live behind a symlink, in which case callers can hold
    // either spelling of it. Accept both, and only the vault's own two forms —
    // this is a prefix test on the vault, never on the requested path.
    let mut allowed_roots = vec![normalized_vault.clone()];
    if let Ok(canonical_vault) = vault.canonicalize() {
        // A root link's target may retain an ancestor alias (on macOS, /var
        // rather than /private/var). It is another spelling of this root, not
        // permission to canonicalize arbitrary requested descendants.
        if let Ok(target) = fs::read_link(&normalized_vault) {
            let target = if target.is_absolute() {
                target
            } else {
                normalized_vault.parent().unwrap_or(Path::new("/")).join(target)
            };
            let target = lexically_normalize(&target)?;
            if target.canonicalize().ok().as_ref() == Some(&canonical_vault) {
                allowed_roots.push(target);
            }
        }
        if canonical_vault != normalized_vault {
            allowed_roots.push(canonical_vault);
        }
    }

    // Longest match first: when one spelling of the root is itself a prefix of
    // another, the relative remainder must be computed from the deeper one.
    let root = allowed_roots
        .iter()
        .filter(|root| normalized_path.starts_with(root))
        .max_by_key(|root| root.components().count())
        .cloned()
        .ok_or_else(|| {
            format!(
                "Access denied: path '{}' is outside the vault directory",
                path.display()
            )
        })?;

    Ok((normalized_path, root))
}

/// Resolve the picked recovery path before writing, including symlink aliases.
#[tauri::command]
fn resolve_recovery_destination(path: String, notebook_path: String) -> Result<String, String> {
    let picked = Path::new(&path);
    if !picked.is_absolute() {
        return Err("Recovery destination must be absolute".into());
    }
    let notebook_path = Path::new(&notebook_path);
    if lexically_normalize(picked)?.starts_with(lexically_normalize(notebook_path)?) {
        return Err("Save recovery outside the notebook and its managed folders".into());
    }
    let notebook = notebook_path.canonicalize().map_err(|e| e.to_string())?;
    let resolved = if picked.exists() || fs::symlink_metadata(picked).is_ok() {
        picked.canonicalize().map_err(|e| e.to_string())?
    } else {
        let parent = picked.parent().ok_or("Recovery destination has no parent")?;
        let name = picked.file_name().ok_or("Recovery destination has no filename")?;
        parent.canonicalize().map_err(|e| e.to_string())?.join(name)
    };
    if resolved.starts_with(&notebook) {
        return Err("Save recovery outside the notebook and its managed folders".into());
    }
    resolved.to_str().map(str::to_owned).ok_or_else(|| "Recovery path is not UTF-8".into())
}

// ---------------------------------------------------------------------------
// Managed (shared-vault) file primitives: race-resistant confinement (SV-32)
// and atomic installation (SV-39).
//
// Accepted shared-view content is written by the engine with names a remote
// writer chose. The legacy commands above resolve such a name through any
// symlink the local user once planted (`mount/link -> ~/Private` plus an
// accepted `link/new.md` lands in `~/Private`). These primitives instead reach
// every component below the notebook root relative to the previous directory
// handle with `O_NOFOLLOW`, so the handles themselves prove containment and
// there is no pre-write `realpath` to race against (TOCTOU).
// ---------------------------------------------------------------------------

/// Prefix of the temporary file an atomic install writes beside its target.
/// Capture skips entries with this prefix and materialization refuses remote
/// entries carrying it (`src/lib/vault/filesystem.ts`), so a crash orphan is
/// never published as content.
const MANAGED_TEMP_PREFIX: &str = ".onyx-vault-tmp-";

/// Canonical root plus the lexical remainder below it for a managed operation.
///
/// The root is the configured notebook, which may itself be a symlink the user
/// chose (`~/Vault -> /mnt/data/Vault`): that hop is followed once, here, and
/// the canonical directory is then opened by pathname. Everything below it is
/// walked no-follow, so a link at the mount root or anywhere along the
/// destination fails instead of redirecting.
///
/// Threat-model boundary: the notebook root and its ancestors (`/Users/<me>`)
/// are trusted. Replacing one of them between `canonicalize` and the open needs
/// the user's own privileges, which already own every file in the notebook; the
/// race this closes is a link *inside* the notebook meeting a remote-chosen
/// name. Race resistance is claimed below the root, not above it.
fn managed_target(notebook: &str, path: &str) -> Result<(PathBuf, PathBuf), String> {
    let relative = vault_relative_path(path, notebook)?;
    let root = fs::canonicalize(notebook).map_err(|e| format!("Vault root is unavailable: {}", e))?;
    Ok((root, relative))
}

/// Splits a non-empty relative path into its parent and final component.
fn split_target(relative: &Path) -> Result<(&Path, &std::ffi::OsStr), String> {
    let name = relative
        .file_name()
        .ok_or_else(|| "The vault root itself cannot be the target of a managed operation".to_string())?;
    Ok((relative.parent().unwrap_or(Path::new("")), name))
}

/// Installs `data` at `path` atomically inside the notebook, creating missing
/// parent directories (never through a link).
fn managed_write_bytes(notebook: &str, path: &str, data: &[u8]) -> Result<(), String> {
    let (root, relative) = managed_target(notebook, path)?;
    let (parent, name) = split_target(&relative)?;
    let root = confined::open_root(&root)?;
    let dir = confined::descend(&root, parent, true)?;
    confined::write_atomic(&dir, name, |file| std::io::Write::write_all(file, data))
}

fn managed_read_bytes(notebook: &str, path: &str) -> Result<Vec<u8>, String> {
    let (root, relative) = managed_target(notebook, path)?;
    let (parent, name) = split_target(&relative)?;
    let root = confined::open_root(&root)?;
    let dir = confined::descend(&root, parent, false)?;
    confined::read(&dir, name)
}

fn managed_create_folder(notebook: &str, path: &str) -> Result<(), String> {
    let (root, relative) = managed_target(notebook, path)?;
    let root = confined::open_root(&root)?;
    confined::descend(&root, &relative, true).map(drop)
}

fn managed_remove(notebook: &str, path: &str) -> Result<(), String> {
    let (root, relative) = managed_target(notebook, path)?;
    let (parent, name) = split_target(&relative)?;
    let root = confined::open_root(&root)?;
    let dir = confined::descend(&root, parent, false)?;
    confined::remove(&dir, name)
}

#[tauri::command]
fn managed_write_binary(scope: tauri::State<'_, SharedVaultScope>, path: String, data: Vec<u8>) -> Result<(), String> {
    managed_write_bytes(&configured_notebook(&scope)?, &path, &data)
}

#[tauri::command]
fn managed_read_binary(scope: tauri::State<'_, SharedVaultScope>, path: String) -> Result<tauri::ipc::Response, String> {
    managed_read_bytes(&configured_notebook(&scope)?, &path).map(tauri::ipc::Response::new)
}

#[tauri::command]
fn managed_mkdir(scope: tauri::State<'_, SharedVaultScope>, path: String) -> Result<(), String> {
    managed_create_folder(&configured_notebook(&scope)?, &path)
}

#[tauri::command]
fn managed_delete(scope: tauri::State<'_, SharedVaultScope>, path: String) -> Result<(), String> {
    managed_remove(&configured_notebook(&scope)?, &path)
}

#[cfg(unix)]
mod confined {
    //! Directory-handle-relative primitives. Everything below the root is reached
    //! through `openat(dirfd, component, O_NOFOLLOW | O_DIRECTORY)`, so the only
    //! way to a file is through real directories inside the root.
    use rustix::fs::{fchmod, fsync, mkdirat, openat, renameat, statat, unlinkat, AtFlags, Dir, FileType, Mode, OFlags, RawMode, CWD};
    use rustix::io::Errno;
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io::{self, Read};
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path};
    use std::sync::atomic::{AtomicU64, Ordering};

    pub type DirHandle = OwnedFd;

    fn link_error(name: &OsStr) -> String {
        format!(
            "Access denied: '{}' is a symbolic link; managed vault paths never follow links",
            Path::new(name).display()
        )
    }

    /// `O_NOFOLLOW` on a link surfaces as `ELOOP` on Linux and, together with
    /// `O_DIRECTORY`, as `ENOTDIR` on macOS; name the link in either case.
    fn describe(dir: &DirHandle, name: &OsStr, errno: Errno) -> String {
        if matches!(errno, Errno::LOOP | Errno::NOTDIR)
            && matches!(statat(dir, name, AtFlags::SYMLINK_NOFOLLOW), Ok(stat) if FileType::from_raw_mode(stat.st_mode as _) == FileType::Symlink)
        {
            return link_error(name);
        }
        format!("'{}': {}", Path::new(name).display(), io::Error::from(errno))
    }

    /// Opens the canonical root: the one place a link (the user's own) is followed.
    pub fn open_root(root: &Path) -> Result<DirHandle, String> {
        openat(CWD, root, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
            .map_err(|e| format!("Vault root is unavailable: {}", io::Error::from(e)))
    }

    fn open_dir(dir: &DirHandle, name: &OsStr) -> Result<DirHandle, String> {
        openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| describe(dir, name, e))
    }

    /// Walks `relative` from `root` one component at a time, never following a
    /// link. With `create`, missing directories are made on the way: `mkdirat`
    /// then open, so a link raced into the slot still fails the open. A directory
    /// this call created is flushed into its parent, so an install beneath it is
    /// durable as a whole, not just at its last level.
    pub fn descend(root: &DirHandle, relative: &Path, create: bool) -> Result<DirHandle, String> {
        let mut dir = root.try_clone().map_err(|e| e.to_string())?;
        for component in relative.components() {
            let name = match component {
                Component::Normal(name) => name,
                _ => return Err(format!("Invalid managed path component in '{}'", relative.display())),
            };
            if create {
                match mkdirat(&dir, name, Mode::from_raw_mode(0o755)) {
                    Ok(()) => fsync(&dir).map_err(|e| describe(&dir, name, e))?,
                    Err(Errno::EXIST) => {}
                    Err(e) => return Err(describe(&dir, name, e)),
                }
            }
            dir = open_dir(&dir, name)?;
        }
        Ok(dir)
    }

    /// `lstat`-style type of `name` under `dir`; `None` when absent.
    fn file_type(dir: &DirHandle, name: &OsStr) -> Result<Option<FileType>, String> {
        match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(FileType::from_raw_mode(stat.st_mode as _))),
            Err(Errno::NOENT) => Ok(None),
            Err(e) => Err(describe(dir, name, e)),
        }
    }

    /// Durability of the installed bytes, before the rename makes them live.
    ///
    /// Linux: `fsync(2)`; with the directory `fsync` after the rename, both the
    /// data and the entry are on the device when the command returns.
    ///
    /// macOS: `F_FULLFSYNC`. `fsync(2)` there only hands data to the drive
    /// without flushing its cache, so a power loss could persist the rename and
    /// not the bytes — and a torn live file would be taken for a local edit by
    /// the next capture and published. The full flush costs milliseconds per
    /// file, paid once per materialised file; flushing once per journal batch is
    /// the optimisation if that ever matters. Volumes that reject the fcntl
    /// (network shares, FAT) fall back to `fsync`.
    fn flush_file(file: &File) -> io::Result<()> {
        #[cfg(target_vendor = "apple")]
        match rustix::fs::fcntl_fullfsync(file) {
            Ok(()) => return Ok(()),
            Err(Errno::NOTSUP) | Err(Errno::INVAL) | Err(Errno::NOTTY) => {}
            Err(e) => return Err(io::Error::from(e)),
        }
        file.sync_all()
    }

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn temp_name() -> OsString {
        OsString::from(format!(
            "{}{}-{}",
            super::MANAGED_TEMP_PREFIX,
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// Installs a file atomically: a fresh `O_EXCL` temporary beside the target is
    /// filled, flushed, then renamed over `name` within the same directory handle.
    /// Any failure before the rename leaves the live file untouched and removes
    /// the temporary. An error from the directory `fsync` after the rename means
    /// the install is in place but its durability is unconfirmed — callers treat
    /// every error as "re-verify the path", never as "nothing changed" (the
    /// materialization journal does exactly that). A crash leaves at most a
    /// `.onyx-vault-tmp-*` orphan. A regular file being replaced keeps its
    /// permission bits; a new file gets `0644` under the umask, as `fs::write`
    /// would.
    pub fn write_atomic(
        dir: &DirHandle,
        name: &OsStr,
        fill: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> Result<(), String> {
        let existing = match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Some(stat),
            Err(Errno::NOENT) => None,
            Err(e) => return Err(describe(dir, name, e)),
        };
        let existing_kind = existing.as_ref().map(|stat| FileType::from_raw_mode(stat.st_mode as _));
        if existing_kind == Some(FileType::Symlink) {
            return Err(link_error(name));
        }
        let preserved_mode = existing
            .filter(|_| existing_kind == Some(FileType::RegularFile))
            .map(|stat| Mode::from_raw_mode((stat.st_mode as RawMode) & 0o7777));
        let (temp, fd) = loop {
            let temp = temp_name();
            match openat(
                dir,
                temp.as_os_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o644),
            ) {
                Ok(fd) => break (temp, fd),
                Err(Errno::EXIST) => continue,
                Err(e) => return Err(describe(dir, &temp, e)),
            }
        };
        let install = || -> io::Result<()> {
            let mut file = File::from(fd);
            fill(&mut file)?;
            if let Some(mode) = preserved_mode {
                fchmod(&file, mode).map_err(io::Error::from)?;
            }
            flush_file(&file)?;
            drop(file);
            renameat(dir, temp.as_os_str(), dir, name).map_err(io::Error::from)?;
            fsync(dir).map_err(io::Error::from)
        };
        if let Err(e) = install() {
            let _ = unlinkat(dir, temp.as_os_str(), AtFlags::empty());
            return Err(format!("Failed to install '{}': {}", Path::new(name).display(), e));
        }
        Ok(())
    }

    pub fn read(dir: &DirHandle, name: &OsStr) -> Result<Vec<u8>, String> {
        let fd = openat(dir, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
            .map_err(|e| describe(dir, name, e))?;
        let mut bytes = Vec::new();
        File::from(fd)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("'{}': {}", Path::new(name).display(), e))?;
        Ok(bytes)
    }

    /// Removes `name` under `dir`: a link is unlinked, never followed; a directory
    /// is emptied through its own handle before `unlinkat(REMOVEDIR)`.
    pub fn remove(dir: &DirHandle, name: &OsStr) -> Result<(), String> {
        let kind = file_type(dir, name)?.ok_or_else(|| describe(dir, name, Errno::NOENT))?;
        remove_entry(dir, name, kind)
    }

    fn remove_entry(dir: &DirHandle, name: &OsStr, kind: FileType) -> Result<(), String> {
        if kind != FileType::Directory {
            return unlinkat(dir, name, AtFlags::empty()).map_err(|e| describe(dir, name, e));
        }
        let child = open_dir(dir, name)?;
        for (child_name, child_kind) in list(&child)? {
            let child_kind = match child_kind {
                Some(kind) => kind,
                None => file_type(&child, &child_name)?.ok_or_else(|| describe(&child, &child_name, Errno::NOENT))?,
            };
            remove_entry(&child, &child_name, child_kind)?;
        }
        drop(child);
        unlinkat(dir, name, AtFlags::REMOVEDIR).map_err(|e| describe(dir, name, e))
    }

    fn list(dir: &DirHandle) -> Result<Vec<(OsString, Option<FileType>)>, String> {
        let mut children = Vec::new();
        for entry in Dir::read_from(dir).map_err(|e| io::Error::from(e).to_string())? {
            let entry = entry.map_err(|e| io::Error::from(e).to_string())?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let kind = match entry.file_type() {
                FileType::Unknown => None,
                kind => Some(kind),
            };
            children.push((OsStr::from_bytes(name).to_os_string(), kind));
        }
        Ok(children)
    }
}

#[cfg(not(unix))]
mod confined {
    //! Verify-then-operate fallback: std has no directory-handle-relative open on
    //! this platform, so each component is checked with `symlink_metadata` before
    //! use and the install rename is `MoveFileEx(REPLACE_EXISTING)`. The window
    //! between a check and its use is a known residual here; the Unix module has
    //! none.
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File};
    use std::io::{self, Read};
    use std::path::{Component, Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    pub struct DirHandle(PathBuf);

    fn link_error(path: &Path) -> String {
        format!(
            "Access denied: '{}' is a symbolic link; managed vault paths never follow links",
            path.display()
        )
    }

    pub fn open_root(root: &Path) -> Result<DirHandle, String> {
        if !root.is_dir() {
            return Err(format!("Vault root is unavailable: {}", root.display()));
        }
        Ok(DirHandle(root.to_path_buf()))
    }

    fn check_not_link(path: &Path) -> Result<Option<fs::Metadata>, String> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => Err(link_error(path)),
            Ok(meta) => Ok(Some(meta)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("'{}': {}", path.display(), e)),
        }
    }

    pub fn descend(root: &DirHandle, relative: &Path, create: bool) -> Result<DirHandle, String> {
        let mut current = root.0.clone();
        for component in relative.components() {
            let name = match component {
                Component::Normal(name) => name,
                _ => return Err(format!("Invalid managed path component in '{}'", relative.display())),
            };
            current.push(name);
            match check_not_link(&current)? {
                Some(meta) if meta.is_dir() => {}
                Some(_) => return Err(format!("'{}' is not a directory", current.display())),
                None if create => fs::create_dir(&current).map_err(|e| format!("'{}': {}", current.display(), e))?,
                None => return Err(format!("'{}': not found", current.display())),
            }
        }
        Ok(DirHandle(current))
    }

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn temp_name() -> OsString {
        OsString::from(format!(
            "{}{}-{}",
            super::MANAGED_TEMP_PREFIX,
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// `sync_all` is `FlushFileBuffers`; NTFS journals the rename itself, so no
    /// directory flush is attempted. Only a temporary this call created is ever
    /// removed on failure; a name a crash orphan still holds is skipped.
    pub fn write_atomic(
        dir: &DirHandle,
        name: &OsStr,
        fill: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> Result<(), String> {
        let target = dir.0.join(name);
        check_not_link(&target)?;
        let (temp, file) = loop {
            let temp = dir.0.join(temp_name());
            match File::options().write(true).create_new(true).open(&temp) {
                Ok(file) => break (temp, file),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("'{}': {}", temp.display(), e)),
            }
        };
        let install = |mut file: File| -> io::Result<()> {
            fill(&mut file)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, &target)
        };
        if let Err(e) = install(file) {
            let _ = fs::remove_file(&temp);
            return Err(format!("Failed to install '{}': {}", target.display(), e));
        }
        Ok(())
    }

    pub fn read(dir: &DirHandle, name: &OsStr) -> Result<Vec<u8>, String> {
        let target = dir.0.join(name);
        check_not_link(&target)?;
        let mut bytes = Vec::new();
        File::open(&target)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(|e| format!("'{}': {}", target.display(), e))?;
        Ok(bytes)
    }

    pub fn remove(dir: &DirHandle, name: &OsStr) -> Result<(), String> {
        let target = dir.0.join(name);
        let meta = fs::symlink_metadata(&target).map_err(|e| format!("'{}': {}", target.display(), e))?;
        let result = if meta.file_type().is_symlink() {
            // A directory link needs remove_dir here; neither form follows it.
            fs::remove_file(&target).or_else(|_| fs::remove_dir(&target))
        } else if meta.is_dir() {
            fs::remove_dir_all(&target)
        } else {
            fs::remove_file(&target)
        };
        result.map_err(|e| format!("'{}': {}", target.display(), e))
    }
}

/// Check if a path is within the config directory (for settings, not vault files)
#[allow(dead_code)]
fn is_config_path(path: &str, app: &AppHandle) -> bool {
    let path = Path::new(path);
    let config_dir = get_config_dir_with_app(app);
    
    if let (Ok(canonical_path), Ok(canonical_config)) = (path.canonicalize(), config_dir.canonicalize()) {
        canonical_path.starts_with(&canonical_config)
    } else {
        false
    }
}

#[tauri::command]
fn load_settings(app: AppHandle) -> Result<AppSettings, String> {
    let path = get_settings_path(&app);
    if !path.exists() {
        return Ok(AppSettings::default());
    }
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&content).map_err(|e| e.to_string())
}

#[tauri::command]
fn save_settings(
    app: AppHandle,
    scope: tauri::State<'_, SharedVaultScope>,
    settings: AppSettings,
) -> Result<(), String> {
    let config_dir = get_config_dir_with_app(&app);
    fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;

    let path = get_settings_path(&app);
    let content = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    fs::write(&path, content).map_err(|e| e.to_string())?;
    // The persisted configuration is the authority the commands validate against,
    // and a save replaces the whole file (the frontend always sends every field),
    // so the in-process copy mirrors it exactly: a save without a vault path
    // leaves no notebook configured, in the file and here alike.
    scope.lock().notebook = settings.vault_path;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileEntry {
    name: String,
    path: String,
    #[serde(rename = "isDirectory")]
    is_directory: bool,
    /// Set on sidebar entries that are symbolic links. The sidebar follows links
    /// (a linked folder is the owner's grant), so the flag is how the frontend
    /// knows which entries need filesystem identity, not spelling, to decide
    /// whether they alias a managed shared-vault mount (SV-42).
    #[serde(rename = "isSymlink", default, skip_serializing_if = "Option::is_none")]
    is_symlink: Option<bool>,
    children: Option<Vec<FileEntry>>,
}

// Asset entry for embedded files (images, audio, video, PDF)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AssetEntry {
    pub name: String,
    pub path: String,
    pub extension: String,
    pub relative_path: String,
}

// Supported asset extensions
const IMAGE_EXTENSIONS: &[&str] = &["avif", "bmp", "gif", "jpeg", "jpg", "png", "svg", "webp"];
const AUDIO_EXTENSIONS: &[&str] = &["flac", "m4a", "mp3", "ogg", "wav", "webm", "3gp"];
const VIDEO_EXTENSIONS: &[&str] = &["mkv", "mov", "mp4", "ogv", "webm"];
const PDF_EXTENSIONS: &[&str] = &["pdf"];
const DOCUMENT_EXTENSIONS: &[&str] = &["docx", "xlsx", "pptx"];

fn is_viewable_extension(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    if let Some(dot_pos) = name_lower.rfind('.') {
        let ext = &name_lower[dot_pos + 1..];
        IMAGE_EXTENSIONS.contains(&ext)
            || PDF_EXTENSIONS.contains(&ext)
            || DOCUMENT_EXTENSIONS.contains(&ext)
    } else {
        false
    }
}

fn is_embeddable_extension(ext: &str) -> bool {
    let ext_lower = ext.to_lowercase();
    IMAGE_EXTENSIONS.contains(&ext_lower.as_str())
        || AUDIO_EXTENSIONS.contains(&ext_lower.as_str())
        || VIDEO_EXTENSIONS.contains(&ext_lower.as_str())
        || PDF_EXTENSIONS.contains(&ext_lower.as_str())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SearchMatch {
    line: usize,
    content: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SearchResult {
    path: String,
    name: String,
    matches: Vec<SearchMatch>,
}

/// How deep the sidebar tree will descend. Linked folders can point anywhere,
/// so this is a backstop against a pathologically deep target as well as cycles.
const MAX_TREE_DEPTH: usize = 32;

fn build_file_tree(path: &Path) -> Vec<FileEntry> {
    let mut visited: Vec<PathBuf> = Vec::new();
    build_file_tree_inner(path, &mut visited, 0)
}

/// `visited` holds the canonical form of every directory on the current branch.
/// Because directory links are followed, `Vault/loop -> Vault` would otherwise
/// recurse until the stack ran out; re-entering a directory we are already
/// inside is the definition of a cycle, so we stop there.
fn build_file_tree_inner(path: &Path, visited: &mut Vec<PathBuf>, depth: usize) -> Vec<FileEntry> {
    build_file_tree_with_filter(path, visited, depth, true)
}

fn build_file_tree_with_filter(
    path: &Path,
    visited: &mut Vec<PathBuf>,
    depth: usize,
    sidebar_filter: bool,
) -> Vec<FileEntry> {
    let mut entries: Vec<FileEntry> = Vec::new();

    if depth >= MAX_TREE_DEPTH {
        return entries;
    }

    let canonical = path.canonicalize().ok();
    if let Some(canonical) = &canonical {
        if visited.contains(canonical) {
            return entries;
        }
        visited.push(canonical.clone());
    }

    if let Ok(read_dir) = fs::read_dir(path) {
        let mut items: Vec<_> = read_dir.filter_map(|e| e.ok()).collect();
        items.sort_by(|a, b| {
            let a_is_dir = a.path().is_dir();
            let b_is_dir = b.path().is_dir();
            match (a_is_dir, b_is_dir) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.file_name().cmp(&b.file_name()),
            }
        });

        for item in items {
            let item_path = item.path();
            let name = item.file_name().to_string_lossy().to_string();

            // Skip hidden files and folders
            if sidebar_filter && name.starts_with('.') {
                continue;
            }

            // Capture never follows local symlinks; the sidebar keeps its linked-folder behaviour.
            let is_symlink = item.file_type().map(|t| t.is_symlink()).unwrap_or(true);
            if !sidebar_filter && is_symlink {
                continue;
            }

            let is_dir = item_path.is_dir();

            // Only include markdown files, viewable files (images, PDFs, documents), and directories
            if sidebar_filter && !is_dir && !name.ends_with(".md") && !is_viewable_extension(&name) {
                continue;
            }

            let children = if is_dir {
                Some(build_file_tree_with_filter(
                    &item_path, visited, depth + 1, sidebar_filter,
                ))
            } else {
                None
            };

            entries.push(FileEntry {
                name,
                path: item_path.to_string_lossy().to_string(),
                is_directory: is_dir,
                is_symlink: if is_symlink { Some(true) } else { None },
                children,
            });
        }
    }

    if canonical.is_some() {
        visited.pop();
    }

    entries
}

// ---------------------------------------------------------------------------
// Vault file commands. Each `#[tauri::command]` is a thin wrapper that takes the
// notebook from `SharedVaultScope` and delegates to a `*_in(notebook, ...)`
// function; the inner functions are what the unit tests exercise. None of them
// accepts a root from the caller (SV-40).
//
// These are the legacy editor's commands: they follow symbolic links the user
// created inside the notebook (`writing_a_symlinked_note_writes_through_to_its_target`
// pins that ruling). The shared-vault engine uses the `managed_*` commands below,
// which never follow a link below the root.
// ---------------------------------------------------------------------------

#[tauri::command]
fn list_files(scope: tauri::State<'_, SharedVaultScope>, path: String) -> Result<Vec<FileEntry>, String> {
    list_files_in(&configured_notebook(&scope)?, &path)
}

fn list_files_in(notebook: &str, path: &str) -> Result<Vec<FileEntry>, String> {
    let path = validate_vault_path(path, notebook)?;
    if !path.exists() {
        return Err("Path does not exist".to_string());
    }
    Ok(build_file_tree(&path))
}

#[tauri::command]
fn list_files_all(scope: tauri::State<'_, SharedVaultScope>, path: String) -> Result<Vec<FileEntry>, String> {
    list_files_all_in(&configured_notebook(&scope)?, &path)
}

fn list_files_all_in(notebook: &str, path: &str) -> Result<Vec<FileEntry>, String> {
    let path = validate_vault_path(path, notebook)?;
    if !path.is_dir() {
        return Err("Path is not a directory".to_string());
    }
    let mut visited = Vec::new();
    Ok(build_file_tree_with_filter(&path, &mut visited, 0, false))
}

#[tauri::command]
fn read_file(scope: tauri::State<'_, SharedVaultScope>, path: String) -> Result<String, String> {
    read_file_in(&configured_notebook(&scope)?, &path)
}

fn read_file_in(notebook: &str, path: &str) -> Result<String, String> {
    let path = validate_vault_path(path, notebook)?;
    fs::read_to_string(&path).map_err(|e| e.to_string())
}

#[tauri::command]
fn write_file(scope: tauri::State<'_, SharedVaultScope>, path: String, content: String) -> Result<(), String> {
    write_file_in(&configured_notebook(&scope)?, &path, &content)
}

fn write_file_in(notebook: &str, path: &str, content: &str) -> Result<(), String> {
    let path = validate_vault_path(path, notebook)?;
    fs::write(&path, content).map_err(|e| e.to_string())
}

#[tauri::command]
fn write_binary_file(scope: tauri::State<'_, SharedVaultScope>, path: String, data: Vec<u8>) -> Result<(), String> {
    write_binary_file_in(&configured_notebook(&scope)?, &path, &data)
}

fn write_binary_file_in(notebook: &str, path: &str, data: &[u8]) -> Result<(), String> {
    let path = validate_vault_path(path, notebook)?;
    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&path, data).map_err(|e| e.to_string())
}

#[tauri::command]
fn read_binary_file(scope: tauri::State<'_, SharedVaultScope>, path: String) -> Result<tauri::ipc::Response, String> {
    // Return a raw IPC response so the frontend receives an ArrayBuffer instead of
    // a JSON number array (huge serialization overhead for large files like PDFs).
    read_binary_file_in(&configured_notebook(&scope)?, &path).map(tauri::ipc::Response::new)
}

fn read_binary_file_in(notebook: &str, path: &str) -> Result<Vec<u8>, String> {
    let path = validate_vault_path(path, notebook)?;
    fs::read(&path).map_err(|e| e.to_string())
}

#[tauri::command]
fn create_file(scope: tauri::State<'_, SharedVaultScope>, path: String) -> Result<(), String> {
    create_file_in(&configured_notebook(&scope)?, &path)
}

fn create_file_in(notebook: &str, path: &str) -> Result<(), String> {
    let path = validate_vault_path(path, notebook)?;
    if path.exists() {
        return Err("File already exists".to_string());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(path, "").map_err(|e| e.to_string())
}

#[tauri::command]
fn create_folder(scope: tauri::State<'_, SharedVaultScope>, path: String) -> Result<(), String> {
    create_folder_in(&configured_notebook(&scope)?, &path)
}

fn create_folder_in(notebook: &str, path: &str) -> Result<(), String> {
    let path = validate_vault_path(path, notebook)?;
    fs::create_dir_all(&path).map_err(|e| e.to_string())
}

/// Dynamically extend the plugin-fs scope to include the user's vault directory.
/// Called when the vault path is set so that plugin-fs operations (writeFile, mkdir, etc.)
/// can access the vault. This is the secure alternative to broadening static fs:scope —
/// only the specific vault directory chosen by the user is granted access at runtime.
#[tauri::command]
fn set_vault_scope(
    app: AppHandle,
    scope: tauri::State<'_, SharedVaultScope>,
    vault_path: String,
) -> Result<(), String> {
    use tauri_plugin_fs::FsExt;
    let path = Path::new(&vault_path);
    if !path.exists() || !path.is_dir() {
        return Err(format!("Vault path does not exist or is not a directory: {}", vault_path));
    }
    // Reject pathological scopes: the filesystem root and the home directory itself.
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("Invalid vault path: {}", e))?;
    if canonical.parent().is_none() {
        return Err("Vault path cannot be the filesystem root".to_string());
    }
    if let Some(home) = dirs::home_dir() {
        if let Ok(home_canonical) = home.canonicalize() {
            if canonical == home_canonical {
                return Err("Vault path cannot be the home directory itself".to_string());
            }
        }
    }
    app.fs_scope()
        .allow_directory(path, true)
        .map_err(|e| format!("Failed to add vault to fs scope: {}", e))?;
    // Settings spelling, not `canonical`: see `get_configured_vault_setting`.
    scope.lock().notebook = Some(vault_path.clone());
    println!("[Scope] Added vault to fs scope: {}", vault_path);
    Ok(())
}

#[tauri::command]
fn get_file_modified_time(path: String) -> Result<u64, String> {
    let metadata = fs::metadata(&path).map_err(|e| e.to_string())?;
    let modified = metadata.modified().map_err(|e| e.to_string())?;
    // Convert to Unix timestamp (seconds since epoch)
    let duration = modified
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?;
    Ok(duration.as_secs())
}

#[tauri::command]
fn file_exists(path: String) -> bool {
    Path::new(&path).exists()
}

#[tauri::command]
fn delete_file(scope: tauri::State<'_, SharedVaultScope>, path: String) -> Result<(), String> {
    delete_file_in(&configured_notebook(&scope)?, &path)
}

fn delete_file_in(notebook: &str, path: &str) -> Result<(), String> {
    let path = validate_vault_path(path, notebook)?;
    if path.is_dir() {
        fs::remove_dir_all(path).map_err(|e| e.to_string())
    } else {
        fs::remove_file(path).map_err(|e| e.to_string())
    }
}

#[tauri::command]
fn rename_file(scope: tauri::State<'_, SharedVaultScope>, old_path: String, new_path: String) -> Result<(), String> {
    rename_file_in(&configured_notebook(&scope)?, &old_path, &new_path)
}

fn rename_file_in(notebook: &str, old_path: &str, new_path: &str) -> Result<(), String> {
    let old_path = validate_vault_path(old_path, notebook)?;
    let new_path = validate_vault_path(new_path, notebook)?;
    fs::rename(&old_path, &new_path).map_err(|e| e.to_string())
}

#[tauri::command]
fn copy_file(scope: tauri::State<'_, SharedVaultScope>, source: String, dest: String) -> Result<(), String> {
    copy_file_in(&configured_notebook(&scope)?, &source, &dest)
}

fn copy_file_in(notebook: &str, source: &str, dest: &str) -> Result<(), String> {
    let source_path = validate_vault_path(source, notebook)?;
    let dest_path = validate_vault_path(dest, notebook)?;

    if source_path.is_dir() {
        // Copy directory recursively
        copy_dir_recursive(&source_path, &dest_path).map_err(|e| e.to_string())
    } else {
        fs::copy(&source_path, &dest_path)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Filesystem identity of a notebook path for the legacy-exclusion check (SV-42):
/// the canonical path when it exists, otherwise the canonical form of its
/// nearest existing ancestor joined with the remaining components, so a file
/// about to be created under an alias resolves to where it would really land.
/// Identity is advisory for the legacy sync's exclusion decision; it is not the
/// confinement boundary (that is the `managed_*` traversal above).
#[tauri::command]
fn resolve_real_path(scope: tauri::State<'_, SharedVaultScope>, path: String) -> Result<String, String> {
    resolve_real_path_in(&configured_notebook(&scope)?, &path)
}

fn resolve_real_path_in(notebook: &str, path: &str) -> Result<String, String> {
    let normalized = validate_vault_path(path, notebook)?;
    let mut existing = normalized.as_path();
    let mut missing: Vec<&std::ffi::OsStr> = Vec::new();
    while fs::symlink_metadata(existing).is_err() {
        let name = existing
            .file_name()
            .ok_or_else(|| format!("'{}' has no existing ancestor", normalized.display()))?;
        missing.push(name);
        existing = existing
            .parent()
            .ok_or_else(|| format!("'{}' has no existing ancestor", normalized.display()))?;
    }
    let mut resolved = fs::canonicalize(existing).map_err(|e| e.to_string())?;
    for name in missing.into_iter().rev() {
        resolved.push(name);
    }
    resolved
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| "Path is not UTF-8".to_string())
}

#[tauri::command]
fn open_in_default_app(path: String) -> Result<(), String> {
    // Validate the path exists and resolve it to an absolute canonical path before
    // handing it to any external program (prevents injection / opening bogus paths).
    let p = Path::new(&path);
    if !p.exists() {
        return Err(format!("Path does not exist: {}", path));
    }
    let canonical = p.canonicalize().map_err(|e| format!("Invalid path: {}", e))?;
    if !canonical.is_file() {
        return Err(format!("Path is not a file: {}", path));
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(&canonical)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(&canonical)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", &canonical.to_string_lossy()])
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = canonical;
        return Err("Opening files in the default app is not supported on this platform".to_string());
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    Ok(())
}

#[tauri::command]
fn show_in_folder(path: String) -> Result<(), String> {
    let path = Path::new(&path);
    let folder = if path.is_file() {
        path.parent().unwrap_or(path)
    } else {
        path
    };

    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(folder)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(folder)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "windows")]
    {
        Command::new("explorer")
            .arg(folder)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileStats {
    pub size: u64,
    pub created: u64,
    pub modified: u64,
}

#[tauri::command]
fn get_file_stats(path: String) -> Result<FileStats, String> {
    let metadata = fs::metadata(&path).map_err(|e| e.to_string())?;

    let size = metadata.len();

    let created = metadata
        .created()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let modified = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(FileStats {
        size,
        created,
        modified,
    })
}

#[tauri::command]
async fn search_files(
    scope: tauri::State<'_, SharedVaultScope>,
    path: String,
    query: String,
) -> Result<Vec<SearchResult>, String> {
    const MAX_RESULTS: usize = 50;
    const MAX_MATCHES_PER_FILE: usize = 5;

    // Security: only allow searching within the configured vault. Same lexical
    // containment rule as validate_vault_path — canonicalizing here put every
    // linked folder out of scope of search. Take the vault in its settings
    // spelling, not canonicalized: the frontend sends paths in that spelling, and
    // a canonical vault root cannot match them when the vault itself is a symlink.
    let vault_str = configured_notebook(&scope)?;
    let root = validate_vault_path(&path, &vault_str)
        .map_err(|_| "Access denied: search path is outside the vault directory".to_string())?;

    let mut results: Vec<SearchResult> = Vec::new();
    let query_lower = query.to_lowercase();

    // Search was unbounded before linked folders were followed; the depth cap is
    // new here and prunes silently, so count what it cut. A vault deeper than the
    // cap returns fewer results with no other signal, which is a day lost to
    // "search says the note does not exist".
    let truncated_at_depth = std::cell::Cell::new(0usize);

    for entry in WalkDir::new(&root)
        // Follow linked folders so search covers the same tree the sidebar shows.
        // WalkDir detects link cycles itself and surfaces them as an Err, which
        // the filter_map below drops.
        .follow_links(true)
        .max_depth(MAX_TREE_DEPTH)
        .into_iter()
        // Skip hidden files/directories (e.g. .git, .obsidian) entirely
        .filter_entry(|e| {
            e.depth() == 0 || !e.file_name().to_string_lossy().starts_with('.')
        })
        .filter_map(|e| e.ok())
        .inspect(|e| {
            // A directory handed back at the cap is one whose contents were never
            // walked — that is exactly what got dropped.
            if e.depth() == MAX_TREE_DEPTH && e.file_type().is_dir() {
                truncated_at_depth.set(truncated_at_depth.get() + 1);
            }
        })
        .filter(|e| {
            e.path().is_file() && e.path().extension().map(|ext| ext == "md").unwrap_or(false)
        })
    {
        let file_path = entry.path();
        if let Ok(content) = fs::read_to_string(file_path) {
            let mut matches: Vec<SearchMatch> = Vec::new();

            for (line_num, line) in content.lines().enumerate() {
                if line.to_lowercase().contains(&query_lower) {
                    matches.push(SearchMatch {
                        line: line_num + 1,
                        content: line.chars().take(100).collect(),
                    });
                    if matches.len() >= MAX_MATCHES_PER_FILE {
                        break;
                    }
                }
            }

            if !matches.is_empty() {
                results.push(SearchResult {
                    path: file_path.to_string_lossy().to_string(),
                    name: file_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    matches,
                });
                if results.len() >= MAX_RESULTS {
                    break;
                }
            }
        }
    }

    if truncated_at_depth.get() > 0 {
        log::warn!(
            "[Search] depth cap {} reached: {} director{} left unsearched under {}. \
             Results may be incomplete.",
            MAX_TREE_DEPTH,
            truncated_at_depth.get(),
            if truncated_at_depth.get() == 1 { "y" } else { "ies" },
            root.display()
        );
    }

    Ok(results)
}

#[tauri::command]
async fn list_assets(scope: tauri::State<'_, SharedVaultScope>, path: String) -> Result<Vec<AssetEntry>, String> {
    let mut assets: Vec<AssetEntry> = Vec::new();
    let vault_path = validate_vault_path(&path, &configured_notebook(&scope)?)?;
    let path = vault_path.to_string_lossy().to_string();
    let vault_path = Path::new(&path);

    if !vault_path.exists() {
        return Err("Path does not exist".to_string());
    }

    for entry in WalkDir::new(&path)
        .into_iter()
        // Prune hidden files and directories (e.g. .git) instead of descending into them
        .filter_entry(|e| {
            e.depth() == 0 || !e.file_name().to_string_lossy().starts_with('.')
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
    {
        let file_path = entry.path();

        // Check if it's an embeddable file type
        if let Some(ext) = file_path.extension() {
            let ext_str = ext.to_string_lossy().to_string();
            if is_embeddable_extension(&ext_str) {
                let name = file_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();

                let full_path = file_path.to_string_lossy().to_string();

                // Calculate relative path from vault root
                let relative_path = file_path
                    .strip_prefix(vault_path)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .to_string();

                assets.push(AssetEntry {
                    name,
                    path: full_path,
                    extension: ext_str.to_lowercase(),
                    relative_path,
                });
            }
        }
    }

    Ok(assets)
}

/// Start the OpenCode server in the background
/// This spawns `opencode serve --port <port>` and tracks the process for cleanup
/// Works on Windows, macOS, and Linux
#[tauri::command]
fn start_opencode_server(
    app: AppHandle,
    state: tauri::State<'_, SharedOpenCodeServerState>,
    command: String,
    cwd: Option<String>,
    port: u16,
) -> Result<(), String> {
    use std::process::Stdio;

    // Validate the command is a known OpenCode binary
    let validated_command = validate_opencode_command(&command, &app)?;

    // Check if we already have a running server
    {
        let mut server_state = state.lock();
        let current_port = server_state.port;

        if let Some(ref mut child) = server_state.process {
            // Check if the process is still running
            match child.try_wait() {
                Ok(Some(_)) => {
                    // Process has exited, clear it
                    server_state.process = None;
                    server_state.port = None;
                }
                Ok(None) => {
                    // Process is still running
                    if current_port == Some(port) {
                        // Same port, server already running
                        return Ok(());
                    } else {
                        // Different port, kill the old one first
                        let _ = child.kill();
                        let _ = child.wait();
                        server_state.process = None;
                        server_state.port = None;
                    }
                }
                Err(_) => {
                    // Error checking, assume it's dead
                    server_state.process = None;
                    server_state.port = None;
                }
            }
        }
    }

    // Build enhanced PATH with common user binary locations (for Unix-like systems)
    #[cfg(not(target_os = "windows"))]
    let enhanced_path = {
        if let Ok(home) = std::env::var("HOME") {
            let current_path = std::env::var("PATH").unwrap_or_default();
            let user_paths = [
                format!("{}/.local/bin", home),
                format!("{}/bin", home),
                format!("{}/.cargo/bin", home),
                format!("{}/.opencode/bin", home),
            ];
            format!("{}:{}:/usr/local/bin", user_paths.join(":"), current_path)
        } else {
            std::env::var("PATH").unwrap_or_default()
        }
    };

    #[cfg(target_os = "windows")]
    let child = {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let mut cmd = Command::new(&validated_command);
        cmd.args(["serve", "--port", &port.to_string()]);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.spawn()
            .map_err(|e| format!("Failed to spawn opencode: {}", e))?
    };

    #[cfg(target_os = "macos")]
    let child = {
        let mut cmd = Command::new(&validated_command);
        cmd.args(["serve", "--port", &port.to_string()]);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        cmd.env("PATH", &enhanced_path);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        cmd.spawn()
            .map_err(|e| format!("Failed to spawn opencode: {}. PATH={}", e, enhanced_path))?
    };

    #[cfg(target_os = "linux")]
    let child = {
        let mut cmd = Command::new(&validated_command);
        cmd.args(["serve", "--port", &port.to_string()]);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        cmd.env("PATH", &enhanced_path);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        cmd.spawn()
            .map_err(|e| format!("Failed to spawn opencode: {}. PATH={}", e, enhanced_path))?
    };

    // OpenCode is not supported on Android
    #[cfg(target_os = "android")]
    {
        return Err("OpenCode is not supported on Android".to_string());
    }

    // Store the process for later cleanup
    #[cfg(not(target_os = "android"))]
    {
        let mut server_state = state.lock();
        server_state.process = Some(child);
        server_state.port = Some(port);
    }

    #[cfg(not(target_os = "android"))]
    Ok(())
}

/// Stop the OpenCode server if running
#[tauri::command]
fn stop_opencode_server(state: tauri::State<'_, SharedOpenCodeServerState>) -> Result<(), String> {
    let mut server_state = state.lock();
    if let Some(ref mut child) = server_state.process {
        // Try graceful kill first, then force if needed
        let _ = child.kill();
        let _ = child.wait();
    }
    server_state.process = None;
    server_state.port = None;
    Ok(())
}

/// Check if the OpenCode server is running (managed by this app)
#[tauri::command]
fn is_opencode_server_managed(state: tauri::State<'_, SharedOpenCodeServerState>) -> bool {
    let mut server_state = state.lock();
    if let Some(ref mut child) = server_state.process {
        match child.try_wait() {
            Ok(Some(_)) => {
                // Process has exited
                server_state.process = None;
                server_state.port = None;
                false
            }
            Ok(None) => true, // Still running
            Err(_) => {
                server_state.process = None;
                server_state.port = None;
                false
            }
        }
    } else {
        false
    }
}

/// Validate that an OpenCode command path is safe to execute.
/// Allows:
///   - The bare command "opencode" (resolved via PATH)
///   - Absolute paths that resolve to known install locations
///   - Paths explicitly registered by the user via the register_opencode_path command
fn validate_opencode_command(command: &str, app: &AppHandle) -> Result<String, String> {
    let trimmed = command.trim();

    // Allow the bare command name -- resolved via PATH which we control
    if trimmed == "opencode" || trimmed == "opencode.exe" {
        return Ok(trimmed.to_string());
    }

    let cmd_path = Path::new(trimmed);

    // Must be an absolute path
    if !cmd_path.is_absolute() {
        return Err(format!(
            "OpenCode path must be 'opencode' or an absolute path, got: {}",
            trimmed
        ));
    }

    // Must exist
    if !cmd_path.exists() {
        return Err(format!("OpenCode binary not found at: {}", trimmed));
    }

    // Canonicalize to resolve symlinks
    let canonical = cmd_path
        .canonicalize()
        .map_err(|e| format!("Failed to resolve path {}: {}", trimmed, e))?;
    let canonical_str = canonical.to_string_lossy().to_string();

    // Check against known install locations
    let known_paths = get_known_opencode_paths();
    for known in &known_paths {
        if let Ok(known_canonical) = known.canonicalize() {
            if canonical == known_canonical {
                return Ok(canonical_str);
            }
        }
        // Also compare non-canonical in case the file was just installed
        if canonical == *known {
            return Ok(canonical_str);
        }
    }

    // Check against explicitly registered path (stored in Tauri Store, not localStorage)
    if let Some(registered) = get_registered_path(app) {
        if let Ok(reg_canonical) = Path::new(&registered).canonicalize() {
            if canonical == reg_canonical {
                return Ok(canonical_str);
            }
        }
    }

    Err(format!(
        "OpenCode path '{}' is not in a known install location. \
         Use Settings to register a custom path.",
        trimmed
    ))
}

/// Get all known OpenCode binary paths for the current platform
fn get_known_opencode_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = dirs::data_dir() {
            paths.push(appdata.join("opencode").join("bin").join("opencode.exe"));
        }
        paths.push(PathBuf::from("C:\\Program Files\\opencode\\opencode.exe"));
        paths.push(PathBuf::from("C:\\opencode\\opencode.exe"));
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            paths.push(PathBuf::from(&home).join(".opencode/bin/opencode"));
            paths.push(PathBuf::from(&home).join(".local/bin/opencode"));
            paths.push(PathBuf::from(&home).join("bin/opencode"));
            paths.push(PathBuf::from(&home).join(".cargo/bin/opencode"));
        }
        paths.push(PathBuf::from("/usr/local/bin/opencode"));
        paths.push(PathBuf::from("/usr/bin/opencode"));
    }

    paths
}

/// Read the user-registered OpenCode path from the Tauri Store
fn get_registered_path(app: &AppHandle) -> Option<String> {
    use tauri_plugin_store::StoreExt;
    if let Ok(store) = app.store("security.json") {
        if let Some(val) = store.get("opencode_registered_path") {
            return val.as_str().map(|s| s.to_string());
        }
    }
    None
}

/// Register a custom OpenCode binary path after validating it.
/// The path is stored in the Tauri Store (backend-managed, not localStorage).
#[tauri::command]
fn register_opencode_path(app: AppHandle, path: String) -> Result<String, String> {
    use tauri_plugin_store::StoreExt;

    let trimmed = path.trim();
    if trimmed.is_empty() {
        // Clear registration
        if let Ok(store) = app.store("security.json") {
            store.delete("opencode_registered_path");
            if let Err(e) = store.save() {
                eprintln!("[Store] Failed to persist security.json after clearing OpenCode path: {}", e);
            }
        }
        return Ok(String::new());
    }

    let cmd_path = Path::new(trimmed);

    // Must be absolute
    if !cmd_path.is_absolute() {
        return Err("Path must be absolute".to_string());
    }

    // Must exist
    if !cmd_path.exists() {
        return Err(format!("File not found: {}", trimmed));
    }

    // Canonicalize
    let canonical = cmd_path
        .canonicalize()
        .map_err(|e| format!("Invalid path: {}", e))?;

    // On Unix, verify it's executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&canonical).map_err(|e| format!("Cannot read file: {}", e))?;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err("File is not executable".to_string());
        }
    }

    let canonical_str = canonical.to_string_lossy().to_string();

    // Store in Tauri Store
    let store = app
        .store("security.json")
        .map_err(|e| format!("Failed to open store: {}", e))?;
    store.set(
        "opencode_registered_path",
        serde_json::Value::String(canonical_str.clone()),
    );
    if let Err(e) = store.save() {
        eprintln!("[Store] Failed to persist security.json after registering OpenCode path: {}", e);
    }

    Ok(canonical_str)
}

/// Get the currently registered OpenCode path (if any)
#[tauri::command]
fn get_registered_opencode_path(app: AppHandle) -> Option<String> {
    get_registered_path(&app)
}

// OpenCode Installer Module
mod opencode_installer {
    use super::*;
    use futures_util::StreamExt;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use tauri::Emitter;

    /// Progress payload for install events
    #[derive(Clone, Serialize)]
    pub struct InstallProgress {
        pub stage: String,
        pub progress: u32,
        pub bytes_downloaded: Option<u64>,
        pub total_bytes: Option<u64>,
        pub message: String,
    }

    /// Get the default install path for OpenCode based on the current platform
    fn get_default_install_dir() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            if let Some(appdata) = dirs::data_dir() {
                appdata.join("opencode").join("bin")
            } else {
                PathBuf::from("C:\\opencode\\bin")
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(home).join(".opencode").join("bin")
            } else {
                PathBuf::from("/usr/local/bin")
            }
        }
    }

    /// Get the full path to the opencode binary
    fn get_opencode_binary_path() -> PathBuf {
        let dir = get_default_install_dir();
        #[cfg(target_os = "windows")]
        {
            dir.join("opencode.exe")
        }
        #[cfg(not(target_os = "windows"))]
        {
            dir.join("opencode")
        }
    }

    /// Check common locations for OpenCode binary
    fn find_opencode_in_path() -> Option<PathBuf> {
        // Check if 'which' or 'where' can find it
        #[cfg(target_os = "windows")]
        let result = Command::new("where").arg("opencode").output();
        #[cfg(not(target_os = "windows"))]
        let result = Command::new("which").arg("opencode").output();

        if let Ok(output) = result {
            if output.status.success() {
                let path_str = String::from_utf8_lossy(&output.stdout);
                let path = path_str.lines().next()?.trim();
                if !path.is_empty() {
                    return Some(PathBuf::from(path));
                }
            }
        }
        None
    }

    /// Check if OpenCode is installed and return its path
    #[tauri::command]
    pub fn check_opencode_installed() -> Option<String> {
        // First check our default install location
        let default_path = get_opencode_binary_path();
        if default_path.exists() {
            return Some(default_path.to_string_lossy().to_string());
        }

        // Check common locations
        let common_paths: Vec<PathBuf> = {
            #[cfg(target_os = "windows")]
            {
                vec![
                    PathBuf::from("C:\\Program Files\\opencode\\opencode.exe"),
                    PathBuf::from("C:\\opencode\\opencode.exe"),
                ]
            }
            #[cfg(not(target_os = "windows"))]
            {
                let home = std::env::var("HOME").unwrap_or_default();
                vec![
                    PathBuf::from(&home).join(".local/bin/opencode"),
                    PathBuf::from(&home).join("bin/opencode"),
                    PathBuf::from("/usr/local/bin/opencode"),
                    PathBuf::from("/usr/bin/opencode"),
                ]
            }
        };

        for path in common_paths {
            if path.exists() {
                return Some(path.to_string_lossy().to_string());
            }
        }

        // Try to find in PATH
        if let Some(path) = find_opencode_in_path() {
            return Some(path.to_string_lossy().to_string());
        }

        None
    }

    /// Get the recommended install path for OpenCode
    #[tauri::command]
    pub fn get_opencode_install_path() -> String {
        get_opencode_binary_path().to_string_lossy().to_string()
    }

    /// GitHub repository hosting OpenCode releases
    const RELEASE_REPO: &str = "anomalyco/opencode";

    /// Get the release asset name for the current platform
    fn get_asset_name() -> Result<&'static str, String> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let asset = "opencode-darwin-arm64.zip";

        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        let asset = "opencode-darwin-x64.zip";

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let asset = "opencode-windows-x64.zip";

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let asset = "opencode-linux-x64.tar.gz";

        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        let asset = "opencode-linux-arm64.tar.gz";

        #[cfg(not(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "x86_64"),
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "aarch64"),
        )))]
        {
            return Err("Unsupported platform".to_string());
        }

        #[cfg(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "x86_64"),
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "aarch64"),
        ))]
        Ok(asset)
    }

    /// A resolved download: a concrete asset URL plus, when available, the
    /// expected SHA-256 of the asset for integrity verification.
    struct ResolvedDownload {
        url: String,
        asset_name: String,
        /// Lowercase hex SHA-256 the downloaded bytes must match, if known.
        expected_sha256: Option<String>,
    }

    /// Extract the expected SHA-256 for an asset from GitHub release metadata.
    ///
    /// The upstream repo publishes no checksums.txt / SHASUMS / signature
    /// assets, so the strongest available source is the `digest` field
    /// ("sha256:<hex>") that GitHub computes server-side for every release
    /// asset. If upstream ever publishes a dedicated checksums asset, add it
    /// as an additional source here.
    fn expected_sha256_from_asset(asset: &serde_json::Value) -> Option<String> {
        asset
            .get("digest")
            .and_then(|d| d.as_str())
            .and_then(|d| d.strip_prefix("sha256:"))
            .map(|h| h.trim().to_ascii_lowercase())
    }

    /// Resolve the download for the current platform.
    ///
    /// Queries the GitHub releases API once so that the download URL and the
    /// expected checksum come from the same pinned release (avoiding a race
    /// against `releases/latest`). Falls back to the unverified
    /// `releases/latest/download` URL if the API is unavailable, so installs
    /// keep working offline from the metadata endpoint (e.g. rate limiting).
    async fn resolve_download(client: &reqwest::Client) -> Result<ResolvedDownload, String> {
        let asset_name = get_asset_name()?;
        let fallback_url = format!(
            "https://github.com/{}/releases/latest/download/{}",
            RELEASE_REPO, asset_name
        );

        let api_url = format!("https://api.github.com/repos/{}/releases/latest", RELEASE_REPO);
        let release: Option<serde_json::Value> = match client
            .get(&api_url)
            .header("User-Agent", "onyx-opencode-installer")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(body) => serde_json::from_slice(&body).ok(),
                Err(e) => {
                    log::warn!("OpenCode installer: failed to read release metadata: {}", e);
                    None
                }
            },
            Ok(resp) => {
                log::warn!(
                    "OpenCode installer: release metadata request returned {}",
                    resp.status()
                );
                None
            }
            Err(e) => {
                log::warn!("OpenCode installer: failed to fetch release metadata: {}", e);
                None
            }
        };

        if let Some(release) = release {
            let tag = release
                .get("tag_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let asset = release
                .get("assets")
                .and_then(|a| a.as_array())
                .and_then(|assets| {
                    assets.iter().find(|a| {
                        a.get("name").and_then(|n| n.as_str()) == Some(asset_name)
                    })
                });

            if let Some(asset) = asset {
                let url = asset
                    .get("browser_download_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| fallback_url.clone());

                let expected_sha256 = expected_sha256_from_asset(asset);
                match &expected_sha256 {
                    Some(digest) => log::info!(
                        "OpenCode installer: resolved release {} asset {} with expected SHA-256 {}",
                        tag, asset_name, digest
                    ),
                    None => log::warn!(
                        "OpenCode installer: release {} provides no SHA-256 digest for {}; integrity verification will be skipped",
                        tag, asset_name
                    ),
                }

                return Ok(ResolvedDownload {
                    url,
                    asset_name: asset_name.to_string(),
                    expected_sha256,
                });
            }

            log::warn!(
                "OpenCode installer: asset {} not found in release {}; falling back to latest/download",
                asset_name, tag
            );
        }

        log::warn!(
            "OpenCode installer: could not resolve release metadata; no checksum available, skipping integrity verification for this install"
        );
        Ok(ResolvedDownload {
            url: fallback_url,
            asset_name: asset_name.to_string(),
            expected_sha256: None,
        })
    }

    /// Extract a .tar.gz archive
    #[cfg(not(target_os = "windows"))]
    fn extract_tar_gz(archive_path: &Path, dest_dir: &Path) -> Result<(), String> {
        use flate2::read::GzDecoder;
        use tar::Archive;

        let file = fs::File::open(archive_path).map_err(|e| format!("Failed to open archive: {}", e))?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);

        // Extract to destination
        archive
            .unpack(dest_dir)
            .map_err(|e| format!("Failed to extract archive: {}", e))?;

        Ok(())
    }

    /// Extract a .zip archive
    fn extract_zip(archive_path: &Path, dest_dir: &Path) -> Result<(), String> {
        let file = fs::File::open(archive_path).map_err(|e| format!("Failed to open archive: {}", e))?;
        let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("Failed to read zip: {}", e))?;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| format!("Failed to read zip entry: {}", e))?;

            let outpath = match file.enclosed_name() {
                Some(path) => dest_dir.join(path),
                None => continue,
            };

            if file.name().ends_with('/') {
                fs::create_dir_all(&outpath).map_err(|e| format!("Failed to create directory: {}", e))?;
            } else {
                if let Some(parent) = outpath.parent() {
                    if !parent.exists() {
                        fs::create_dir_all(parent)
                            .map_err(|e| format!("Failed to create directory: {}", e))?;
                    }
                }
                let mut outfile = fs::File::create(&outpath)
                    .map_err(|e| format!("Failed to create file: {}", e))?;
                std::io::copy(&mut file, &mut outfile)
                    .map_err(|e| format!("Failed to write file: {}", e))?;
            }

            // Set executable permissions on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    fs::set_permissions(&outpath, fs::Permissions::from_mode(mode)).ok();
                }
            }
        }

        Ok(())
    }

    /// Download and install OpenCode
    #[tauri::command]
    pub async fn install_opencode(app: AppHandle) -> Result<String, String> {
        let install_dir = get_default_install_dir();
        let binary_path = get_opencode_binary_path();

        // Emit starting
        let _ = app.emit(
            "opencode-install-progress",
            InstallProgress {
                stage: "checking".to_string(),
                progress: 0,
                bytes_downloaded: None,
                total_bytes: None,
                message: "Preparing installation...".to_string(),
            },
        );

        // Create install directory
        fs::create_dir_all(&install_dir)
            .map_err(|e| format!("Failed to create install directory: {}", e))?;

        // Resolve the release asset and its expected checksum from the same
        // pinned release before downloading anything
        let client = reqwest::Client::new();
        let resolved = resolve_download(&client).await?;

        // Create temp file for download
        let temp_dir = std::env::temp_dir();
        let archive_name = resolved.asset_name.as_str();
        let archive_path = temp_dir.join(archive_name);

        // Download the archive
        let _ = app.emit(
            "opencode-install-progress",
            InstallProgress {
                stage: "downloading".to_string(),
                progress: 0,
                bytes_downloaded: Some(0),
                total_bytes: None,
                message: format!("Connecting to GitHub..."),
            },
        );

        let response = client
            .get(&resolved.url)
            .send()
            .await
            .map_err(|e| format!("Failed to download: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Download failed with status: {}", response.status()));
        }

        let total_size = response.content_length();
        let mut downloaded: u64 = 0;
        let mut file = fs::File::create(&archive_path)
            .map_err(|e| format!("Failed to create temp file: {}", e))?;
        let mut hasher = Sha256::new();

        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| format!("Download error: {}", e))?;
            file.write_all(&chunk)
                .map_err(|e| format!("Failed to write: {}", e))?;
            hasher.update(&chunk);
            downloaded += chunk.len() as u64;

            let progress = if let Some(total) = total_size {
                ((downloaded as f64 / total as f64) * 100.0) as u32
            } else {
                0
            };

            let message = if let Some(total) = total_size {
                format!(
                    "Downloading... {:.1} MB / {:.1} MB",
                    downloaded as f64 / 1_000_000.0,
                    total as f64 / 1_000_000.0
                )
            } else {
                format!("Downloading... {:.1} MB", downloaded as f64 / 1_000_000.0)
            };

            let _ = app.emit(
                "opencode-install-progress",
                InstallProgress {
                    stage: "downloading".to_string(),
                    progress,
                    bytes_downloaded: Some(downloaded),
                    total_bytes: total_size,
                    message,
                },
            );
        }

        drop(file);

        // Verify download integrity against the checksum from the release
        // metadata before extracting or executing anything
        let _ = app.emit(
            "opencode-install-progress",
            InstallProgress {
                stage: "verifying".to_string(),
                progress: 75,
                bytes_downloaded: None,
                total_bytes: None,
                message: "Verifying download integrity...".to_string(),
            },
        );

        let actual_sha256 = format!("{:x}", hasher.finalize());
        match &resolved.expected_sha256 {
            Some(expected) => {
                if &actual_sha256 != expected {
                    let _ = fs::remove_file(&archive_path);
                    return Err(format!(
                        "Integrity verification failed for {}: expected SHA-256 {}, got {}. \
                         The download may be corrupted or tampered with; installation aborted.",
                        archive_name, expected, actual_sha256
                    ));
                }
                log::info!(
                    "OpenCode installer: verified SHA-256 of {} ({})",
                    archive_name, actual_sha256
                );
            }
            None => {
                log::warn!(
                    "OpenCode installer: upstream publishes no checksums for this download; \
                     skipping integrity verification for {} (downloaded SHA-256: {})",
                    archive_name, actual_sha256
                );
            }
        }

        // Extract the archive
        let _ = app.emit(
            "opencode-install-progress",
            InstallProgress {
                stage: "extracting".to_string(),
                progress: 80,
                bytes_downloaded: None,
                total_bytes: None,
                message: "Extracting OpenCode...".to_string(),
            },
        );

        // Create a temp extraction directory
        let extract_dir = temp_dir.join("opencode_extract");
        if extract_dir.exists() {
            let _ = fs::remove_dir_all(&extract_dir);
        }
        fs::create_dir_all(&extract_dir)
            .map_err(|e| format!("Failed to create extract directory: {}", e))?;

        // Extract based on archive type
        if archive_name.ends_with(".tar.gz") {
            #[cfg(not(target_os = "windows"))]
            extract_tar_gz(&archive_path, &extract_dir)?;
            #[cfg(target_os = "windows")]
            return Err("tar.gz extraction not supported on Windows".to_string());
        } else if archive_name.ends_with(".zip") {
            extract_zip(&archive_path, &extract_dir)?;
        } else {
            return Err("Unknown archive format".to_string());
        }

        // Find the opencode binary in the extracted files
        let _ = app.emit(
            "opencode-install-progress",
            InstallProgress {
                stage: "configuring".to_string(),
                progress: 90,
                bytes_downloaded: None,
                total_bytes: None,
                message: "Installing OpenCode...".to_string(),
            },
        );

        // Look for the opencode binary
        #[cfg(target_os = "windows")]
        let binary_name = "opencode.exe";
        #[cfg(not(target_os = "windows"))]
        let binary_name = "opencode";

        let mut found_binary: Option<PathBuf> = None;
        for entry in WalkDir::new(&extract_dir).max_depth(3) {
            if let Ok(entry) = entry {
                if entry.file_name().to_string_lossy() == binary_name {
                    found_binary = Some(entry.path().to_path_buf());
                    break;
                }
            }
        }

        let source_binary = found_binary.ok_or("OpenCode binary not found in archive")?;

        // Copy to install location
        fs::copy(&source_binary, &binary_path)
            .map_err(|e| format!("Failed to install binary: {}", e))?;

        // Make executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&binary_path, fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("Failed to set permissions: {}", e))?;
        }

        // Clean up temp files
        let _ = fs::remove_file(&archive_path);
        let _ = fs::remove_dir_all(&extract_dir);

        // Emit completion
        let _ = app.emit(
            "opencode-install-progress",
            InstallProgress {
                stage: "complete".to_string(),
                progress: 100,
                bytes_downloaded: None,
                total_bytes: None,
                message: "OpenCode installed successfully!".to_string(),
            },
        );

        Ok(binary_path.to_string_lossy().to_string())
    }

    /// Get the currently installed OpenCode version
    #[tauri::command]
    pub fn get_opencode_version() -> Result<String, String> {
        let binary_path = if let Some(path) = check_opencode_installed() {
            path
        } else {
            return Err("OpenCode not installed".to_string());
        };

        let output = Command::new(&binary_path)
            .arg("--version")
            .output()
            .map_err(|e| format!("Failed to get version: {}", e))?;

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(version)
        } else {
            Err("Failed to get version".to_string())
        }
    }
}

// PTY Session management (desktop only)
#[cfg(not(target_os = "android"))]
mod pty {
    use super::*;
    use std::io::Write;
    use std::time::{Instant, Duration};

    // Maximum PTY session lifetime: 4 hours
    const PTY_SESSION_TIMEOUT: Duration = Duration::from_secs(4 * 60 * 60);
    // Maximum number of concurrent PTY sessions
    const MAX_PTY_SESSIONS: usize = 10;

    pub struct PtySession {
        pub writer: Box<dyn Write + Send>,
        pub _child: Box<dyn portable_pty::Child + Send + Sync>,
        pub master: Box<dyn portable_pty::MasterPty + Send>,
        pub created_at: Instant,
    }

    pub struct PtyState {
        pub sessions: std::collections::HashMap<String, PtySession>,
        pub counter: u32,
    }

    impl Default for PtyState {
        fn default() -> Self {
            Self {
                sessions: std::collections::HashMap::new(),
                counter: 0,
            }
        }
    }
    
    impl PtyState {
        /// Remove sessions that have exceeded their timeout, killing their child processes
        pub fn cleanup_expired_sessions(&mut self) {
            let now = Instant::now();
            self.sessions.retain(|_id, session| {
                let keep = now.duration_since(session.created_at) < PTY_SESSION_TIMEOUT;
                if !keep {
                    // Dropping the child does not terminate it; kill and reap explicitly
                    let _ = session._child.kill();
                    let _ = session._child.wait();
                }
                keep
            });
        }

        /// Kill and reap all PTY child processes and clear the session map
        pub fn kill_all(&mut self) {
            for (_id, mut session) in self.sessions.drain() {
                let _ = session._child.kill();
                let _ = session._child.wait();
            }
        }

        /// Check if we can create a new session (respects max limit)
        pub fn can_create_session(&self) -> bool {
            self.sessions.len() < MAX_PTY_SESSIONS
        }
    }

    pub type SharedPtyState = Arc<Mutex<PtyState>>;

    #[tauri::command]
    pub fn spawn_pty(
        app: AppHandle,
        state: tauri::State<'_, SharedPtyState>,
        command: String,
        cwd: Option<String>,
        cols: u16,
        rows: u16,
    ) -> Result<String, String> {
        // Security: Validate the command is a known OpenCode binary
        let validated_command = validate_opencode_command(&command, &app)?;

        // Security: Clean up expired sessions and check limits
        {
            let mut state_guard = state.lock();
            state_guard.cleanup_expired_sessions();
            if !state_guard.can_create_session() {
                return Err("Maximum number of terminal sessions reached. Please close some terminals first.".to_string());
            }
        }
        
        let pty_system = native_pty_system();

        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| e.to_string())?;

        let mut cmd = CommandBuilder::new(&validated_command);

        if let Some(dir) = cwd {
            cmd.cwd(dir);
        }

        // Set TERM environment variable for proper terminal emulation
        cmd.env("TERM", "xterm-256color");

        // Enhance PATH with common user binary locations
        // This helps find binaries when running as a system-installed app
        if let Ok(home) = std::env::var("HOME") {
            let current_path = std::env::var("PATH").unwrap_or_default();
            let user_paths = [
                format!("{}/.local/bin", home),
                format!("{}/bin", home),
                format!("{}/.cargo/bin", home),
                format!("{}/.opencode/bin", home),
                format!("{}/.nvm/versions/node/*/bin", home), // Common node location
            ];
            let enhanced_path = format!("{}:{}:/usr/local/bin", user_paths.join(":"), current_path);
            cmd.env("PATH", enhanced_path);
        }

        let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;

        let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let writer = pair.master.take_writer().map_err(|e| e.to_string())?;

        // Generate session ID
        let session_id = {
            let mut state = state.lock();
            state.counter += 1;
            format!("pty_{}", state.counter)
        };

        let session_id_clone = session_id.clone();
        let app_clone = app.clone();

        // Spawn reader thread to emit output events
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        // EOF - process ended
                        let _ = app_clone.emit(&format!("pty-exit-{}", session_id_clone), ());
                        break;
                    }
                    Ok(n) => {
                        let data = String::from_utf8_lossy(&buf[..n]).to_string();
                        let _ = app_clone.emit(&format!("pty-output-{}", session_id_clone), data);
                    }
                    Err(_) => {
                        let _ = app_clone.emit(&format!("pty-exit-{}", session_id_clone), ());
                        break;
                    }
                }
            }
        });

        // Store session with creation timestamp
        {
            let mut state = state.lock();
            state.sessions.insert(
                session_id.clone(),
                PtySession {
                    writer,
                    _child: child,
                    master: pair.master,
                    created_at: Instant::now(),
                },
            );
        }

        Ok(session_id)
    }

    #[tauri::command]
    pub fn write_pty(
        state: tauri::State<'_, SharedPtyState>,
        session_id: String,
        data: String,
    ) -> Result<(), String> {
        let mut state = state.lock();
        if let Some(session) = state.sessions.get_mut(&session_id) {
            session
                .writer
                .write_all(data.as_bytes())
                .map_err(|e| e.to_string())?;
            session.writer.flush().map_err(|e| e.to_string())?;
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }

    #[tauri::command]
    pub fn resize_pty(
        state: tauri::State<'_, SharedPtyState>,
        session_id: String,
        cols: u16,
        rows: u16,
    ) -> Result<(), String> {
        let state = state.lock();
        if let Some(session) = state.sessions.get(&session_id) {
            session
                .master
                .resize(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|e| e.to_string())?;
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }

    #[tauri::command]
    pub fn kill_pty(
        state: tauri::State<'_, SharedPtyState>,
        session_id: String,
    ) -> Result<(), String> {
        let mut state = state.lock();
        if let Some(mut session) = state.sessions.remove(&session_id) {
            // Dropping the child does not terminate it; kill and reap explicitly
            let _ = session._child.kill();
            let _ = session._child.wait();
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }
}

#[cfg(not(target_os = "android"))]
use pty::{PtyState, SharedPtyState};

// Stub PTY functions for Android
#[cfg(target_os = "android")]
mod pty {
    use super::*;

    pub struct PtyState;
    impl Default for PtyState {
        fn default() -> Self {
            Self
        }
    }
    impl PtyState {
        /// No-op on Android (no PTY support)
        pub fn kill_all(&mut self) {}
    }
    pub type SharedPtyState = Arc<Mutex<PtyState>>;

    #[tauri::command]
    pub fn spawn_pty(
        _app: AppHandle,
        _state: tauri::State<'_, SharedPtyState>,
        _command: String,
        _cwd: Option<String>,
        _cols: u16,
        _rows: u16,
    ) -> Result<String, String> {
        Err("PTY not supported on Android".to_string())
    }

    #[tauri::command]
    pub fn write_pty(
        _state: tauri::State<'_, SharedPtyState>,
        _session_id: String,
        _data: String,
    ) -> Result<(), String> {
        Err("PTY not supported on Android".to_string())
    }

    #[tauri::command]
    pub fn resize_pty(
        _state: tauri::State<'_, SharedPtyState>,
        _session_id: String,
        _cols: u16,
        _rows: u16,
    ) -> Result<(), String> {
        Err("PTY not supported on Android".to_string())
    }

    #[tauri::command]
    pub fn kill_pty(
        _state: tauri::State<'_, SharedPtyState>,
        _session_id: String,
    ) -> Result<(), String> {
        Err("PTY not supported on Android".to_string())
    }
}

#[cfg(target_os = "android")]
use pty::{PtyState, SharedPtyState};

// File watcher for detecting changes
struct WatcherState {
    watcher: Option<RecommendedWatcher>,
}

impl Default for WatcherState {
    fn default() -> Self {
        Self { watcher: None }
    }
}

type SharedWatcherState = Arc<Mutex<WatcherState>>;

#[tauri::command]
fn start_watching(
    app: AppHandle,
    state: tauri::State<'_, SharedWatcherState>,
    scope: tauri::State<'_, SharedVaultScope>,
    path: String,
) -> Result<(), String> {
    // A watcher reports every change below its path; keep it inside the notebook.
    let path = validate_vault_path(&path, &configured_notebook(&scope)?)?;
    let mut watcher_state = state.lock();

    // Stop existing watcher if any
    watcher_state.watcher = None;

    let app_clone = app.clone();
    let watcher = RecommendedWatcher::new(
        move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                        // Shared vaults include binary files, dotfiles and removed
                        // directories. Keep all affected paths, not sidebar types.
                        let paths: Vec<String> = event
                            .paths
                            .iter()
                            .filter_map(|p| p.to_str().map(|s| s.to_string()))
                            .collect();
                        let _ = app_clone.emit("files-changed", &paths);
                        let markdown: Vec<String> = paths
                            .into_iter()
                            .filter(|p| std::path::Path::new(p).extension().map(|e| e == "md").unwrap_or(false))
                            .collect();
                        if !markdown.is_empty() {
                            let _ = app_clone.emit("file-modified", markdown);
                        }
                    }
                    _ => {}
                }
            }
        },
        Config::default().with_poll_interval(Duration::from_secs(1)),
    )
    .map_err(|e| e.to_string())?;

    watcher_state.watcher = Some(watcher);

    // Start watching the path
    if let Some(ref mut w) = watcher_state.watcher {
        w.watch(&path, RecursiveMode::Recursive)
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}

#[tauri::command]
fn stop_watching(state: tauri::State<'_, SharedWatcherState>) -> Result<(), String> {
    let mut watcher_state = state.lock();
    watcher_state.watcher = None;
    Ok(())
}

// Skills directory management
fn get_skills_dir() -> PathBuf {
    // All platforms: ~/.config/opencode/skills
    // On Windows this resolves to C:\Users\<user>\.config\opencode\skills
    if let Some(home) = dirs::home_dir() {
        home.join(".config").join("opencode").join("skills")
    } else {
        PathBuf::from(".").join(".config").join("opencode").join("skills")
    }
}

/// Validate a skill ID or file name to prevent path traversal
fn validate_skill_param(param: &str, param_name: &str) -> Result<(), String> {
    if param.is_empty() {
        return Err(format!("{} cannot be empty", param_name));
    }
    if param.contains("..") || param.contains('/') || param.contains('\\') || param.contains('\0') {
        return Err(format!("{} contains invalid characters", param_name));
    }
    Ok(())
}

#[tauri::command]
fn skill_is_installed(skill_id: String) -> bool {
    let skill_dir = get_skills_dir().join(&skill_id);
    skill_dir.exists() && skill_dir.join("SKILL.md").exists()
}

#[tauri::command]
fn skill_save_file(skill_id: String, file_name: String, content: String) -> Result<(), String> {
    validate_skill_param(&skill_id, "skill_id")?;
    validate_skill_param(&file_name, "file_name")?;
    let skills_dir = get_skills_dir();
    let skill_dir = skills_dir.join(&skill_id);
    
    // Create the skills directory first if it doesn't exist
    fs::create_dir_all(&skill_dir).map_err(|e| {
        format!(
            "Failed to create skill directory '{}': {}",
            skill_dir.display(),
            e
        )
    })?;

    let file_path = skill_dir.join(&file_name);
    fs::write(&file_path, &content).map_err(|e| {
        format!(
            "Failed to write file '{}': {}",
            file_path.display(),
            e
        )
    })
}

#[tauri::command]
fn skill_delete(skill_id: String) -> Result<(), String> {
    validate_skill_param(&skill_id, "skill_id")?;
    let skill_dir = get_skills_dir().join(&skill_id);
    if skill_dir.exists() {
        fs::remove_dir_all(&skill_dir).map_err(|e| e.to_string())
    } else {
        Ok(())
    }
}

#[tauri::command]
fn skill_list_installed() -> Result<Vec<String>, String> {
    let skills_dir = get_skills_dir();
    if !skills_dir.exists() {
        return Ok(Vec::new());
    }

    let mut installed = Vec::new();
    if let Ok(entries) = fs::read_dir(&skills_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            if entry.path().is_dir() {
                if entry.path().join("SKILL.md").exists() {
                    if let Some(name) = entry.file_name().to_str() {
                        installed.push(name.to_string());
                    }
                }
            }
        }
    }
    Ok(installed)
}

#[tauri::command]
fn skill_read_file(skill_id: String, file_name: String) -> Result<String, String> {
    validate_skill_param(&skill_id, "skill_id")?;
    validate_skill_param(&file_name, "file_name")?;
    let file_path = get_skills_dir().join(&skill_id).join(&file_name);
    fs::read_to_string(&file_path).map_err(|e| e.to_string())
}

/// Import a skill from a ZIP file
/// Returns the skill ID (folder name) extracted from the ZIP
#[tauri::command]
fn skill_import_zip(zip_path: String) -> Result<String, String> {
    use std::io::Read;
    use zip::ZipArchive;

    let file = fs::File::open(&zip_path).map_err(|e| format!("Failed to open ZIP: {}", e))?;
    let mut archive =
        ZipArchive::new(file).map_err(|e| format!("Failed to read ZIP archive: {}", e))?;

    // Find SKILL.md to determine the skill structure
    // ZIP could be structured as:
    // 1. skill-name/SKILL.md (with folder)
    // 2. SKILL.md (flat, at root)
    let mut skill_id: Option<String> = None;
    let mut has_root_skill_md = false;

    for i in 0..archive.len() {
        let file = archive
            .by_index(i)
            .map_err(|e| format!("Failed to read ZIP entry: {}", e))?;
        let name = file.name();

        if name == "SKILL.md" {
            has_root_skill_md = true;
        } else if name.ends_with("/SKILL.md") {
            // Extract folder name (first component)
            if let Some(folder) = name.split('/').next() {
                skill_id = Some(folder.to_string());
            }
        }
    }

    // Determine skill ID
    let skill_id = if let Some(id) = skill_id {
        id
    } else if has_root_skill_md {
        // Use ZIP filename as skill ID
        let zip_name = std::path::Path::new(&zip_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("imported-skill");
        zip_name
            .to_lowercase()
            .replace(|c: char| !c.is_alphanumeric() && c != '-', "-")
    } else {
        return Err("ZIP does not contain a SKILL.md file".to_string());
    };

    // Security: the skill ID must be a single, plain path component (no `..`, `/`, etc.)
    // so that joining it onto the skills directory cannot escape it.
    {
        let skill_id_path = Path::new(&skill_id);
        let mut components = skill_id_path.components();
        let valid = matches!(components.next(), Some(std::path::Component::Normal(_)))
            && components.next().is_none();
        if skill_id.is_empty() || !valid {
            return Err(format!("Invalid skill ID in ZIP: {}", skill_id));
        }
    }

    let skill_dir = get_skills_dir().join(&skill_id);
    fs::create_dir_all(&skill_dir).map_err(|e| format!("Failed to create skill directory: {}", e))?;

    // Re-open archive for extraction
    let file = fs::File::open(&zip_path).map_err(|e| format!("Failed to open ZIP: {}", e))?;
    let mut archive =
        ZipArchive::new(file).map_err(|e| format!("Failed to read ZIP archive: {}", e))?;

    // Extract files
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("Failed to read ZIP entry: {}", e))?;

        // Security: reject entries with unsafe names (zip-slip, absolute paths, `..`)
        if file.enclosed_name().is_none() {
            eprintln!("[Skills] Skipping unsafe ZIP entry: {}", file.name());
            continue;
        }

        let name = file.name().to_string();

        // Skip directories
        if name.ends_with('/') {
            continue;
        }

        // Determine output path
        let output_name = if has_root_skill_md && !name.contains('/') {
            // Flat structure - file is at root
            name.clone()
        } else if let Some(rest) = name.strip_prefix(&format!("{}/", skill_id)) {
            // Nested structure - strip the folder prefix
            rest.to_string()
        } else if name.contains('/') {
            // Some other nested structure - use path after first /
            name.split('/').skip(1).collect::<Vec<_>>().join("/")
        } else {
            name.clone()
        };

        if output_name.is_empty() {
            continue;
        }

        // Security: the derived relative path must consist solely of normal components
        // (no `..`, no root/prefix, no empty segments)
        let output_rel = Path::new(&output_name);
        if !output_rel
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
        {
            eprintln!("[Skills] Skipping unsafe ZIP entry: {}", name);
            continue;
        }

        let output_path = skill_dir.join(output_rel);

        // Defense in depth: lexically verify the final path stays within the skill dir
        if !output_path.starts_with(&skill_dir) {
            eprintln!("[Skills] Skipping ZIP entry escaping skill directory: {}", name);
            continue;
        }

        // Create parent directories if needed
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory: {}", e))?;
        }

        // Read and write file
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|e| format!("Failed to read ZIP entry: {}", e))?;
        fs::write(&output_path, &contents)
            .map_err(|e| format!("Failed to write file: {}", e))?;
    }

    // Verify SKILL.md exists
    if !skill_dir.join("SKILL.md").exists() {
        // Clean up
        let _ = fs::remove_dir_all(&skill_dir);
        return Err("Extracted files do not contain SKILL.md".to_string());
    }

    Ok(skill_id)
}

#[tauri::command]
async fn fetch_skills_sh(pages: Option<u32>) -> Result<String, String> {
    let pages = pages.unwrap_or(3); // 3 pages x 200 skills = ~600 skills
    let client = reqwest::Client::new();
    let mut all_skills = Vec::new();

    for page in 0..pages {
        let url = format!("https://skills.sh/api/skills/all-time/{}", page);
        let response = client
            .get(&url)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| format!("Failed to fetch skills.sh page {}: {}", page, e))?;

        if !response.status().is_success() {
            return Err(format!("skills.sh returned status: {}", response.status()));
        }

        let text = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        let page_data: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("Failed to parse skills.sh response: {}", e))?;

        if let Some(skills) = page_data.get("skills").and_then(|s| s.as_array()) {
            for skill in skills {
                // Remap new field names to old format for frontend compatibility:
                // skillId -> id, source -> topSource
                let remapped = serde_json::json!({
                    "id": skill.get("skillId").or_else(|| skill.get("name")).unwrap_or(&serde_json::Value::Null),
                    "name": skill.get("name").unwrap_or(&serde_json::Value::Null),
                    "installs": skill.get("installs").unwrap_or(&serde_json::json!(0)),
                    "topSource": skill.get("source").unwrap_or(&serde_json::Value::Null),
                });
                all_skills.push(remapped);
            }
        }

        // Stop early if no more pages
        let has_more = page_data.get("hasMore").and_then(|h| h.as_bool()).unwrap_or(false);
        if !has_more {
            break;
        }
    }

    let result = serde_json::json!({
        "skills": all_skills,
        "hasMore": false,
    });

    Ok(result.to_string())
}

#[tauri::command]
async fn fetch_skill_file(url: String) -> Result<String, String> {
    // Security: only fetch public HTTPS URLs; block internal/loopback targets (SSRF)
    let parsed = reqwest::Url::parse(&url).map_err(|e| format!("Invalid URL: {}", e))?;
    if parsed.scheme() != "https" {
        return Err("Only https:// URLs are allowed".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or("URL has no host")?
        .to_lowercase();
    // Reject IP literals (IPv6 host_str is bracketed, e.g. "[::1]")
    let bare_host = host.trim_start_matches('[').trim_end_matches(']');
    if bare_host.parse::<std::net::IpAddr>().is_ok() {
        return Err("IP address hosts are not allowed".to_string());
    }
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return Err("Internal hosts are not allowed".to_string());
    }

    let client = reqwest::Client::new();
    let response = client
        .get(parsed)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Failed to fetch skill file: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Failed to fetch skill file: status {}", response.status()));
    }

    response
        .text()
        .await
        .map_err(|e| format!("Failed to read skill file: {}", e))
}

// Keyring commands for secure credential storage (desktop only)
#[cfg(not(target_os = "android"))]
mod keyring_commands {
    use super::*;

    const KEYRING_SERVICE: &str = "com.onyx.app";

    #[tauri::command]
    pub fn keyring_set(key: String, value: String) -> Result<(), String> {
        let entry = Entry::new(KEYRING_SERVICE, &key).map_err(|e| e.to_string())?;
        entry.set_password(&value).map_err(|e| e.to_string())
    }

    #[tauri::command]
    pub fn keyring_get(key: String) -> Result<Option<String>, String> {
        let entry = Entry::new(KEYRING_SERVICE, &key).map_err(|e| e.to_string())?;
        match entry.get_password() {
            Ok(password) => Ok(Some(password)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    #[tauri::command]
    pub fn keyring_delete(key: String) -> Result<(), String> {
        let entry = Entry::new(KEYRING_SERVICE, &key).map_err(|e| e.to_string())?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

// Android keyring commands using app-private file storage
// Data is stored in the app's private directory which requires root access to read
// Combined with biometric authentication in the UI layer for additional security
#[cfg(target_os = "android")]
mod keyring_commands {
    use sha2::{Sha256, Digest};
    use std::fs;
    use std::path::PathBuf;
    use tauri::Manager;

    fn get_secure_storage_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
        let data_dir = app
            .path()
            .app_data_dir()
            .map_err(|e| format!("Failed to get app data dir: {}", e))?;
        
        let secure_dir = data_dir.join(".secure");
        if !secure_dir.exists() {
            fs::create_dir_all(&secure_dir)
                .map_err(|e| format!("Failed to create secure dir: {}", e))?;
        }
        Ok(secure_dir)
    }

    fn get_key_path(app: &tauri::AppHandle, key: &str) -> Result<PathBuf, String> {
        let secure_dir = get_secure_storage_path(app)?;
        // Hash the key name using SHA-256 to avoid filesystem issues with special characters
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        Ok(secure_dir.join(hash))
    }

    #[tauri::command]
    pub fn keyring_set(app: tauri::AppHandle, key: String, value: String) -> Result<(), String> {
        let path = get_key_path(&app, &key)?;
        fs::write(&path, value.as_bytes())
            .map_err(|e| format!("Failed to write secure data: {}", e))
    }

    #[tauri::command]
    pub fn keyring_get(app: tauri::AppHandle, key: String) -> Result<Option<String>, String> {
        let path = get_key_path(&app, &key)?;
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read secure data: {}", e))?;
        Ok(Some(data))
    }

    #[tauri::command]
    pub fn keyring_delete(app: tauri::AppHandle, key: String) -> Result<(), String> {
        let path = get_key_path(&app, &key)?;
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|e| format!("Failed to delete secure data: {}", e))?;
        }
        Ok(())
    }
}

// Generic OpenAI-compatible provider proxy commands (bypasses CORS)
// Works with MapleAI Proxy, Ollama, LM Studio, vLLM, or any OpenAI-compatible API.

#[tauri::command]
async fn custom_provider_request(url: String, api_key: String, body: String) -> Result<String, String> {
    let client = reqwest::Client::new();
    let mut request = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .timeout(Duration::from_secs(120));

    if !api_key.is_empty() {
        request = request.header("Authorization", format!("Bearer {}", api_key));
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Server returned {}: {}", status, body));
    }

    response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))
}

#[tauri::command]
async fn custom_provider_stream(
    app: AppHandle,
    request_id: String,
    url: String,
    api_key: String,
    body: String,
) -> Result<(), String> {
    use futures_util::StreamExt;

    let client = reqwest::Client::new();
    let mut request = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .timeout(Duration::from_secs(300));

    if !api_key.is_empty() {
        request = request.header("Authorization", format!("Bearer {}", api_key));
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Server returned {}: {}", status, body));
    }

    let mut stream = response.bytes_stream();
    let event_name = format!("custom-provider-stream-{}", request_id);

    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                if let Ok(text) = String::from_utf8(bytes.to_vec()) {
                    let _ = app.emit(&event_name, text);
                }
            }
            Err(e) => {
                let _ = app.emit(&event_name, format!("__ERROR__:{}", e));
                break;
            }
        }
    }

    // Signal end of stream
    let _ = app.emit(&event_name, "__DONE__");
    Ok(())
}

#[tauri::command]
async fn custom_provider_list_models(url: String, api_key: String) -> Result<String, String> {
    let client = reqwest::Client::new();
    let mut request = client
        .get(&url)
        .header("Content-Type", "application/json")
        .timeout(Duration::from_secs(15));

    if !api_key.is_empty() {
        request = request.header("Authorization", format!("Bearer {}", api_key));
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Server returned {}: {}", status, body));
    }

    response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))
}

// OpenClaw HTTP proxy commands (bypasses CORS)
#[tauri::command]
async fn openclaw_request(url: String, token: String, body: String) -> Result<String, String> {
    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(body)
        .timeout(Duration::from_secs(120))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Server returned {}: {}", status, body));
    }

    response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))
}

#[tauri::command]
async fn openclaw_stream(
    app: AppHandle,
    request_id: String,
    url: String,
    token: String,
    body: String,
) -> Result<(), String> {
    use futures_util::StreamExt;

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(body)
        .timeout(Duration::from_secs(300))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Server returned {}: {}", status, body));
    }

    let mut stream = response.bytes_stream();
    let event_name = format!("openclaw-stream-{}", request_id);

    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                if let Ok(text) = String::from_utf8(bytes.to_vec()) {
                    let _ = app.emit(&event_name, text);
                }
            }
            Err(e) => {
                let _ = app.emit(&event_name, format!("__ERROR__:{}", e));
                break;
            }
        }
    }

    // Signal end of stream
    let _ = app.emit(&event_name, "__DONE__");
    Ok(())
}

// OpenClaw Gateway WebSocket proxy
// Connects, performs challenge/connect handshake, sends a request, returns the response.
// Each call opens a fresh connection (lazy connect pattern for skills UI).
#[tauri::command]
async fn openclaw_gateway_request(
    ws_url: String,
    token: String,
    method: String,
    params: String,
) -> Result<String, String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    // Connect to the Gateway WebSocket
    let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| format!("WebSocket connect failed: {}", e))?;

    let (mut write, mut read) = ws_stream.split();

    // Step 1: Wait for connect.challenge event
    let mut challenge_nonce: Option<String> = None;
    let timeout = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(msg) = read.next().await {
            if let Ok(Message::Text(text)) = msg {
                if let Ok(frame) = serde_json::from_str::<serde_json::Value>(&text) {
                    if frame.get("type").and_then(|t| t.as_str()) == Some("event")
                        && frame.get("event").and_then(|e| e.as_str()) == Some("connect.challenge")
                    {
                        challenge_nonce = frame
                            .get("payload")
                            .and_then(|p| p.get("nonce"))
                            .and_then(|n| n.as_str())
                            .map(|s| s.to_string());
                        return Ok(());
                    }
                }
            }
        }
        Err("WebSocket closed before challenge".to_string())
    })
    .await;

    match timeout {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("Timeout waiting for challenge".to_string()),
    }

    // Step 2: Send connect request
    let connect_id = uuid::Uuid::new_v4().to_string();
    let connect_frame = serde_json::json!({
        "type": "req",
        "id": connect_id,
        "method": "connect",
        "params": {
            "minProtocol": 3,
            "maxProtocol": 3,
            "client": {
                "id": "gateway-client",
                "displayName": "Onyx",
                "version": "1.0.0",
                "platform": std::env::consts::OS,
                "mode": "ui"
            },
            "role": "operator",
            "scopes": ["operator.admin"],
            "caps": [],
            "auth": {
                "token": token
            }
        }
    });

    write
        .send(Message::Text(connect_frame.to_string()))
        .await
        .map_err(|e| format!("Failed to send connect: {}", e))?;

    // Step 3: Wait for hello-ok response
    let timeout = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(msg) = read.next().await {
            if let Ok(Message::Text(text)) = msg {
                if let Ok(frame) = serde_json::from_str::<serde_json::Value>(&text) {
                    if frame.get("type").and_then(|t| t.as_str()) == Some("res")
                        && frame.get("id").and_then(|i| i.as_str()) == Some(&connect_id)
                    {
                        let ok = frame.get("ok").and_then(|o| o.as_bool()).unwrap_or(false);
                        if !ok {
                            let err_msg = frame
                                .get("error")
                                .and_then(|e| e.get("message"))
                                .and_then(|m| m.as_str())
                                .unwrap_or("Connection rejected");
                            return Err(format!("Gateway connect failed: {}", err_msg));
                        }
                        return Ok(());
                    }
                }
            }
        }
        Err("WebSocket closed during handshake".to_string())
    })
    .await;

    match timeout {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("Timeout during handshake".to_string()),
    }

    // Step 4: Send the actual request
    let request_id = uuid::Uuid::new_v4().to_string();
    let params_value: serde_json::Value =
        serde_json::from_str(&params).unwrap_or(serde_json::json!({}));

    let request_frame = serde_json::json!({
        "type": "req",
        "id": request_id,
        "method": method,
        "params": params_value
    });

    write
        .send(Message::Text(request_frame.to_string()))
        .await
        .map_err(|e| format!("Failed to send request: {}", e))?;

    // Step 5: Wait for the response (skip events)
    let timeout = tokio::time::timeout(Duration::from_secs(300), async {
        while let Some(msg) = read.next().await {
            if let Ok(Message::Text(text)) = msg {
                if let Ok(frame) = serde_json::from_str::<serde_json::Value>(&text) {
                    if frame.get("type").and_then(|t| t.as_str()) == Some("res")
                        && frame.get("id").and_then(|i| i.as_str()) == Some(&request_id)
                    {
                        let ok = frame.get("ok").and_then(|o| o.as_bool()).unwrap_or(false);
                        if !ok {
                            let err_msg = frame
                                .get("error")
                                .and_then(|e| e.get("message"))
                                .and_then(|m| m.as_str())
                                .unwrap_or("Request failed");
                            return Err(format!("Gateway error: {}", err_msg));
                        }
                        let payload = frame.get("payload").cloned().unwrap_or(serde_json::json!({}));
                        return Ok(payload.to_string());
                    }
                    // Skip events (tick, presence, etc.)
                }
            }
        }
        Err("WebSocket closed before response".to_string())
    })
    .await;

    // Close the connection
    let _ = write.send(Message::Close(None)).await;

    match timeout {
        Ok(Ok(payload)) => Ok(payload),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("Timeout waiting for response".to_string()),
    }
}

/// Get any deep link URLs passed as command line arguments
/// On Linux, when the app is launched via xdg-open, the URL is passed as an argument
#[tauri::command]
fn get_deep_link_args() -> Vec<String> {
    let args: Vec<String> = std::env::args().collect();
    let mut deep_links = Vec::new();
    
    // Skip the first arg (program name), check for URLs starting with onyx://
    for arg in args.iter().skip(1) {
        if arg.starts_with("onyx://") {
            deep_links.push(arg.clone());
        }
    }
    
    deep_links
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Create shared state for OpenCode server
    let opencode_server_state: SharedOpenCodeServerState =
        Arc::new(Mutex::new(OpenCodeServerState::default()));
    let opencode_server_state_clone = opencode_server_state.clone();

    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_clipboard_manager::init());

    // Desktop-only plugins
    #[cfg(desktop)]
    {
        // Single instance plugin - ensures only one instance runs
        // When a second instance is launched, it passes args to the first instance
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            // Focus the main window
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
            }
            
            // Check for deep link URLs in args and emit them to the frontend
            for arg in args.iter().skip(1) {
                if arg.starts_with("onyx://") {
                    let _ = app.emit("deep-link-received", arg.clone());
                }
            }
        }))
        // Window state plugin - remembers window position and size
        .plugin(tauri_plugin_window_state::Builder::default().build());
    }

    // Mobile-only plugins
    #[cfg(mobile)]
    {
        builder = builder
            .plugin(tauri_plugin_haptics::init())
            .plugin(tauri_plugin_biometric::init());
    }

    builder
        .manage(Arc::new(Mutex::new(PtyState::default())) as SharedPtyState)
        .manage(Arc::new(Mutex::new(WatcherState::default())) as SharedWatcherState)
        .manage(Arc::new(Mutex::new(VaultScopeState::default())) as SharedVaultScope)
        .manage(opencode_server_state)
        // Clean up OpenCode server and PTY children on app exit
        .on_window_event(move |window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                let mut server_state = opencode_server_state_clone.lock();
                if let Some(ref mut child) = server_state.process {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                server_state.process = None;
                server_state.port = None;
                drop(server_state);

                // Kill and reap all PTY child processes (dropping them does not kill them)
                let pty_state = window.app_handle().state::<SharedPtyState>();
                pty_state.lock().kill_all();
            }
        })
        // Register asset protocol to serve local files
        .register_uri_scheme_protocol("asset", |ctx, request| {
            let app = ctx.app_handle();
            let path = request.uri().path();
            // URL decode the path
            let decoded_path = percent_decode_str(path).decode_utf8_lossy().to_string();
            // On Windows, path might start with / before drive letter, remove it
            #[cfg(target_os = "windows")]
            let decoded_path = if decoded_path.starts_with('/')
                && decoded_path.len() > 2
                && decoded_path.chars().nth(2) == Some(':')
            {
                decoded_path[1..].to_string()
            } else {
                decoded_path
            };
            
            // Security: same lexical containment rule as the file commands.
            // This handler used to carry its own copy of the pre-fix rule
            // (`canonicalize()` + `starts_with`), so every image and PDF inside a
            // symlinked vault folder 403'd even after the commands learned to open
            // them. It also rejected any path *string* containing "..", which is a
            // false-positive generator — `screenshot..final.png` is a legal name.
            // `lexically_normalize` inside `validate_vault_path` resolves `..`
            // properly and rejects the escapes.
            let resolved = {
                let in_vault = app
                    .state::<SharedVaultScope>()
                    .lock()
                    .notebook
                    .clone()
                    .and_then(|vault| validate_vault_path(&decoded_path, &vault).ok());
                // Also allow config directory access (for app assets).
                in_vault.or_else(|| {
                    let config_dir = get_config_dir_with_app(app).to_string_lossy().to_string();
                    validate_vault_path(&decoded_path, &config_dir).ok()
                })
            };

            let Some(resolved) = resolved else {
                return tauri::http::Response::builder()
                    .status(403)
                    .header("Content-Type", "text/plain")
                    .body("Access denied: file outside vault".as_bytes().to_vec())
                    .unwrap();
            };

            if !resolved.exists() {
                return tauri::http::Response::builder()
                    .status(404)
                    .body(Vec::new())
                    .unwrap();
            }

            // Only serve files, never directories. `is_file` follows symlinks,
            // which is the intended read-through.
            if !resolved.is_file() {
                return tauri::http::Response::builder()
                    .status(403)
                    .header("Content-Type", "text/plain")
                    .body("Access denied: not a file".as_bytes().to_vec())
                    .unwrap();
            }

            match fs::read(&resolved) {
                Ok(data) => {
                    // Determine MIME type based on extension
                    let mime = match Path::new(&decoded_path)
                        .extension()
                        .and_then(|e| e.to_str())
                    {
                        Some("png") => "image/png",
                        Some("jpg") | Some("jpeg") => "image/jpeg",
                        Some("gif") => "image/gif",
                        Some("webp") => "image/webp",
                        Some("svg") => "image/svg+xml",
                        Some("bmp") => "image/bmp",
                        Some("avif") => "image/avif",
                        Some("mp3") => "audio/mpeg",
                        Some("wav") => "audio/wav",
                        Some("ogg") => "audio/ogg",
                        Some("flac") => "audio/flac",
                        Some("m4a") => "audio/mp4",
                        Some("webm") => "video/webm",
                        Some("mp4") => "video/mp4",
                        Some("mkv") => "video/x-matroska",
                        Some("mov") => "video/quicktime",
                        Some("ogv") => "video/ogg",
                        Some("pdf") => "application/pdf",
                        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        Some("pptx") => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                        _ => "application/octet-stream",
                    };
                    tauri::http::Response::builder()
                        .status(200)
                        .header("Content-Type", mime)
                        .header("Access-Control-Allow-Origin", "tauri://localhost")
                        .body(data)
                        .unwrap()
                }
                Err(_) => tauri::http::Response::builder()
                    .status(404)
                    .body(Vec::new())
                    .unwrap(),
            }
        })
        .setup(|app| {
            // The notebook the vault commands validate against, before the
            // frontend has had a chance to say anything.
            app.state::<SharedVaultScope>().lock().notebook =
                get_configured_vault_setting(&app.handle());
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_files,
            list_files_all,
            list_assets,
            read_file,
            write_file,
            write_binary_file,
            read_binary_file,
            create_file,
            create_folder,
            managed_write_binary,
            managed_read_binary,
            managed_mkdir,
            managed_delete,
            set_vault_scope,
            get_file_modified_time,
            file_exists,
            delete_file,
            rename_file,
            copy_file,
            open_in_default_app,
            show_in_folder,
            search_files,
            resolve_real_path,
            get_file_stats,
            start_opencode_server,
            stop_opencode_server,
            is_opencode_server_managed,
            register_opencode_path,
            get_registered_opencode_path,
            pty::spawn_pty,
            pty::write_pty,
            pty::resize_pty,
            pty::kill_pty,
            load_settings,
            resolve_recovery_destination,
            save_settings,
            keyring_commands::keyring_set,
            keyring_commands::keyring_get,
            keyring_commands::keyring_delete,
            start_watching,
            stop_watching,
            skill_is_installed,
            skill_save_file,
            skill_delete,
            skill_list_installed,
            skill_read_file,
            skill_import_zip,
            fetch_skills_sh,
            fetch_skill_file,
            get_platform_info,
            opencode_installer::check_opencode_installed,
            opencode_installer::get_opencode_install_path,
            opencode_installer::install_opencode,
            opencode_installer::get_opencode_version,
            get_deep_link_args,
            openclaw_request,
            openclaw_stream,
            openclaw_gateway_request,
            custom_provider_request,
            custom_provider_stream,
            custom_provider_list_models,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod vault_path_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// Builds a throwaway vault:
    ///   <tmp>/vault/Notes/plain.md
    ///   <tmp>/vault/Projects -> <tmp>/real/onyx   (the shape that was broken)
    ///   <tmp>/real/onyx/README.md
    fn fixture(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("onyx-vault-test-{}-{}", std::process::id(), tag));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("vault/Notes")).unwrap();
        fs::create_dir_all(root.join("real/onyx")).unwrap();
        fs::write(root.join("vault/Notes/plain.md"), "# plain").unwrap();
        fs::write(root.join("real/onyx/README.md"), "# linked").unwrap();
        symlink(root.join("real/onyx"), root.join("vault/Projects")).unwrap();
        root
    }

    fn vault_of(root: &Path) -> String {
        root.join("vault").to_string_lossy().to_string()
    }

    #[test]
    fn recovery_destination_rejects_notebook_paths_and_symlink_aliases() {
        let root = fixture("recovery-destination");
        let vault = vault_of(&root);
        symlink(root.join("vault"), root.join("alias")).unwrap();
        symlink(root.join("vault/Notes/plain.md"), root.join("linked.json")).unwrap();
        for relative in ["vault/recovery.json", "alias/recovery.json", "linked.json", "vault/Projects/recovery.json"] {
            assert!(resolve_recovery_destination(root.join(relative).to_string_lossy().into_owned(), vault.clone()).is_err());
        }
        let destination = root.join("recovery.json");
        assert_eq!(resolve_recovery_destination(destination.to_string_lossy().into_owned(), vault.clone()).unwrap(),
            destination.parent().unwrap().canonicalize().unwrap().join("recovery.json").to_string_lossy());
        assert!(resolve_recovery_destination("recovery.json".into(), vault).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn list_files_all_includes_hidden_and_binary_entries_without_following_links() {
        let root = fixture("list-all");
        let vault = vault_of(&root);
        let directory = root.join("vault");
        fs::create_dir_all(directory.join(".config/empty")).unwrap();
        fs::write(directory.join(".config/settings.json"), "{}").unwrap();
        fs::write(directory.join(".env"), "KEY=value").unwrap();
        fs::write(directory.join("archive.bin"), [0, 255]).unwrap();
        fs::write(directory.join("note.md"), "# note").unwrap();
        symlink("..", directory.join("Notes/loop")).unwrap();
        symlink(directory.join("archive.bin"), directory.join("linked.bin")).unwrap();

        let tree = list_files_all_in(&vault, &vault).unwrap();
        let names: Vec<_> = tree.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, [".config", "Notes", ".env", "archive.bin", "note.md"]);
        let config = tree[0].children.as_ref().unwrap();
        assert_eq!(config[0].name, "empty");
        assert!(config[0].children.as_ref().unwrap().is_empty());
        assert_eq!(config[1].name, "settings.json");
        let notes = tree[1].children.as_ref().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].name, "plain.md");

        let sidebar = list_files_in(&vault, &vault).unwrap();
        let sidebar_names: Vec<_> = sidebar.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(sidebar_names, ["Notes", "Projects", "note.md"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn list_files_all_matches_shared_web_conformance_fixture() {
        let root = fixture("list-all-conformance");
        let vault = vault_of(&root);
        let directory = root.join("vault/conformance");
        fs::create_dir_all(&directory).unwrap();
        let expected: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../tests/fixtures/list-all-conformance.json"
        )).unwrap();
        for entry in &expected {
            let path = directory.join(entry["path"].as_str().unwrap());
            if entry["isDirectory"].as_bool().unwrap() {
                fs::create_dir_all(path).unwrap();
            } else {
                fs::write(path, [0, 255]).unwrap();
            }
        }
        symlink("..", directory.join("nested/loop")).unwrap();
        symlink(directory.join("archive.bin"), directory.join("linked.bin")).unwrap();
        let entries = list_files_all_in(&vault, &directory.to_string_lossy()).unwrap();
        fn flatten(entries: &[FileEntry], root: &Path, result: &mut Vec<serde_json::Value>) {
            for entry in entries {
                result.push(serde_json::json!({
                    "path": Path::new(&entry.path).strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"),
                    "isDirectory": entry.is_directory
                }));
                if let Some(children) = &entry.children { flatten(children, root, result); }
            }
        }
        let mut actual = Vec::new();
        flatten(&entries, &directory, &mut actual);
        actual.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
        assert_eq!(actual, expected);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn list_files_all_requires_a_directory_inside_the_notebook() {
        let root = fixture("list-all-scope");
        let vault = vault_of(&root);
        assert!(list_files_all_in(&vault, &root.to_string_lossy()).is_err());
        assert!(list_files_all_in(&vault, &format!("{}/../real", vault)).is_err());
        assert!(list_files_all_in(&vault, "Notes").is_err());
        assert!(list_files_all_in(&vault, &format!("{}/missing", vault)).is_err());
        assert!(list_files_all_in(&vault, &format!("{}/Notes/plain.md", vault)).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    /// SV-40 (H4): the frontend used to send `{ path: root, vaultPath: root }`, so
    /// any readable directory passed as both arguments was its own scope. The
    /// scope now comes from the configured notebook only; a caller-supplied root
    /// that is a real, readable directory outside it is refused by every command.
    #[test]
    fn a_caller_supplied_root_outside_the_notebook_is_refused() {
        let root = fixture("caller-root");
        let notebook = vault_of(&root);
        let outside = root.join("real");
        fs::write(outside.join("onyx/secret.md"), "secret").unwrap();
        let outside_str = outside.to_string_lossy().to_string();
        let secret = outside.join("onyx/secret.md").to_string_lossy().to_string();
        let scratch = outside.join("scratch").to_string_lossy().to_string();

        assert!(outside.is_dir(), "the refused root is a genuine directory");
        assert!(list_files_all_in(&notebook, &outside_str).is_err());
        assert!(list_files_in(&notebook, &outside_str).is_err());
        assert!(read_file_in(&notebook, &secret).is_err());
        assert!(read_binary_file_in(&notebook, &secret).is_err());
        assert!(write_file_in(&notebook, &scratch, "x").is_err());
        assert!(write_binary_file_in(&notebook, &scratch, b"x").is_err());
        assert!(create_file_in(&notebook, &scratch).is_err());
        assert!(create_folder_in(&notebook, &scratch).is_err());
        assert!(delete_file_in(&notebook, &secret).is_err());
        assert!(rename_file_in(&notebook, &secret, &scratch).is_err());
        assert!(copy_file_in(&notebook, &secret, &scratch).is_err());
        // Both directions: a notebook path may not be moved or copied outside either.
        let inside = root.join("vault/Notes/plain.md").to_string_lossy().to_string();
        assert!(rename_file_in(&notebook, &inside, &scratch).is_err());
        assert!(copy_file_in(&notebook, &inside, &scratch).is_err());

        assert_eq!(fs::read_to_string(outside.join("onyx/secret.md")).unwrap(), "secret");
        assert!(!outside.join("scratch").exists());
        // The same calls succeed for the configured notebook itself.
        assert!(list_files_all_in(&notebook, &notebook).is_ok());
        assert!(read_file_in(&notebook, &inside).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_an_ordinary_file_in_the_vault() {
        let root = fixture("ordinary");
        let vault = vault_of(&root);
        let target = root.join("vault/Notes/plain.md");
        assert!(validate_vault_path(&target.to_string_lossy(), &vault).is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn accepts_a_file_inside_a_linked_folder() {
        // This is the regression: canonicalize() resolved the path to
        // <tmp>/real/onyx/README.md and the starts_with check rejected it.
        let root = fixture("linked");
        let vault = vault_of(&root);
        let target = root.join("vault/Projects/README.md");
        let resolved = validate_vault_path(&target.to_string_lossy(), &vault)
            .expect("a file inside a linked folder must be readable");
        assert_eq!(resolved, target, "the link path is preserved, not resolved");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn accepts_the_link_itself() {
        let root = fixture("linkdir");
        let vault = vault_of(&root);
        let target = root.join("vault/Projects");
        assert!(validate_vault_path(&target.to_string_lossy(), &vault).is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn accepts_a_file_that_does_not_exist_yet() {
        // New-note creation inside a linked folder.
        let root = fixture("newfile");
        let vault = vault_of(&root);
        let target = root.join("vault/Projects/brand-new.md");
        assert!(validate_vault_path(&target.to_string_lossy(), &vault).is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn still_rejects_dot_dot_traversal() {
        let root = fixture("traversal");
        let vault = vault_of(&root);
        let target = format!("{}/Notes/../../real/onyx/README.md", vault);
        assert!(
            validate_vault_path(&target, &vault).is_err(),
            "`..` out of the vault must stay denied"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn still_rejects_an_unrelated_absolute_path() {
        let root = fixture("outside");
        let vault = vault_of(&root);
        assert!(validate_vault_path("/etc/passwd", &vault).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_a_relative_path() {
        let root = fixture("relative");
        let vault = vault_of(&root);
        assert!(validate_vault_path("Notes/plain.md", &vault).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_a_sibling_that_merely_shares_a_name_prefix() {
        // "<tmp>/vault-evil" must not pass a naive starts_with on "<tmp>/vault".
        let root = fixture("prefix");
        let vault = vault_of(&root);
        fs::create_dir_all(root.join("vault-evil")).unwrap();
        fs::write(root.join("vault-evil/secret.md"), "x").unwrap();
        let target = root.join("vault-evil/secret.md");
        assert!(
            validate_vault_path(&target.to_string_lossy(), &vault).is_err(),
            "Path::starts_with is component-wise, so this must be denied"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// Momus's case 17: enough `..` after a symlink hop to leave the vault.
    /// Lexical normalization pops the link component rather than climbing out of
    /// the link's *target*, so the two orderings disagree — but both land outside
    /// the vault here, and the lexical one is denied. Deny is the safe direction.
    #[test]
    fn dot_dot_after_a_link_hop_out_of_the_vault_is_denied() {
        let root = fixture("case17");
        let vault = vault_of(&root);
        fs::write(root.join("real/secret.md"), "secret").unwrap();
        let attack = format!("{}/Projects/../../real/secret.md", vault);

        assert!(
            validate_vault_path(&attack, &vault).is_err(),
            "`..` climbing past the vault root must be denied even after a link hop"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// The other half of case 17: a single `..` after a link hop stays inside the
    /// vault lexically, while the OS would have resolved it against the link's
    /// target and landed somewhere else entirely. That divergence is only safe
    /// because callers operate on the returned path, never the raw string — this
    /// test pins the returned path, which is what makes the rule sound.
    #[test]
    fn dot_dot_after_a_link_hop_pops_the_link_not_its_target() {
        let root = fixture("popped");
        let vault = vault_of(&root);
        let input = format!("{}/Projects/../Notes/plain.md", vault);

        let resolved = validate_vault_path(&input, &vault)
            .expect("lexically this lands back inside the vault");
        assert_eq!(
            resolved,
            Path::new(&vault).join("Notes/plain.md"),
            "the returned path must pop the link component, not follow it"
        );
        assert!(resolved.exists(), "and it must name the real in-vault file");
        // The OS ordering would have reached <tmp>/real/Notes/plain.md.
        assert!(!root.join("real/Notes/plain.md").exists());
        let _ = fs::remove_dir_all(&root);
    }

    /// The returned path is the security boundary: every command operates on it,
    /// so it must never point outside the vault even when the raw input would.
    #[test]
    fn returned_path_is_always_inside_the_vault() {
        let root = fixture("returned");
        let vault = vault_of(&root);
        let inputs = [
            format!("{}/Projects/README.md", vault),
            format!("{}/Projects/../Notes/plain.md", vault),
            format!("{}/Notes/./plain.md", vault),
        ];
        for input in inputs {
            let resolved = validate_vault_path(&input, &vault).expect(&input);
            assert!(
                resolved.starts_with(&vault),
                "{} resolved outside the vault: {:?}",
                input,
                resolved
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// Momus F2: `links/parent-loop -> ..` points at the vault itself. `is_dir()`
    /// follows it, so the pre-fix walker descended forever. Mutual and self loops
    /// were never the crash — `is_dir()` returns false on ELOOP.
    #[test]
    fn tree_walk_terminates_on_an_ancestor_link() {
        let root = fixture("ancestor");
        let vault = root.join("vault");
        symlink("..", vault.join("Notes/parent-loop")).unwrap();
        symlink("loop-b", vault.join("Notes/loop-a")).unwrap();
        symlink("loop-a", vault.join("Notes/loop-b")).unwrap();
        symlink("self", vault.join("Notes/self")).unwrap();

        let tree = build_file_tree(&vault);
        assert!(!tree.is_empty(), "the walk must still return the real entries");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn tree_walk_terminates_on_a_link_cycle() {
        let root = fixture("cycle");
        symlink(root.join("vault"), root.join("vault/Notes/loop")).unwrap();
        // Would recurse forever without the visited set.
        let tree = build_file_tree(&root.join("vault"));
        assert!(!tree.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    /// SV-42 (H6): the report's fixture. `notebook/Alias -> notebook/Shared`
    /// is not a managed path by spelling, but its identity is the mount. The
    /// sidebar marks the alias as a link so the frontend asks for identity only
    /// where it matters, and `resolve_real_path` answers for existing and
    /// not-yet-created paths alike; capture never lists the alias at all.
    #[test]
    fn an_alias_into_a_mount_is_flagged_and_resolves_to_the_mount() {
        let root = fixture("alias-identity");
        let notebook_dir = root.join("vault");
        let notebook = notebook_dir.to_string_lossy().to_string();
        let s = |path: &Path| path.to_string_lossy().to_string();
        fs::create_dir_all(notebook_dir.join("Shared")).unwrap();
        fs::write(notebook_dir.join("Shared/private.md"), "secret").unwrap();
        symlink(notebook_dir.join("Shared"), notebook_dir.join("Alias")).unwrap();
        let shared = notebook_dir.join("Shared").canonicalize().unwrap();

        assert_eq!(
            resolve_real_path_in(&notebook, &s(&notebook_dir.join("Alias/private.md"))).unwrap(),
            s(&shared.join("private.md"))
        );
        assert_eq!(
            resolve_real_path_in(&notebook, &s(&notebook_dir.join("Alias/new/deeper.md"))).unwrap(),
            s(&shared.join("new/deeper.md")),
            "a path that does not exist yet resolves through its nearest existing ancestor"
        );
        assert_eq!(resolve_real_path_in(&notebook, &s(&notebook_dir.join("Shared"))).unwrap(), s(&shared));
        assert_eq!(
            resolve_real_path_in(&notebook, &s(&notebook_dir.join("Notes/plain.md"))).unwrap(),
            s(&notebook_dir.join("Notes/plain.md").canonicalize().unwrap())
        );
        assert!(resolve_real_path_in(&notebook, &s(&root.join("real/onyx/README.md"))).is_err());

        let sidebar = list_files_in(&notebook, &notebook).unwrap();
        let alias = sidebar.iter().find(|e| e.name == "Alias").expect("the sidebar follows the alias");
        assert_eq!(alias.is_symlink, Some(true));
        assert!(alias.is_directory);
        assert_eq!(alias.children.as_ref().unwrap()[0].name, "private.md");
        let shared_entry = sidebar.iter().find(|e| e.name == "Shared").unwrap();
        assert_eq!(shared_entry.is_symlink, None);
        assert_eq!(shared_entry.children.as_ref().unwrap()[0].is_symlink, None);
        assert_eq!(serde_json::to_value(shared_entry).unwrap().get("isSymlink"), None);
        assert_eq!(serde_json::to_value(alias).unwrap()["isSymlink"], serde_json::json!(true));

        let capture = list_files_all_in(&notebook, &notebook).unwrap();
        assert!(capture.iter().all(|e| e.name != "Alias"), "capture omits links entirely");
        let _ = fs::remove_dir_all(&root);
    }

    /// Momus's case 17 verbatim: `links/dir-abs-outside/../../outside/notes/second.md`,
    /// where `dir-abs-outside` links out of the vault. Two `..` pop the link and
    /// `links`, landing on `<vault>/outside/notes/second.md`, which is *inside* —
    /// so this is an ALLOW, not a deny. Nothing escapes because the returned path
    /// is the in-vault spelling and every caller uses it; the OS ordering would
    /// have resolved against the link target and reached `<tmp>/outside/...`.
    #[test]
    fn case_17_dot_dot_after_a_link_hop_lands_back_inside_and_is_allowed() {
        let root = fixture("case17-verbatim");
        let vault = vault_of(&root);
        let vault_dir = root.join("vault");

        // Outside the vault: the place the OS ordering would have reached.
        fs::create_dir_all(root.join("outside/notes")).unwrap();
        fs::write(root.join("outside/notes/second.md"), "outside").unwrap();
        // Inside the vault: the place the lexical rule actually names.
        fs::create_dir_all(vault_dir.join("outside/notes")).unwrap();
        fs::write(vault_dir.join("outside/notes/second.md"), "inside").unwrap();
        fs::create_dir_all(vault_dir.join("links")).unwrap();
        symlink(root.join("outside"), vault_dir.join("links/dir-abs-outside")).unwrap();

        let input = format!("{}/links/dir-abs-outside/../../outside/notes/second.md", vault);
        let resolved = validate_vault_path(&input, &vault)
            .expect("this normalizes back inside the vault, so it is allowed");
        assert_eq!(
            resolved,
            vault_dir.join("outside/notes/second.md"),
            "the returned path must be the in-vault spelling"
        );
        assert_eq!(fs::read_to_string(&resolved).unwrap(), "inside");
        let _ = fs::remove_dir_all(&root);
    }

    /// Derek's ruling (2026-07-29): saving a note that is a symlink writes through
    /// to the target, even when the target lives outside the vault. Every link in a
    /// vault was made by its owner outside Onyx — the app has no symlink-creation
    /// command — so a link is a grant. This test exists so a later refactor cannot
    /// quietly close the behaviour by adding a `symlink_metadata` guard.
    #[test]
    fn writing_a_symlinked_note_writes_through_to_its_target() {
        let root = fixture("write-through");
        let vault = vault_of(&root);
        let outside = root.join("real/onyx/README.md");
        let link = root.join("vault/Notes/linked-note.md");
        symlink(&outside, &link).unwrap();

        write_file_in(&vault, &link.to_string_lossy(), "# edited through the link")
            .expect("saving a symlinked note must succeed");

        assert_eq!(
            fs::read_to_string(&outside).unwrap(),
            "# edited through the link",
            "the write must reach the link target"
        );
        assert!(
            fs::symlink_metadata(&link).unwrap().file_type().is_symlink(),
            "and must not replace the link with a regular file"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// SV-39 (H3b): `fs::write` truncated the live file before writing, so a
    /// crash mid-write left partial live bytes. The managed install fills a
    /// temporary and renames it over the target; a failure after partial bytes
    /// leaves the live file exactly as it was and no temporary behind.
    #[test]
    fn a_partial_install_never_becomes_the_live_file() {
        let root = fixture("managed-crash");
        let dir_path = root.join("vault/Notes");
        let live = dir_path.join("live.md");
        fs::write(&live, "old").unwrap();
        let orphans = || -> Vec<String> {
            fs::read_dir(&dir_path).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|name| name.starts_with(MANAGED_TEMP_PREFIX)).collect()
        };

        let dir = confined::open_root(&dir_path.canonicalize().unwrap()).unwrap();
        let err = confined::write_atomic(&dir, std::ffi::OsStr::new("live.md"), |file| {
            std::io::Write::write_all(file, b"par")?;
            Err(std::io::Error::other("injected crash"))
        })
        .unwrap_err();
        assert!(err.contains("injected crash"), "{err}");
        assert_eq!(fs::read_to_string(&live).unwrap(), "old", "partial bytes must never be visible at the live path");
        assert!(orphans().is_empty(), "the temporary is removed on failure");

        // A new file that fails mid-write never appears at all.
        assert!(confined::write_atomic(&dir, std::ffi::OsStr::new("fresh.md"), |_| Err(std::io::Error::other("boom"))).is_err());
        assert!(!dir_path.join("fresh.md").exists());
        assert!(orphans().is_empty());

        // And a complete install is visible in full, once.
        confined::write_atomic(&dir, std::ffi::OsStr::new("live.md"), |file| std::io::Write::write_all(file, b"new")).unwrap();
        assert_eq!(fs::read_to_string(&live).unwrap(), "new");
        assert!(orphans().is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    /// Momus's C4, which he predicted would destroy data and then measured as safe:
    /// `remove_dir_all` refuses to descend a symlink, so deleting a linked folder
    /// removes only the link. Fenced here because `delete_file` reaches that branch
    /// through `is_dir()`, which *does* follow links.
    #[test]
    fn deleting_a_linked_folder_removes_the_link_not_the_target() {
        let root = fixture("delete-link");
        let vault = vault_of(&root);
        let link = root.join("vault/Projects");

        delete_file_in(&vault, &link.to_string_lossy()).expect("delete must succeed");

        assert!(!fs::symlink_metadata(&link).is_ok(), "the link is gone");
        assert!(
            root.join("real/onyx/README.md").exists(),
            "the target contents must survive"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// A vault that is itself a symlink (`~/Vault -> /mnt/data/Vault`). The
    /// `allowed_roots` branch exists for exactly this and had no coverage, which is
    /// how the search regression got through. Passing the vault in its *link*
    /// spelling accepts a path in either spelling.
    #[test]
    fn a_symlinked_vault_root_accepts_both_of_its_spellings() {
        let root = fixture("linked-vault-both");
        let link_vault = root.join("vault-link");
        symlink(root.join("vault"), &link_vault).unwrap();
        let vault = link_vault.to_string_lossy().to_string();

        let link_spelled = link_vault.join("Notes/plain.md");
        let canonical_spelled = root.join("vault/Notes/plain.md");

        assert_eq!(
            validate_vault_path(&link_spelled.to_string_lossy(), &vault).unwrap(),
            link_spelled,
            "the spelling the frontend sends must be accepted as-is"
        );
        assert!(
            validate_vault_path(&canonical_spelled.to_string_lossy(), &vault).is_ok(),
            "the canonical spelling must be accepted too — walkdir and the watcher \
             can hand back either one"
        );
        assert!(validate_vault_path(&canonical_spelled.to_string_lossy(), &format!("{}/", vault)).is_ok());
        let fully_canonical = canonical_spelled.canonicalize().unwrap();
        assert!(validate_vault_path(&fully_canonical.to_string_lossy(), &vault).is_ok());
        assert!(validate_vault_path(&root.join("real/onyx/README.md").to_string_lossy(), &vault).is_err());
        assert!(validate_vault_path(&link_vault.join("../real/onyx/README.md").to_string_lossy(), &vault).is_err());
        assert!(validate_vault_path(&root.join("vault-sibling/file.md").to_string_lossy(), &vault).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_relative_symlinked_vault_root_accepts_its_target_spelling() {
        let root = fixture("linked-vault-relative");
        let link = root.join("vault-link");
        symlink("vault", &link).unwrap();
        let vault = link.to_string_lossy().to_string();
        let target = root.join("vault/Notes/plain.md");
        assert_eq!(validate_vault_path(&target.to_string_lossy(), &vault).unwrap(), target);
        assert!(validate_vault_path(&root.join("real/onyx/README.md").to_string_lossy(), &vault).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    /// The caller's shape, and the reason `get_configured_vault_setting` exists.
    /// `allowed_roots` only bridges settings-spelling -> canonical, never the
    /// reverse: hand it the *canonical* vault and a link-spelled path and there is
    /// no root to match, so it denies. `search_files` used to source its vault from
    /// a canonicalizing helper, which denied every search for anyone whose vault is
    /// a symlink. This test pins the asymmetry so the helper cannot be swapped back.
    // -----------------------------------------------------------------------
    // Managed (shared-vault) primitives: SV-32 confinement.
    // -----------------------------------------------------------------------

    /// A shared mount at `<tmp>/vault/mount` with every shape of planted link:
    ///   vault/mount/link      -> <tmp>/real          (directory link mid-path)
    ///   vault/mount/note.md   -> <tmp>/real/onyx/README.md (file link at the target)
    ///   vault/Shared          -> <tmp>/real          (link *at* a mount root)
    fn managed_fixture(tag: &str) -> PathBuf {
        let root = fixture(tag);
        fs::create_dir_all(root.join("vault/mount")).unwrap();
        symlink(root.join("real"), root.join("vault/mount/link")).unwrap();
        symlink(root.join("real/onyx/README.md"), root.join("vault/mount/note.md")).unwrap();
        symlink(root.join("real"), root.join("vault/Shared")).unwrap();
        root
    }

    fn s(path: &Path) -> String {
        path.to_string_lossy().to_string()
    }

    fn temp_orphans(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|name| name.starts_with(MANAGED_TEMP_PREFIX))
            .collect()
    }

    /// SV-32 (H3): the attack from the report. `validate_vault_path` accepts
    /// `mount/link/new.md` lexically and the legacy `write_binary_file` would
    /// have created `<tmp>/real/new.md`. The managed write refuses every link
    /// below the root — mid-path, at the final component, and at a mount root —
    /// and nothing outside the notebook changes.
    #[test]
    fn managed_write_never_follows_a_descendant_link() {
        let root = managed_fixture("managed-no-follow");
        let notebook = vault_of(&root);
        let readme = root.join("real/onyx/README.md");

        for relative in ["vault/mount/link/new.md", "vault/mount/link/deeper/new.md", "vault/Shared/new.md"] {
            let err = managed_write_bytes(&notebook, &s(&root.join(relative)), b"remote").unwrap_err();
            assert!(err.contains("symbolic link"), "{relative}: {err}");
        }
        assert!(!root.join("real/new.md").exists(), "the write must not land through the link");
        assert!(!root.join("real/deeper").exists(), "no directory may be created through the link either");

        let err = managed_write_bytes(&notebook, &s(&root.join("vault/mount/note.md")), b"remote").unwrap_err();
        assert!(err.contains("symbolic link"), "{err}");
        assert_eq!(fs::read_to_string(&readme).unwrap(), "# linked", "the link target is untouched");
        assert!(fs::symlink_metadata(root.join("vault/mount/note.md")).unwrap().file_type().is_symlink(), "and the link itself is preserved");

        // The legacy command keeps following links (Derek's ruling), so the two
        // surfaces must differ on exactly this input.
        write_binary_file_in(&notebook, &s(&root.join("vault/mount/link/legacy.md")), b"user").unwrap();
        assert!(root.join("real/legacy.md").exists());
        assert!(temp_orphans(&root.join("vault/mount")).is_empty());

        // And like every vault command, the managed ones refuse a caller-supplied
        // path outside the configured notebook outright.
        let outside = root.join("real/onyx");
        assert!(managed_write_bytes(&notebook, &s(&outside.join("scratch")), b"x").is_err());
        assert!(managed_read_bytes(&notebook, &s(&readme)).is_err());
        assert!(managed_create_folder(&notebook, &s(&outside.join("scratch"))).is_err());
        assert!(managed_remove(&notebook, &s(&readme)).is_err());
        assert!(readme.exists() && !outside.join("scratch").exists());
        let _ = fs::remove_dir_all(&root);
    }

    /// The notebook root itself may be the user's symlink; only descendants may not
    /// redirect. Both spellings of a path under a linked root install into the
    /// real directory.
    #[test]
    fn managed_write_accepts_a_symlinked_notebook_root() {
        let root = fixture("managed-linked-root");
        let link_vault = root.join("vault-link");
        symlink(root.join("vault"), &link_vault).unwrap();
        let notebook = s(&link_vault);

        managed_write_bytes(&notebook, &s(&link_vault.join("Notes/from-link.md")), b"a").unwrap();
        managed_write_bytes(&notebook, &s(&root.join("vault/Notes/from-canonical.md")), b"b").unwrap();
        assert_eq!(fs::read(root.join("vault/Notes/from-link.md")).unwrap(), b"a");
        assert_eq!(fs::read(root.join("vault/Notes/from-canonical.md")).unwrap(), b"b");
        assert_eq!(managed_read_bytes(&notebook, &s(&link_vault.join("Notes/from-canonical.md"))).unwrap(), b"b");
        // A link *below* the linked root is still refused.
        assert!(managed_write_bytes(&notebook, &s(&link_vault.join("Projects/new.md")), b"c").is_err());
        assert!(!root.join("real/onyx/new.md").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn managed_write_creates_parents_and_replaces_without_orphans() {
        let root = managed_fixture("managed-replace");
        let notebook = vault_of(&root);
        let target = root.join("vault/mount/a/b/c.md");

        managed_write_bytes(&notebook, &s(&target), b"one").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"one");
        managed_write_bytes(&notebook, &s(&target), b"two").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"two");
        assert!(temp_orphans(target.parent().unwrap()).is_empty());
        // A replaced regular file keeps its permission bits (a 0600 note stays 0600).
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        managed_write_bytes(&notebook, &s(&target), b"three").unwrap();
        assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read(&target).unwrap(), b"three");
        // Replacing a directory with a file is a type transition the engine
        // performs through `remove` first; the install alone refuses it.
        assert!(managed_write_bytes(&notebook, &s(&root.join("vault/mount/a")), b"x").is_err());
        assert!(root.join("vault/mount/a/b/c.md").exists());
        assert!(temp_orphans(&root.join("vault/mount")).is_empty());
        // The root itself is never a write target.
        assert!(managed_write_bytes(&notebook, &notebook, b"x").is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn managed_remove_read_and_mkdir_never_follow_links() {
        let root = managed_fixture("managed-remove");
        let notebook = vault_of(&root);
        let mount = root.join("vault/mount");
        fs::create_dir_all(mount.join("dir/sub")).unwrap();
        fs::write(mount.join("dir/sub/file.md"), "x").unwrap();
        symlink(root.join("real"), mount.join("dir/escape")).unwrap();
        symlink(root.join("real/onyx/README.md"), mount.join("dir/escape.md")).unwrap();

        // Through a link component: refused, target untouched.
        assert!(managed_remove(&notebook, &s(&mount.join("link/onyx"))).is_err());
        assert!(managed_remove(&notebook, &s(&mount.join("link/onyx/README.md"))).is_err());
        assert!(managed_read_bytes(&notebook, &s(&mount.join("link/onyx/README.md"))).is_err());
        assert!(managed_read_bytes(&notebook, &s(&mount.join("note.md"))).is_err());
        assert!(managed_create_folder(&notebook, &s(&mount.join("link/made"))).is_err());
        assert!(managed_create_folder(&notebook, &s(&root.join("vault/Shared/made"))).is_err());
        assert!(!root.join("real/made").exists());
        assert!(root.join("real/onyx/README.md").exists());

        // A tree containing links: the links are unlinked, their targets survive.
        managed_remove(&notebook, &s(&mount.join("dir"))).unwrap();
        assert!(!mount.join("dir").exists());
        assert_eq!(fs::read_to_string(root.join("real/onyx/README.md")).unwrap(), "# linked");
        assert!(root.join("real/onyx").is_dir());

        // Removing a link itself removes only the link.
        managed_remove(&notebook, &s(&mount.join("link"))).unwrap();
        assert!(fs::symlink_metadata(mount.join("link")).is_err());
        assert!(root.join("real/onyx/README.md").exists());
        assert!(managed_remove(&notebook, &s(&mount.join("missing"))).is_err());

        managed_create_folder(&notebook, &s(&mount.join("new/nested"))).unwrap();
        assert!(mount.join("new/nested").is_dir());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_canonical_vault_root_cannot_match_a_link_spelled_path() {
        let root = fixture("linked-vault-asymmetry");
        let link_vault = root.join("vault-link");
        symlink(root.join("vault"), &link_vault).unwrap();

        let canonical_vault = root.join("vault").to_string_lossy().to_string();
        let link_spelled = link_vault.join("Notes/plain.md");

        assert!(
            validate_vault_path(&link_spelled.to_string_lossy(), &canonical_vault).is_err(),
            "a canonical vault root denies the link spelling — so commands must be \
             given the settings spelling, which accepts both"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
