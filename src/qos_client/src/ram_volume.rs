//! Decides whether a directory sits on a RAM-backed volume, the only place a
//! release build of `qos_client` writes a transient plaintext key: a Shamir
//! share, a reconstructed secret, a decrypted plaintext. It also holds the
//! `YubiKey` member passphrase file. A file-held key from `generate-file-key`
//! is the operator's identity and is written wherever it is asked to be, with
//! owner-only permissions. On macOS a volume counts when `hdiutil`
//! reports it as part of a `ram://` disk image, and on Linux when it is tmpfs
//! or ramfs. A refusal prints how to make one.
//!
//! Ported from nimbus-core's `root-gen-operator`, which enforces the same rule.

use std::path::Path;

/// Admits `dir` as the target of a plaintext key: a release build refuses it
/// unless it is RAM-backed, naming how to make a RAM disk; a debug build, which
/// the tests run against `/tmp`, warns and writes anyway.
///
/// # Errors
///
/// Returns the refusal in a release build.
pub fn admit(dir: &Path) -> Result<(), String> {
	match require(dir) {
		Ok(()) => Ok(()),
		Err(refusal) if cfg!(debug_assertions) => {
			eprintln!("WARNING (debug build only): {refusal}");
			Ok(())
		}
		Err(refusal) => Err(refusal),
	}
}

/// Admits the directory holding the file at `path`, as [`admit`] does.
///
/// # Errors
///
/// Returns the refusal in a release build.
pub fn admit_file(path: &Path) -> Result<(), String> {
	match path.parent() {
		Some(dir) if !dir.as_os_str().is_empty() => admit(dir),
		_ => admit(Path::new(".")),
	}
}

/// Refuses `dir` unless it is on a RAM-backed volume, naming how to make one.
///
/// # Errors
///
/// Returns a message when `dir` cannot be examined, when it is on any other volume, or when this
/// platform has no way to tell.
pub fn require(dir: &Path) -> Result<(), String> {
	if ram_backed(dir)? {
		return Ok(());
	}
	Err(format!(
		"{} is not on a RAM-backed volume, and a plaintext key written there outlives this \
         session on the disk. {}",
		dir.display(),
		HOW_TO_MAKE_ONE
	))
}

#[cfg(target_os = "macos")]
const HOW_TO_MAKE_ONE: &str = "Make a RAM disk and pass a private directory on it:\n  \
     dev=$(hdiutil attach -nomount ram://131072 | awk '{print $1}')\n  \
     diskutil erasevolume HFS+ \"qos-keys-$(openssl rand -hex 6)\" \"$dev\"\n  \
     mnt=$(diskutil info \"$dev\" | sed -n 's/^ *Mount Point: *//p')\n  \
     touch \"$mnt/.metadata_never_index\"\n  \
     mkdir -m 700 \"$mnt/keys\"\n\
     and destroy it, keys and all, with `hdiutil detach \"$dev\" || hdiutil detach -force \"$dev\"` \
     when done. HFS+ rather than APFS keeps one device: APFS synthesises a container disk, so the \
     volume mounts from one device and detaches through another.";

#[cfg(target_os = "linux")]
const HOW_TO_MAKE_ONE: &str = "Pass a private directory on a tmpfs, $XDG_RUNTIME_DIR or else \
     /dev/shm:\n  \
     mkdir -m 700 \"${XDG_RUNTIME_DIR:-/dev/shm}/qos-keys\"\n\
     and remove it with `rm -rf \"${XDG_RUNTIME_DIR:-/dev/shm}/qos-keys\"` when done. A tmpfs \
     can swap; for keys that must not, mount a ramfs and pass a directory on it:\n  \
     sudo mkdir -p /mnt/qos-keys\n  \
     sudo mount -t ramfs -o mode=700 ramfs /mnt/qos-keys && sudo chown \"$USER\" /mnt/qos-keys\n  \
     mkdir -m 700 /mnt/qos-keys/keys\n\
     and destroy it with `sudo umount /mnt/qos-keys` when done.";

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const HOW_TO_MAKE_ONE: &str = "This platform has no check for a RAM-backed volume; write \
     plaintext keys on macOS or Linux.";

/// Returns whether `dir` is on a RAM disk: the device `df` reports it mounted
/// from belongs to a `ram://` image in `hdiutil info`.
#[cfg(target_os = "macos")]
fn ram_backed(dir: &Path) -> Result<bool, String> {
	Ok(ram_image_holds(&disk_images()?, &mounted_from(dir)?))
}

/// Returns the device the volume holding `dir` is mounted from, as `df -P`
/// reports it, run by absolute path so nothing earlier on `PATH` answers.
#[cfg(target_os = "macos")]
fn mounted_from(dir: &Path) -> Result<String, String> {
	let output = std::process::Command::new("/bin/df")
		.arg("-P")
		.arg(dir)
		.output()
		.map_err(|error| format!("running df: {error}"))?;
	if !output.status.success() {
		return Err(format!(
			"examining the volume under {}: df failed ({})",
			dir.display(),
			output.status
		));
	}
	String::from_utf8_lossy(&output.stdout)
		.lines()
		.nth(1)
		.and_then(|line| line.split_whitespace().next())
		.map(str::to_owned)
		.ok_or_else(|| {
			format!("df named no device for the volume under {}", dir.display())
		})
}

/// Returns whether `dir` is on a tmpfs or ramfs, by the filesystem type
/// `statfs` reports.
#[cfg(target_os = "linux")]
fn ram_backed(dir: &Path) -> Result<bool, String> {
	use nix::sys::statfs::{FsType, TMPFS_MAGIC, statfs};

	const RAMFS_MAGIC: FsType = FsType(0x8584_58f6);
	let filesystem = statfs(dir)
		.map_err(|error| {
			format!("examining the volume under {}: {error}", dir.display())
		})?
		.filesystem_type();
	Ok(filesystem == TMPFS_MAGIC || filesystem == RAMFS_MAGIC)
}

/// Refuses every directory: this platform has no check.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn ram_backed(_dir: &Path) -> Result<bool, String> {
	Ok(false)
}

/// Returns `hdiutil info` as JSON, converted from its plist by `plutil`, both run by absolute path
/// so nothing earlier on `PATH` answers in their place.
#[cfg(target_os = "macos")]
fn disk_images() -> Result<serde_json::Value, String> {
	use std::io::Write as _;
	use std::process::{Command, Stdio};

	let info = Command::new("/usr/bin/hdiutil")
		.args(["info", "-plist"])
		.output()
		.map_err(|error| format!("running hdiutil info: {error}"))?;
	if !info.status.success() {
		return Err(format!("hdiutil info failed ({})", info.status));
	}
	let mut convert = Command::new("/usr/bin/plutil")
		.args(["-convert", "json", "-o", "-", "-"])
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.spawn()
		.map_err(|error| format!("running plutil: {error}"))?;
	convert
		.stdin
		.take()
		.ok_or_else(|| "plutil took no input".to_owned())?
		.write_all(&info.stdout)
		.map_err(|error| format!("feeding plutil: {error}"))?;
	let converted = convert
		.wait_with_output()
		.map_err(|error| format!("running plutil: {error}"))?;
	if !converted.status.success() {
		return Err(format!(
			"plutil could not convert hdiutil's plist ({})",
			converted.status
		));
	}
	serde_json::from_slice(&converted.stdout)
		.map_err(|error| format!("hdiutil info does not parse: {error}"))
}

/// Returns whether `info`, `hdiutil info` as JSON, lists `device` among the entities of an image
/// whose path is `ram://`. An HFS+ volume erased onto a RAM disk mounts from the image's own
/// device, its only entity. An APFS volume mounts from a slice of the container disk APFS
/// synthesises, and `hdiutil` lists that slice and its container under the image too.
#[cfg(any(target_os = "macos", test))]
fn ram_image_holds(info: &serde_json::Value, device: &str) -> bool {
	info["images"].as_array().is_some_and(|images| {
		images.iter().any(|image| {
			image["image-path"]
				.as_str()
				.is_some_and(|path| path.starts_with("ram://"))
				&& image["system-entities"].as_array().is_some_and(|entities| {
					entities.iter().any(|entity| {
						entity["dev-entry"].as_str() == Some(device)
					})
				})
		})
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	fn images() -> serde_json::Value {
		serde_json::json!({
			"images": [
				{
					"image-path": "/System/Library/AssetsV2/runtime.dmg",
					"system-entities": [
						{ "dev-entry": "/dev/disk6" },
						{ "dev-entry": "/dev/disk7s1", "mount-point": "/Library/Developer" }
					]
				},
				{
					"image-path": "ram://20480",
					"system-entities": [
						{ "dev-entry": "/dev/disk8" },
						{ "dev-entry": "/dev/disk9" },
						{ "dev-entry": "/dev/disk9s1", "mount-point": "/Volumes/qos-keys" }
					]
				},
				{
					"image-path": "ram://131072",
					"system-entities": [
						{
							"dev-entry": "/dev/disk10",
							"mount-point": "/Volumes/qos-keys-0a1b2c3d4e5f"
						}
					]
				}
			]
		})
	}

	#[test]
	fn an_hfs_volume_on_a_ram_image_is_ram_backed() {
		assert!(
			ram_image_holds(&images(), "/dev/disk10"),
			"diskutil erasevolume HFS+ on a ram:// device mounts that device itself, the image's \
             only entity, as nimbus-core's RAM disk recipe does"
		);
	}

	#[test]
	fn an_apfs_volume_on_a_ram_image_is_ram_backed() {
		assert!(
			ram_image_holds(&images(), "/dev/disk9s1"),
			"diskutil erasevolume APFS on a ram:// device mounts a slice of a synthesised \
             container, which hdiutil lists under the RAM image beside the raw device"
		);
	}

	#[test]
	fn a_volume_on_a_file_backed_image_or_no_image_is_not() {
		assert!(!ram_image_holds(&images(), "/dev/disk7s1"));
		assert!(!ram_image_holds(&images(), "/dev/disk3s1"));
		assert!(!ram_image_holds(&serde_json::json!({}), "/dev/disk9s1"));
	}

	#[test]
	fn a_directory_on_the_build_disk_is_refused_with_the_way_to_make_a_ram_disk()
	 {
		let error = require(Path::new(env!("CARGO_MANIFEST_DIR")))
			.expect_err("the source tree sits on a disk, not in RAM");
		assert!(error.contains("not on a RAM-backed volume"), "{error}");
		assert!(error.contains(HOW_TO_MAKE_ONE), "{error}");
	}

	#[cfg(target_os = "macos")]
	#[test]
	fn the_refusal_on_macos_prints_the_hfs_recipe() {
		for step in [
			"hdiutil attach -nomount ram://",
			"diskutil erasevolume HFS+ ",
			"diskutil info",
			".metadata_never_index",
			"mkdir -m 700",
			"hdiutil detach -force",
		] {
			assert!(
				HOW_TO_MAKE_ONE.contains(step),
				"the macOS recipe must keep the step `{step}`: {HOW_TO_MAKE_ONE}"
			);
		}
		assert!(
			!HOW_TO_MAKE_ONE.contains("erasevolume APFS"),
			"an APFS volume mounts from a synthesised container disk rather than the RAM device, \
             so the recipe formats HFS+"
		);
	}
}
