//! The Reaper is responsible for initializing the enclave's primary
//! processes. Concretely it spawns the enclave server and launches the "pivot"
//! executable once it becomes available in the file system.
//!
//! The pivot is an executable the enclave runs to initialize the secure
//! applications.
use std::{
	fs,
	net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
	process::Stdio,
	sync::{Arc, RwLock},
	time::Duration,
};

use qos_nsm::NsmProvider;
use tokio::{
	io::{AsyncBufReadExt, BufReader},
	process::{Child, Command},
};

use crate::{
	handles::Handles,
	io::{HostBridge, IOError, SocketAddress, StreamPool},
	protocol::{
		ProtocolPhase, ProtocolState,
		processor::ProtocolProcessor,
		services::boot::{BridgeConfig, RestartPolicy},
	},
	server::SocketServer,
};

/// Delay for restarting the pivot app if the process exits.
pub const REAPER_RESTART_DELAY: Duration = Duration::from_millis(50);
/// Delay until the reaper exits after pivot app with a Never restart policy
/// exits.
pub const REAPER_EXIT_DELAY: Duration = Duration::from_secs(3);

const REAPER_STATE_CHECK_DELAY: Duration = Duration::from_millis(100);
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

// runs the enclave vsock setup server for qos_host communication, waiting for manifest/pivot
// executed as a task from `Reaper::execute`
async fn run_server(
	server_state: Arc<RwLock<InterState>>,
	handles: Handles,
	nsm: Box<dyn NsmProvider + Send>,
	core_socket: SocketAddress,
	test_only_init_phase_override: Option<ProtocolPhase>,
) {
	let protocol_state =
		ProtocolState::new(nsm, handles.clone(), test_only_init_phase_override)
			.shared();
	let core_pool = StreamPool::single(core_socket)
		.expect("unable to create single socket core pool");
	// send a shared version of state and the async pool to each processor
	let protocol_processor = ProtocolProcessor::new(protocol_state);

	// listen on the protocol server
	let _protocol_server =
		SocketServer::listen_all(core_pool, protocol_processor, 1)
			.expect("unable to get listen task list for protocol server");

	println!("Reaper::server running");
	while *server_state.read().unwrap() != InterState::Quitting {
		tokio::time::sleep(REAPER_STATE_CHECK_DELAY).await;
	}

	println!("Reaper::server shutdown");
}

// runs configured bridges based on `BridgeConfig` so that apps can use any TCP based protocol without worrying about VSOCK
// communication. This is started if `PivotConfig::bridge_config` has any members defined.
// uses the enclave core socket and given pivot host port to construct the VSOCK to TCP bridge for server side
// and opens a fully transparent egress if client side is set.
fn run_bridges(
	core_socket: &SocketAddress,
	bridges: &[BridgeConfig],
) -> Result<(), IOError> {
	// do nothing if we're not asked to provide bridging
	if bridges.is_empty() {
		println!("skipping host bridge, not configured");
		return Ok(());
	}

	let mut egress_enabled = false;

	for bc in bridges {
		match bc {
			BridgeConfig::Server { port, host: _ } => {
				let app_socket = core_socket.with_port(*port)?;
				let host_addr: SocketAddr =
					SocketAddrV4::new(Ipv4Addr::LOCALHOST, *port).into();
				let app_pool = StreamPool::single(app_socket)?;
				let bridge = HostBridge::new(app_pool, host_addr);

				bridge.vsock_to_tcp();
			}
			BridgeConfig::Client { port: _, host: _ } => {
				// only run one instance as it covers ALL ports, the others are for firewalls
				if !egress_enabled {
					egress_enabled = true;
					run_egress_bridge(core_socket);
				}
			}
		}
	}

	Ok(())
}

// dummy placeholder
#[cfg(not(feature = "egress"))]
fn run_egress_bridge(_core_socket: &SocketAddress) {
	panic!("unable to run egress without vsock support");
}

// run the transparent host egress
#[cfg(feature = "egress")]
fn run_egress_bridge(core_socket: &SocketAddress) {
	let cid = core_socket.vsock().cid();

	crate::egress::run_looping(
		"/egress",
		&format!("--cid {cid} --vsock-to-host false"),
	);
}

fn reprint_pivot_output(child: &mut Child) {
	let stdout = child.stdout.take().expect("failed to get pivot stdout");
	let stderr = child.stderr.take().expect("failed to get pivot stderr");

	let stdout_reader = BufReader::new(stdout);
	let stderr_reader = BufReader::new(stderr);

	tokio::spawn(async move {
		let mut stdout_lines = stdout_reader.lines();
		let mut stderr_lines = stderr_reader.lines();

		loop {
			tokio::select! {
				line = stdout_lines.next_line() => {
					match line {
						Ok(Some(line)) => println!("PIVOT[OUT]: {line}"),
						Ok(None) => break, // process exit
						Err(e) => eprintln!("error reading pivot stdout: {e}"),
					}
				}
				line = stderr_lines.next_line() => {
					match line {
						Ok(Some(line)) => eprintln!("PIVOT[ERR]: {line}"),
						Ok(None) => break, // process exit
						Err(e) => eprintln!("error reading pivot stderr: {e}"),
					}
				}
			}
		}
	});
}

fn resolv_conf_with_nameservers(resolvers: &[IpAddr]) -> String {
	let mut output = String::new();
	for resolver in resolvers {
		output.push_str("nameserver ");
		output.push_str(&resolver.to_string());
		output.push('\n');
	}
	output
}

fn write_resolv_conf(resolvers: &[IpAddr]) -> std::io::Result<()> {
	fs::write(RESOLV_CONF_PATH, resolv_conf_with_nameservers(resolvers))
}

/// Whether the files the pivot starts on are all written. The protocol writes
/// last the quorum key, or, for a manifest that boots without one, the app
/// key, or with no app key either, the manifest.
fn ready_to_pivot(handles: &Handles) -> bool {
	if !handles.pivot_exists() || !handles.manifest_envelope_exists() {
		return false;
	}
	if handles.quorum_key_exists() {
		return true;
	}
	match handles.get_manifest_envelope() {
		Ok(envelope) if envelope.no_quorum_key() => {
			envelope.app_key_minter().is_none() || handles.app_key_exists()
		}
		_ => false,
	}
}

/// Primary entry point for running the enclave. Coordinates spawning the server
/// and pivot binary.
pub struct Reaper;
impl Reaper {
	/// Run the Reaper, with the given shutdown oneshot channel Receiver. If a signal is passed (regardless of value)
	/// the Reaper will shut down and clean up the server. It is the responsibility of the caller to send the shutdown
	/// signal.
	///
	/// # Panics
	///
	/// - If spawning the pivot errors.
	/// - If waiting for the pivot errors.
	pub async fn execute(
		handles: &Handles,
		nsm: Box<dyn NsmProvider + Send>,
		core_socket: SocketAddress,
		test_only_init_phase_override: Option<ProtocolPhase>,
	) {
		// state switch to communicate between pivot run task (here) and run_server task
		// we need to establish
		let inter_state = Arc::new(RwLock::new(InterState::Booting));
		let server_state = inter_state.clone();

		let server_worker = tokio::spawn(run_server(
			server_state,
			handles.clone(),
			nsm,
			core_socket.clone(),
			test_only_init_phase_override,
		));

		loop {
			let server_state = *inter_state.read().unwrap();
			// helper for integration tests and manual runs aka qos_core binary
			if server_state == InterState::Quitting {
				eprintln!("quit called by ctrl+c");
				std::process::exit(1);
			}

			if ready_to_pivot(handles) {
				// The state required to pivot exists, so we can break this
				// holding pattern and start the pivot.
				break;
			}

			eprintln!("Reaper::execute waiting for pivot and manifest");
			tokio::time::sleep(REAPER_STATE_CHECK_DELAY).await;
		}

		println!("Reaper::execute about to spawn pivot");

		let manifest = handles
			.get_manifest_envelope()
			.expect("Checked above that the manifest exists.")
			.manifest();
		let args = manifest.args().to_vec();
		let restart = manifest.restart();
		let host_config = manifest.bridge_config().to_vec();
		let dns_config = manifest.dns_config().cloned();

		if let Some(dns_config) = dns_config {
			write_resolv_conf(&dns_config.resolvers)
				.expect("failed to write /etc/resolv.conf");
		}

		// if the app indicates the need for the VSOCK -> TCP bridge, run it as another task
		run_bridges(&core_socket, &host_config)
			.expect("failed to run ingress/egress bridges");

		let mut pivot = Command::new(handles.pivot_path());
		pivot.env_clear();
		pivot.args(&args[..]);
		// Only pipe pivot output when it will be drained below.
		if manifest.debug_mode() {
			pivot.stdout(Stdio::piped()).stderr(Stdio::piped());
		} else {
			pivot.stdout(Stdio::null()).stderr(Stdio::null());
		}

		loop {
			let mut child = pivot.spawn().expect("Failed to spawn pivot");
			// print pivot stderr and stdout if in debug mode
			// *NOTE*: this requires `DEBUG` and `LOGS` env vars set when booting the enclave itself. If not, nothing will be visible
			if manifest.debug_mode() {
				reprint_pivot_output(&mut child);
			}

			let status =
				child.wait().await.expect("Pivot executable never started...");

			println!("Pivot exited with status: {status}");
			// pause to ensure OS has enough time to clean up resources
			// before restarting
			tokio::time::sleep(REAPER_RESTART_DELAY).await;

			match restart {
				RestartPolicy::Always => {}
				RestartPolicy::Never => break,
			}
			println!("Restarting pivot ...");
		}

		*inter_state.write().unwrap() = InterState::Quitting;

		tokio::time::sleep(REAPER_EXIT_DELAY).await;

		if let Err(err) = server_worker.await {
			eprintln!("Reaper::execute server_worker join error: {err:?}");
		}

		println!("Reaper exiting ... ");
	}
}

// basic helper for x-thread comms in Reaper
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterState {
	// We're booting, no pivot yet
	Booting,
	// We're quitting (ctrl+c for tests and such)
	Quitting,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn resolv_conf_write_uses_configured_nameservers() {
		let resolvers = ["1.1.1.1", "2606:4700:4700::1111"]
			.into_iter()
			.map(|resolver| resolver.parse().unwrap())
			.collect::<Vec<IpAddr>>();

		assert_eq!(
			resolv_conf_with_nameservers(&resolvers),
			"nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\n"
		);
	}

	#[test]
	fn resolv_conf_write_supports_empty_resolver_list() {
		assert_eq!(resolv_conf_with_nameservers(&[]), "");
	}

	mod ready_to_pivot {
		use qos_hybrid::HybridPair;
		use qos_test_primitives::PathWrapper;

		use super::super::ready_to_pivot;
		use crate::{
			handles::Handles,
			protocol::services::boot::{
				ManifestBuilder, ManifestSet, Namespace, NitroConfig,
				ShareSetV2, VersionedManifest, VersionedManifestEnvelope,
				manifest::v2::ManifestEnvelopeV2,
			},
		};

		/// Handles over files under `name`, removed on drop, holding a pivot
		/// and a v2 manifest that boots without a quorum key when
		/// `no_quorum_key`, naming an app key minter when `minter`.
		fn booted(
			name: &str,
			no_quorum_key: bool,
			minter: bool,
		) -> (Handles, Vec<PathWrapper<String>>) {
			let path = |file: &str| {
				PathWrapper::from(format!("/tmp/ready_to_pivot_{name}.{file}"))
			};
			let files = vec![
				path("eph"),
				path("quorum"),
				path("app"),
				path("manifest"),
				path("pivot"),
			];
			let handles = Handles::new(
				files[0].display().to_string(),
				files[1].display().to_string(),
				files[2].display().to_string(),
				files[3].display().to_string(),
				files[4].display().to_string(),
			);
			let builder = ManifestBuilder::v2()
				.namespace(Namespace {
					name: name.to_string(),
					nonce: 1,
					quorum_key: Vec::new(),
				})
				.pivot_hash([0; 32])
				.manifest_set(ManifestSet::default())
				.share_holders(ShareSetV2::default())
				.enclave(NitroConfig::default());
			let builder = if minter {
				builder.app_key_minter(
					HybridPair::generate().unwrap().public_key().to_bytes(),
				)
			} else {
				builder
			};
			let builder =
				if no_quorum_key { builder.no_quorum_key() } else { builder };
			let VersionedManifest::V2(manifest) = builder.build().unwrap()
			else {
				unreachable!("ManifestBuilder::v2 builds v2");
			};
			handles.put_pivot(b"pivot").unwrap();
			handles
				.put_manifest_envelope(VersionedManifestEnvelope::V2(
					ManifestEnvelopeV2 {
						manifest,
						manifest_set_approvals: Vec::new(),
						share_set_approvals: Vec::new(),
					},
				))
				.unwrap();
			(handles, files)
		}

		#[test]
		fn a_manifest_with_a_quorum_key_waits_for_it() {
			let (handles, _files) = booted("with_quorum", false, false);
			assert!(!ready_to_pivot(&handles));

			handles.put_quorum_key(&HybridPair::generate().unwrap()).unwrap();
			assert!(ready_to_pivot(&handles));
		}

		#[test]
		fn a_manifest_without_a_quorum_key_or_minter_starts_at_once() {
			let (handles, _files) = booted("no_quorum", true, false);
			assert!(ready_to_pivot(&handles));
		}

		#[test]
		fn a_manifest_without_a_quorum_key_waits_for_its_app_key() {
			let (handles, _files) = booted("no_quorum_minter", true, true);
			assert!(!ready_to_pivot(&handles));

			handles.put_app_key(&HybridPair::generate().unwrap()).unwrap();
			assert!(ready_to_pivot(&handles));
		}
	}
}

// See qos_test/tests/async_reaper for more tests
