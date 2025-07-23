use std::{path::Path, process::Command, time::Duration};

use anyhow::{Context, Result};
use pcap::{Active, Capture, Device};

// Import the tester module
mod tester;
use tester::*;

// Global constants for 5G Network Functions IP addresses
pub const AMF_IP: &str = "10.0.0.2"; // Access and Mobility Management Function
pub const SMF_IP: &str = "10.0.0.3"; // Session Management Function
pub const UPF_IP: &str = "10.0.0.4"; // User Plane Function
pub const NRF_IP: &str = "10.0.0.5"; // Network Repository Function
pub const AUSF_IP: &str = "10.0.0.6"; // Authentication Server Function
pub const PCF_IP: &str = "10.0.0.7"; // Policy Control Function
pub const NSSF_IP: &str = "10.0.0.8"; // Network Slice Selection Function
pub const UDM_IP: &str = "10.0.0.9"; // Unified Data Management
pub const UDR_IP: &str = "10.0.0.10"; // Unified Data Repository
pub const BSF_IP: &str = "10.0.0.11"; // Binding Support Function
pub const CHF_IP: &str = "10.0.0.12"; // Charging Function
pub const SMSF_IP: &str = "10.0.0.13"; // Short Message Service Function
pub const N3IWF_IP: &str = "10.0.0.14"; // Non-3GPP Interworking Function
pub const SEPP_IP: &str = "10.0.0.15"; // Security Edge Protection Proxy
pub const NWDAF_IP: &str = "10.0.0.16"; // Network Data Analytics Function
pub const GMLC_IP: &str = "10.0.0.17"; // Gateway Mobile Location Centre
pub const SCEF_IP: &str = "10.0.0.18"; // Service Capability Exposure Function
pub const EIR_IP: &str = "10.0.0.19"; // Equipment Identity Register
pub const UDSF_IP: &str = "10.0.0.20"; // Unstructured Data Storage Function
pub const LMF_IP: &str = "10.0.0.21"; // Location Management Function
pub const MBSF_IP: &str = "10.0.0.22"; // Multicast Broadcast Service Function
pub const NAF_IP: &str = "10.0.0.23"; // Network Application Function
pub const NEF_IP: &str = "10.0.0.24"; // Network Exposure Function
pub const SCP_IP: &str = "10.0.0.25"; // Service Communication Proxy
pub const SPP_IP: &str = "10.0.0.26"; // Service Producer Proxy
pub const HSS_IP: &str = "10.0.0.27"; // Home Subscriber Server
pub const CBC_IP: &str = "10.0.0.28"; // Cell Broadcast Centre
pub const IWF_IP: &str = "10.0.0.29"; // Interworking Function
pub const DCCF_IP: &str = "10.0.0.30"; // Data Collection Coordination Function

// GNB Simulator IP addresses
pub const RAN1_IP: &str = "10.0.1.0"; // Ran1
pub const RAN2_IP: &str = "10.0.1.1"; // Ran2
pub const RAN3_IP: &str = "10.0.1.2"; // Ran3

// MongoDB
pub const MONGO_IP: &str = "10.0.100.0"; // MongoDB

/// Orchestrates the integration test by setting up Docker Compose services, capturing network packets, and analyzing them.
///
/// This asynchronous entry point ensures a clean Docker environment, launches 5G network function simulators using Docker Compose,
/// waits for the Docker bridge interface, captures all network packets on that interface, and processes them for 30 seconds.
/// Returns an error if any setup step fails or if the required Docker Compose file is missing.
async fn main() -> Result<()> {
	let compose_file = "docker-compose.yaml";

	if !Path::new(compose_file).exists() {
		anyhow::bail!("docker-compose.yaml not found in current directory");
	}

	println!("Cleaning up any existing containers and networks...");
	cleanup_docker_resources()?;

	// Start Docker Compose in background first
	println!("Starting Docker Compose services...");
	start_docker_compose_background().await?;

	// Start packet capture (will wait for bridge to be created)
	println!("Starting packet capture on bridge...");
	let mut capture = start_packet_capture().await?;

	// Process packets with advanced filtering and dissection
	println!("Capturing and analyzing packets for 30 seconds...");
	process_filtered_packets(&mut capture, Duration::from_secs(30))?;

	println!("Packet capture and analysis stopped.");

	Ok(())
}

/// Cleans up Docker containers and networks to prepare for a fresh test environment.
///
/// Stops and removes existing Docker Compose containers and orphaned services, deletes the `omnipath_nf-network` network if present, prunes unused Docker networks, and removes any Docker networks whose names contain "bridge" or "nf-network" to prevent IP conflicts.
///
/// # Examples
///
/// ```
/// cleanup_docker_resources()?;
/// ```
fn cleanup_docker_resources() -> Result<()> {
	// Stop and remove any existing containers
	let _ = Command::new("docker-compose")
		.args(["down", "--remove-orphans"])
		.current_dir(".")
		.output();

	// Remove any existing network with the same name
	let _ = Command::new("docker")
		.args(["network", "rm", "omnipath_nf-network"])
		.output();

	// Remove all bridge networks to avoid IP conflicts
	let _ = Command::new("docker")
		.args(["network", "prune", "-f"])
		.output();

	// List and remove specific bridge networks that might conflict
	let output = Command::new("docker")
		.args(["network", "ls", "--format", "{{.Name}}"])
		.output();

	if let Ok(output) = output {
		let networks = String::from_utf8_lossy(&output.stdout);
		for network in networks.lines() {
			if network.contains("bridge") || network.contains("nf-network") {
				let _ = Command::new("docker")
					.args(["network", "rm", network])
					.output();
			}
		}
	}

	Ok(())
}

/// Starts Docker Compose services synchronously in the current directory.
///
/// Runs `docker compose up --build` and waits for completion. Returns an error if the command fails.
fn start_docker_compose() -> Result<()> {
	// Run docker compose up
	let output = Command::new("docker")
		.args(["compose", "up", "--build"])
		.current_dir(".")
		.output()
		.context("Failed to execute docker compose command")?;

	if output.status.success() {
		println!("Docker Compose services started successfully!");
		println!("Output: {}", String::from_utf8_lossy(&output.stderr));
	} else {
		eprintln!("Docker Compose failed to start services");
		eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
		anyhow::bail!("Docker Compose command failed");
	}

	Ok(())
}

/// Starts Docker Compose services asynchronously in the background.
///
/// Spawns a background task to run `docker-compose up --build` in the current directory.
/// Returns immediately after starting the task, without waiting for the services to finish starting.
///
/// # Returns
///
/// Returns `Ok(())` if the background task was spawned successfully.
///
/// # Examples
///
/// ```
/// tokio::runtime::Runtime::new().unwrap().block_on(async {
///     start_docker_compose_background().unwrap();
/// });
/// ```
async fn start_docker_compose_background() -> Result<()> {
	// Spawn docker-compose up in background using tokio
	tokio::spawn(async move {
		let output = Command::new("docker-compose")
			.args(["up", "--build"])
			.current_dir(".")
			.output();

		match output {
			Ok(output) => {
				if output.status.success() {
					println!("Docker Compose services started successfully!");
				} else {
					eprintln!("Docker Compose failed to start services");
					eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
				}
			}
			Err(e) => {
				eprintln!("Failed to execute docker-compose command: {}", e);
			}
		}
	});

	println!("Docker Compose started in background");

	Ok(())
}

/// Starts a packet capture session on the Docker bridge network interface.
///
/// Waits for up to 30 seconds for a network device with a name starting with "br-" (the Docker bridge)
/// to appear, then opens a promiscuous capture on that device with a 65,535-byte snap length and a 1-second timeout.
/// Captures all packets by applying an empty filter.
///
/// # Returns
/// A `Capture<Active>` handle for the bridge device if successful.
///
/// # Errors
/// Returns an error if the bridge device is not found within the timeout or if packet capture setup fails.
///
/// # Examples
///
/// ```
/// let capture = tokio::runtime::Runtime::new()
///     .unwrap()
///     .block_on(start_packet_capture())
///     .expect("Failed to start packet capture");
/// assert!(capture.get_selectable_fd().is_some());
/// ```
async fn start_packet_capture() -> Result<Capture<Active>> {
	// Wait for bridge to be created by Docker Compose
	let mut attempts = 0;
	let max_attempts = 30; // Wait up to 30 seconds

	while attempts < max_attempts {
		let devices = Device::list().context("Failed to list network devices")?;

		let bridge_device = devices
			.into_iter()
			.find(|device| device.name.starts_with("br-"));

		if let Some(device) = bridge_device {
			let bridge_name = device.name.clone();
			println!("Found bridge device: {}", bridge_name);

			// Create capture on the bridge device
			let mut capture = Capture::from_device(device)
				.context("Failed to create capture from bridge device")?
				.promisc(true)
				.snaplen(65535)
				.timeout(1000) // 1 second timeout
				.open()
				.context("Failed to open capture on bridge device")?;

			// Set a filter to capture all packets (optional)
			capture
				.filter("", true)
				.context("Failed to set capture filter")?;

			println!("Started packet capture on {}", bridge_name);
			return Ok(capture);
		}

		println!(
			"Bridge not found yet, waiting... (attempt {}/{})",
			attempts + 1,
			max_attempts
		);
		tokio::time::sleep(Duration::from_secs(1)).await;
		attempts += 1;
	}

	anyhow::bail!("Bridge device not found after {} attempts", max_attempts)
}