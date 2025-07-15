use std::{fs::File, io, io::Read};

use nf_base::{LoggingConfig, NfConfig, NfInstance, RuntimeConfig, RuntimeType};
use omnipath::OmniPathApp;
use thiserror::Error;
use tokio::runtime::{Builder, Runtime};
use tokio_util::sync::CancellationToken;
use tracing::{info, trace};
use tracing_error::ErrorLayer;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

pub const DATAWARP_STR: &'static str = "datawarp";
pub const INFINISYNC_STR: &'static str = "infinisync";
pub const OMNIPATH_STR: &'static str = "omnipath";

pub struct App;

impl App {
	pub fn start_app(
		app_name: &str,
		config_path: &str,
	) -> color_eyre::Result<()> {
		match app_name {
			OMNIPATH_STR => Self::run::<OmniPathApp>(config_path),
			_ => unreachable!(),
		}
	}

	fn run<T: NfInstance>(config_path: &str) -> color_eyre::Result<()> {
		install_tracing();
		let nf_app: NfApp<T> = NfApp::new(config_path)?;
		let runtime_config = nf_app.config.get_runtime_config();
		let logging_config = nf_app.config.get_log_config();
		setup_logging(logging_config)?;
		trace!("config: {:#?}", nf_app.config);
		let rt = setup_runtime(runtime_config)?;
		rt.block_on(nf_app.run())?;
		Ok(())
	}
}

#[derive(Error, Debug)]
pub enum AppSetupError {
	#[error(transparent)]
	ConfigError(#[from] AppConfigError),

	#[error("Tokio Runtime Build Error: {0}")]
	RuntimeBuildError(#[from] io::Error),

	#[error("Color Eyre Installation Error: {0}")]
	LoggingError(#[from] color_eyre::Report),
}

#[derive(Error, Debug)]
pub enum AppConfigError {
	#[error("Error reading App Config: {0}")]
	IoError(#[from] io::Error),
	#[error("Error parsing Config yaml: {0}")]
	YamlParsingError(#[from] serde_yaml::Error),
}

pub struct NfApp<T: NfInstance> {
	pub(crate) cancellation_token: CancellationToken,
	pub(crate) config: T::Config,
}

#[derive(Error, Debug)]
pub enum NfError<T> {
	#[error("NF Initialization Error: {0}")]
	InitializationFailedError(
		#[backtrace]
		#[source]
		T,
	),
	#[error("RuntimeError: Running NF Error")]
	RuntimeError(
		#[backtrace]
		#[source]
		T,
	),
	#[error("ShutdownDeregistrationFailedError: Deregistration NF Error")]
	ShutdownDeregistrationFailedError(
		#[backtrace]
		#[source]
		T,
	),
	#[error(
		"RuntimeWithDeregistrationError: Runtime error and unable to deregister : \nMain App \
		 Error - {0} \nDeregisteration Error {1}"
	)]
	RuntimeWithDeregistrationError(
		#[backtrace]
		#[source]
		T,
		T,
	),
}

impl<T: NfInstance> NfApp<T> {
	pub fn new(config_path: &str) -> Result<Self, AppSetupError> {
		let mut file = File::open(config_path).expect("Failed to open config file");
		let mut contents = String::new();
		trace!("Going to parse config");
		file.read_to_string(&mut contents)
			.map_err(AppConfigError::from)?;
		let config = serde_yaml::from_str(&contents).map_err(AppConfigError::from)?;

		let cancellation_token = CancellationToken::new();
		Ok(NfApp {
			cancellation_token,
			config,
		})
	}

	pub async fn run(self) -> Result<(), NfError<T::Error>> {
		let shutdown_token = self.cancellation_token.clone();
		let handle = tokio::spawn(async move {
			use tokio::signal::unix::{SignalKind, signal};

			// Infos here:
			// https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html
			let mut signal_terminate = signal(SignalKind::terminate()).unwrap();
			let mut signal_interrupt = signal(SignalKind::interrupt()).unwrap();

			tokio::select! {
				_ = signal_terminate.recv() => tracing::debug!("Received SIGTERM."),
				_ = signal_interrupt.recv() => tracing::debug!("Received SIGINT."),
			};
			shutdown_token.cancel();
		});
		info!("Starting App Initialization");
		let nf_app = T::initialize(self.config, self.cancellation_token)
			.map_err(NfError::InitializationFailedError)?;
		info!("App Initialized Successfully");
		tokio::select! {
			 _ = handle => {
				nf_app.deregister_nf().await.map_err(NfError::ShutdownDeregistrationFailedError)
			 },
			 res = async {
				nf_app.register_nf().await?;
				info!("Nf Registered Successfully");
				nf_app.start().await?;
				info!("Nf Execution Completed");
				Ok(())
			 } => {
				let dreg_res = nf_app.deregister_nf().await;
				if res.is_ok() && dreg_res.is_err() {
					dreg_res.map_err(NfError::ShutdownDeregistrationFailedError)
				} else if dreg_res.is_ok() && res.is_err() {
					res.map_err(NfError::RuntimeError)
				} else if let Err(dreg_err) = dreg_res {
					res.map_err(|e| NfError::RuntimeWithDeregistrationError(e, dreg_err))
				} else {
					info!("Nf Deregistered Successfully");
					Ok(())
				}
			},
		}
	}
}

fn setup_logging(_config: &LoggingConfig) -> Result<(), AppSetupError> {
	Ok(())
}

fn setup_runtime(config: &RuntimeConfig) -> Result<Runtime, AppSetupError> {
	trace!("Starting Tokio Runtime: {:?}", config.rt_type);
	let rt = match config.rt_type {
		RuntimeType::Multi => Builder::new_multi_thread().enable_all().build()?,
		RuntimeType::Single => Builder::new_current_thread().enable_all().build()?,
	};
	Ok(rt)
}

fn install_tracing() {
	let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);
	let filter_layer = EnvFilter::try_from_default_env()
		.or_else(|_| EnvFilter::try_new("info"))
		.unwrap();

	tracing_subscriber::registry()
		.with(filter_layer)
		.with(fmt_layer)
		.with(ErrorLayer::default())
		.init();
}
