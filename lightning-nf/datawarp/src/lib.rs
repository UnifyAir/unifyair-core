use thiserror::Error;

pub async fn run(config: config::DataWarpConfig) -> Result <(), DataWarpError> {
    println!("Running with config: {:?}", config);
    Ok(())
}

pub mod config;


#[derive(Error, Debug)]
pub enum DataWarpError {}

