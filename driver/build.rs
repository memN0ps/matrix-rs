fn main() -> Result<(), wdk_build::ConfigError> {
    wdk_build::Config::from_env_auto()?.configure_binary_build();
    Ok(())
}
