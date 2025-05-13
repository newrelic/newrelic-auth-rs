pub fn env(var: &str) -> Result<String, std::io::Error> {
    std::env::var(var).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("error loading env var {}: {}", var, e),
        )
    })
}
