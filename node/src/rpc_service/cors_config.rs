use axum::http::{HeaderName, HeaderValue, Method};
use std::str::FromStr;
use tower_http::cors::{Any, CorsLayer};

/// CORS configuration structure
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// List of allowed origin domains
    pub allowed_origins: Vec<String>,
    /// List of allowed request headers
    pub allowed_headers: Vec<String>,
    /// List of allowed HTTP methods
    pub allowed_methods: Vec<Method>,
    /// Whether to allow credentials
    pub allow_credentials: bool,
    /// Preflight request cache time in seconds
    pub max_age: u64,
    /// Whether to allow private network access
    pub allow_private_network: bool,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec![
                "http://localhost:3000".to_string(),
                "http://localhost:8080".to_string(),
                "https://localhost:3000".to_string(),
                "https://localhost:8080".to_string(),
            ],
            allowed_headers: vec![
                "content-type".to_string(),
                // "authorization".to_string(),
                // "x-requested-with".to_string(),
                "accept".to_string(),
                "origin".to_string(),
                "access-control-request-method".to_string(),
                "access-control-request-headers".to_string(),
            ],
            allowed_methods: vec![
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ],
            allow_credentials: false, // Default to false for security
            max_age: 3600,            // 1 hour - more reasonable for production
            allow_private_network: false,
        }
    }
}

impl CorsConfig {
    /// Create CORS configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Read allowed origins from environment variables
        if let Ok(origins) = std::env::var("CORS_ALLOWED_ORIGINS") {
            config.allowed_origins = origins
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Read allowed headers from environment variables
        if let Ok(headers) = std::env::var("CORS_ALLOWED_HEADERS") {
            config.allowed_headers = headers
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Read credentials allowance from environment variables
        if let Ok(allow_creds) = std::env::var("CORS_ALLOW_CREDENTIALS") {
            config.allow_credentials = allow_creds.parse().unwrap_or(false); // Default to false for security
        }

        // Read preflight request cache time from environment variables
        if let Ok(max_age) = std::env::var("CORS_MAX_AGE") {
            config.max_age = max_age.parse().unwrap_or_else(|_| Self::get_recommended_max_age());
        } else {
            config.max_age = Self::get_recommended_max_age();
        }

        // Read private network allowance from environment variables
        if let Ok(allow_private) = std::env::var("CORS_ALLOW_PRIVATE_NETWORK") {
            config.allow_private_network = allow_private.parse().unwrap_or(false);
        }

        config
    }

    /// Get recommended max_age based on environment
    fn get_recommended_max_age() -> u64 {
        // Check if we're in development mode
        if std::env::var("RUST_LOG").unwrap_or_default().contains("debug")
            || std::env::var("ENVIRONMENT").unwrap_or_default() == "development"
        {
            300 // 5 minutes for development
        } else if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
            3600 // 1 hour for production
        } else {
            1800 // 30 minutes for testing/staging
        }
    }

    /// Create CORS layer
    pub fn create_cors_layer(&self) -> CorsLayer {
        let mut cors_layer = CorsLayer::new();

        // Set allowed origins
        if self.allowed_origins.is_empty() {
            cors_layer = cors_layer.allow_origin(Any);
        } else {
            let origins: Result<Vec<_>, _> =
                self.allowed_origins.iter().map(|origin| HeaderValue::from_str(origin)).collect();

            match origins {
                Ok(header_values) => {
                    cors_layer = cors_layer.allow_origin(header_values);
                }
                Err(_) => {
                    tracing::warn!("Invalid CORS origins, falling back to Any");
                    cors_layer = cors_layer.allow_origin(Any);
                }
            }
        }

        // Set allowed headers
        if self.allowed_headers.is_empty() {
            cors_layer = cors_layer.allow_headers(Any);
        } else {
            let headers: Result<Vec<_>, _> =
                self.allowed_headers.iter().map(|header| HeaderName::from_str(header)).collect();

            match headers {
                Ok(header_names) => {
                    cors_layer = cors_layer.allow_headers(header_names);
                }
                Err(_) => {
                    tracing::warn!("Invalid CORS headers, falling back to Any");
                    cors_layer = cors_layer.allow_headers(Any);
                }
            }
        }

        // Set allowed HTTP methods;
        // Set credentials allowance;
        // Set preflight request cache time;
        // Set private network allowance
        cors_layer = cors_layer
            .allow_methods(self.allowed_methods.clone())
            .allow_credentials(self.allow_credentials)
            .max_age(std::time::Duration::from_secs(self.max_age))
            .allow_private_network(self.allow_private_network);
        cors_layer
    }

    /// Validate configuration security
    pub fn validate_security(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        // Check if all origins are allowed
        if self.allowed_origins.is_empty() {
            warnings.push("CORS allows all origins, security risk".to_string());
        }

        // Check for insecure origins
        for origin in &self.allowed_origins {
            if origin == "*" {
                warnings.push("CORS contains wildcard origin, security risk".to_string());
            }
            if origin.starts_with("http://") && !origin.contains("localhost") {
                warnings.push(format!("CORS contains insecure HTTP origin: {origin}"));
            }
        }

        // Check if all headers are allowed
        if self.allowed_headers.is_empty() {
            warnings.push("CORS allows all headers, security risk".to_string());
        }

        // Check for sensitive headers
        let sensitive_headers = ["authorization", "cookie", "x-api-key"];
        for header in &self.allowed_headers {
            if sensitive_headers.contains(&header.as_str()) {
                warnings.push(format!("CORS allows sensitive header: {header}"));
            }
        }

        // Check credentials setting
        if self.allow_credentials {
            // Check for wildcard origin with credentials
            if self.allowed_origins.contains(&"*".to_string()) {
                warnings.push(
                    "CORS allows credentials with wildcard origin, security risk".to_string(),
                );
            }

            // Check for empty origins (falls back to wildcard)
            if self.allowed_origins.is_empty() {
                warnings.push(
                    "CORS allows credentials with empty origins list, will fallback to wildcard"
                        .to_string(),
                );
            }

            // Check for HTTP origins with credentials
            for origin in &self.allowed_origins {
                if origin.starts_with("http://") && !origin.contains("localhost") {
                    warnings.push(format!(
                        "CORS allows credentials with insecure HTTP origin: {origin}"
                    ));
                }
            }

            // Check for overly permissive origins
            for origin in &self.allowed_origins {
                if origin.contains("*") && !origin.starts_with("https://") {
                    warnings.push(format!(
                        "CORS allows credentials with potentially unsafe origin pattern: {origin}"
                    ));
                }
            }
        }

        // Check max_age setting
        if self.max_age > 86400 {
            // More than 24 hours
            warnings.push(format!(
                "CORS max_age is too long ({} seconds), consider reducing for better security",
                self.max_age
            ));
        } else if self.max_age > 3600 {
            // More than 1 hour
            warnings.push(format!(
                "CORS max_age is quite long ({} seconds), ensure this is intentional",
                self.max_age
            ));
        }

        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_cors_config() {
        let config = CorsConfig::default();
        assert!(!config.allowed_origins.is_empty());
        assert!(!config.allowed_headers.is_empty());
        assert!(!config.allowed_methods.is_empty());
        assert!(!config.allow_credentials); // Default to false for security
        assert_eq!(config.max_age, 3600); // 1 hour default
    }

    #[test]
    fn test_cors_config_validation() {
        let config = CorsConfig {
            allowed_origins: vec!["*".to_string()],
            allow_credentials: true,
            ..Default::default()
        };

        let warnings = config.validate_security();
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("wildcard origin")));
        assert!(warnings.iter().any(|w| w.contains("credentials with wildcard origin")));
    }

    #[test]
    fn test_secure_cors_config() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            allowed_headers: vec!["content-type".to_string(), "accept".to_string()],
            allowed_methods: vec![Method::GET, Method::POST],
            allow_credentials: false,
            max_age: 3600,
            allow_private_network: false,
        };

        let warnings = config.validate_security();
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_max_age_warnings() {
        // Test very long max_age
        let mut config = CorsConfig {
            max_age: 172800, // 48 hours
            ..Default::default()
        };
        let warnings = config.validate_security();
        assert!(warnings.iter().any(|w| w.contains("too long")));

        // Test moderately long max_age
        config.max_age = 7200; // 2 hours
        let warnings = config.validate_security();
        assert!(warnings.iter().any(|w| w.contains("quite long")));

        // Test reasonable max_age
        config.max_age = 1800; // 30 minutes
        let warnings = config.validate_security();
        assert!(!warnings.iter().any(|w| w.contains("long")));
    }

    #[test]
    fn test_credentials_security() {
        // Test credentials with wildcard origin (should warn)
        let mut config = CorsConfig {
            allow_credentials: true,
            allowed_origins: vec!["*".to_string()],
            ..Default::default()
        };
        let warnings = config.validate_security();
        assert!(warnings.iter().any(|w| w.contains("credentials with wildcard origin")));

        // Test credentials with specific origins (should be safe)
        config.allow_credentials = true;
        config.allowed_origins = vec!["https://example.com".to_string()];
        let warnings = config.validate_security();
        assert!(!warnings.iter().any(|w| w.contains("credentials with wildcard origin")));

        // Test no credentials (should be safe)
        config.allow_credentials = false;
        config.allowed_origins = vec!["*".to_string()];
        let warnings = config.validate_security();
        assert!(!warnings.iter().any(|w| w.contains("credentials with wildcard origin")));
    }
}
