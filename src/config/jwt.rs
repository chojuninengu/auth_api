use std::env;
use jsonwebtoken::{EncodingKey, DecodingKey};

// Default key to use if environment variables are not set
const DEFAULT_JWT_SECRET: &[u8] = b"default_secret_key_please_change_in_production";

/// Get the JWT encoding key from the environment or use a default for development
pub fn get_encoding_key() -> EncodingKey {
    match env::var("JWT_SECRET") {
        Ok(secret) => EncodingKey::from_secret(secret.as_bytes()),
        Err(_) => {
            // In production, you might want to panic here instead of using a default
            println!("Warning: Using default JWT secret. This is not secure for production!");
            EncodingKey::from_secret(DEFAULT_JWT_SECRET)
        }
    }
}

/// Get the JWT decoding key from the environment or use a default for development
pub fn get_decoding_key() -> DecodingKey {
    match env::var("JWT_SECRET") {
        Ok(secret) => DecodingKey::from_secret(secret.as_bytes()),
        Err(_) => {
            // In production, you might want to panic here instead of using a default
            println!("Warning: Using default JWT secret. This is not secure for production!");
            DecodingKey::from_secret(DEFAULT_JWT_SECRET)
        }
    }
} 