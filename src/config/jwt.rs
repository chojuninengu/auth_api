use std::env;
use jsonwebtoken::{EncodingKey, DecodingKey};

// Default key to use if environment variables are not set
// Using a secure randomly generated key
const DEFAULT_JWT_SECRET: &str = "7aecf547f7283d58405abe08d8886b1e1b69737f8eb3482facdadffa5be34d3e00d5e0b04a13daf7ed82346b277e8004b4c69be8ccf2291ac0e24f06e2a07871";

/// Get the JWT encoding key from the environment or use a default for development
pub fn get_encoding_key() -> EncodingKey {
    match env::var("JWT_SECRET") {
        Ok(secret) => EncodingKey::from_secret(secret.as_bytes()),
        Err(_) => {
            // In production, you might want to panic here instead of using a default
            println!("Warning: Using default JWT secret. This is not secure for production!");
            EncodingKey::from_secret(DEFAULT_JWT_SECRET.as_bytes())
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
            DecodingKey::from_secret(DEFAULT_JWT_SECRET.as_bytes())
        }
    }
} 