use dotenvy::dotenv;

pub struct Config {
    pub jwt_salt: String,
    pub jwt_secret: String,
    pub jwt_expiration: String,
}

pub fn load_env() -> Config {
    dotenv().ok();

    let JWT_SALT = std::env::var("JWT_SALT")
        .unwrap_or_else(|_| {
            println!("JWT_SALT must be set in .env file");
            std::process::exit(1);
        });
    let JWT_SECRET = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| {
            println!("JWT_SECRET must be set in .env file");
            std::process::exit(1);
        });
    let JWT_EXPIRATION = std::env::var("JWT_EXPIRATION")
        .unwrap_or_else(|_| {
            println!("JWT_EXPIRATION must be set in .env file");
            std::process::exit(1);
        });

    return Config {
        jwt_salt: JWT_SALT,
        jwt_secret: JWT_SECRET,
        jwt_expiration: JWT_EXPIRATION,
    };
}