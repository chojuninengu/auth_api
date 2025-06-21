use dotenvy::dotenv;
pub struct  Config{
    pub jwt_salt: String,
    pub jwt_secret: String,
    pub jwt_expiration_secs: u32,
}

pub fn load_env() -> Config {
    dotenv().ok();

    let jwt_salt = std::env::var("JWT_SALT").expect("JWT_SALT environment variable is not set");
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET environment variable is not set");
    let jwt_expiration_secs = std::env::var("JWT_EXPIRATION_SECS")
    .expect("JWT_EXPIRATION_SECS environment variable is not set")
    .parse::<u32>()
    .expect("JWT_EXPIRATION_SECS must be a valid unsigned integer");

return Config{
    jwt_salt,
    jwt_secret,
    jwt_expiration_secs,
};
}