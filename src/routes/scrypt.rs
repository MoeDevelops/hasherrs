use axum::{http::StatusCode, Json};
use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Params, Scrypt,
};

use serde::Deserialize;

#[derive(Deserialize)]
pub struct ScryptParameters {
    password: String,
    salt: Option<String>,
    cost: u8,
    block_size: u32,
    parallelism: u32,
    hash_length: Option<usize>,
}

pub async fn hash(
    Json(parameters): Json<ScryptParameters>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let salt = match parameters.salt {
        Some(salt_parameter) => SaltString::from_b64(&salt_parameter)
            .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string())),
        _ => Ok(SaltString::generate(&mut OsRng)),
    }?;

    let hash_length = match parameters.hash_length {
        Some(length) => length,
        _ => 32,
    };

    let password_hash = Scrypt
        .hash_password_customized(
            parameters.password.as_bytes(),
            None,
            None,
            Params::new(
                parameters.cost,
                parameters.block_size,
                parameters.parallelism,
                hash_length,
            )
            .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?,
            &salt,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((StatusCode::OK, password_hash.to_string()))
}
