use argon2_kdf::{Algorithm, Hasher};
use axum::{http::StatusCode, Json};
use base64::Engine;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Argon2idParameters {
    algorithm: Option<String>,
    password: String,
    salt: Option<String>,
    parallelism: u32,
    memory: u32,
    iterations: u32,
    hash_length: Option<u32>,
}

pub async fn hash(
    Json(parameters): Json<Argon2idParameters>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let mut argon2: Hasher = Hasher::new()
        .memory_cost_kib(parameters.memory)
        .iterations(parameters.iterations)
        .threads(parameters.parallelism);

    argon2 = match parameters.algorithm.as_deref() {
        Some("i") => Ok(argon2.algorithm(Algorithm::Argon2i)),
        Some("d") => Ok(argon2.algorithm(Algorithm::Argon2d)),
        Some("id") => Ok(argon2.algorithm(Algorithm::Argon2id)),
        None => Ok(argon2.algorithm(Algorithm::Argon2id)),
        _ => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid algorithm".to_string(),
        )),
    }?;

    argon2 = match parameters.hash_length {
        Some(length) => argon2.hash_length(length),
        _ => argon2,
    };

    let salt = match parameters.salt {
        Some(ref salt_parameter) => base64::prelude::BASE64_STANDARD
            .decode(salt_parameter)
            .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?,
        _ => Vec::new(),
    };

    argon2 = match parameters.salt {
        Some(_) => argon2.custom_salt(&salt),
        _ => argon2,
    };

    let password_hash = argon2
        .hash(parameters.password.as_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .to_string();

    return Ok((StatusCode::OK, password_hash));
}
