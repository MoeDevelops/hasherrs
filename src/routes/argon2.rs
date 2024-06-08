use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString},
    Argon2, Params,
};
use axum::{http::StatusCode, Json};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Argon2idParameters {
    algorithm: String,
    password: String,
    salt: Option<String>,
    version: u8,
    parallelism: u32,
    memory: u32,
    iterations: u32,
    hash_length: Option<usize>,
}

pub async fn hash(
    Json(parameters): Json<Argon2idParameters>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let algorithm = match parameters.algorithm.as_ref() {
        "i" => Ok(argon2::Algorithm::Argon2i),
        "d" => Ok(argon2::Algorithm::Argon2d),
        "id" => Ok(argon2::Algorithm::Argon2id),
        _ => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid algorithm".to_string(),
        )),
    }?;

    let version = match parameters.version {
        16 => Ok(argon2::Version::V0x10),
        19 => Ok(argon2::Version::V0x13),
        _ => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid version".to_string(),
        )),
    }?;

    let argon2 = Argon2::new(
        algorithm,
        version,
        Params::new(
            parameters.memory,
            parameters.iterations,
            parameters.parallelism,
            parameters.hash_length,
        )
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?,
    );

    let salt = match parameters.salt {
        Some(salt_parameter) => SaltString::from_b64(&salt_parameter)
            .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string())),
        _ => Ok(SaltString::generate(&mut OsRng)),
    }?;

    let password_hash = argon2
        .hash_password(parameters.password.as_bytes(), &salt)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .to_string();

    let parsed_hash = PasswordHash::new(&password_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    return Ok((StatusCode::OK, parsed_hash.to_string()));
}
