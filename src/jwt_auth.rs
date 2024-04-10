use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::Serialize;
use uuid::Uuid;
use warp::{reject, Rejection, Reply};

use crate::config::Config;
use crate::model::TokenClaims;

#[derive(Debug, Serialize, Clone)]
struct ErrorResponse {
    status: String,
    message: String,
}



impl warp::reject::Reject for ErrorResponse {}

pub fn jwt_middleware(
    config: Config,
    token: Option<String>,
) -> Result<Uuid, Rejection> {

    if token.is_none() {
        let json_error = ErrorResponse {
            status: "fail".to_string(),
            message: "You are not logged in, please provide a token".to_string(),
        };
        return Err(warp::reject::custom(json_error));
    }

    let claims = match decode::<TokenClaims>(
        &token.unwrap(),
        &DecodingKey::from_secret(config.jwt_secret.as_ref()),
        &Validation::default(),
    ) {
        Ok(c) => c.claims,
        Err(_) => {
            let json_error = ErrorResponse {
                status: "fail".to_string(),
                message: "Invalid token".to_string(),
            };
            return Err(warp::reject::custom(json_error));
        }
    };

    let user_id = match Uuid::parse_str(claims.sub.as_str()) {
        Ok(id) => id,
        Err(_) => {
            let json_error = ErrorResponse {
                status: "fail".to_string(),
                message: "Invalid token".to_string(),
            };
            return Err(warp::reject::custom(json_error));
        }
    };

    Ok(user_id)
}
