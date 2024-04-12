use warp::{reject, Filter, Rejection};
use serde::Serialize;
use uuid::Uuid;
use jsonwebtoken::{decode, DecodingKey, Validation};
use crate::config::Config;
use crate::model::TokenClaims;

#[derive(Debug, Serialize, Clone)]
struct ErrorResponse {
    status: String,
    message: String,
}

impl warp::reject::Reject for ErrorResponse {}

pub fn auth_validation(config: Config) -> impl Filter<Extract = (Uuid,), Error = Rejection> + Clone {
    warp::cookie::optional("token").clone()
        .and_then(move |token: Option<String>| {
            let jwt_secret = config.jwt_secret.clone(); // Clone the jwt_secret
            async move {
                match token {
                    Some(token) => {
                        if token.is_empty() {
                            let json_error = ErrorResponse {
                                status: "fail".to_string(),
                                message: "Token is Empty!".to_string(),
                            };
                            let rejection = reject::custom(json_error);
                            return Err(rejection);
                        }

                        println!("{:?}", token);
                        let claims = match decode::<TokenClaims>(
                            &token,
                            &DecodingKey::from_secret(jwt_secret.as_ref()),
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
                    None => {
                        // println!("{}", token);
                        let json_error = ErrorResponse {
                            status: "fail".to_string(),
                            message: "You are not logged in, please provide a token".to_string(),
                        };
                        let rejection = reject::custom(json_error);
                        Err(rejection)
                    }
                }
            }
        })
}