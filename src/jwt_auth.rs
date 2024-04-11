// use jsonwebtoken::{decode, DecodingKey, Validation};
// use serde::Serialize;
// use uuid::Uuid;
// use warp::{reject, Rejection, Reply};

// use crate::config::Config;
// use crate::model::TokenClaims;

// #[derive(Debug, Serialize, Clone)]
// struct ErrorResponse {
//     status: String,
//     message: String,
// }

// impl warp::reject::Reject for ErrorResponse {}

// pub fn jwt_middleware(
//     config: Config,
// ) -> Result<Uuid, Rejection> {
//     let token:Option<String> = Some("wrr,v-djnvjvndj=dvdfvfb".to_string());
//     if token.is_none() {
//         let json_error = ErrorResponse {
//             status: "fail".to_string(),
//             message: "You are not logged in, please provide a token".to_string(),
//         };
//         return Err(warp::reject::custom(json_error));
//     }

//     let claims = match decode::<TokenClaims>(
//         &token.unwrap(),
//         &DecodingKey::from_secret(config.jwt_secret.as_ref()),
//         &Validation::default(),
//     ) {
//         Ok(c) => c.claims,
//         Err(_) => {
//             let json_error = ErrorResponse {
//                 status: "fail".to_string(),
//                 message: "Invalid token".to_string(),
//             };
//             return Err(warp::reject::custom(json_error));
//         }
//     };

//     let user_id = match Uuid::parse_str(claims.sub.as_str()) {
//         Ok(id) => id,
//         Err(_) => {
//             let json_error = ErrorResponse {
//                 status: "fail".to_string(),
//                 message: "Invalid token".to_string(),
//             };
//             return Err(warp::reject::custom(json_error));
//         }
//     };

//     Ok(user_id)
// }

// use jsonwebtoken::{decode, DecodingKey, Validation};
// use serde::Serialize;
// use uuid::Uuid;
// use warp::{reject, Filter, Rejection, Reply};

// use crate::config::Config;
// use crate::model::TokenClaims;

// #[derive(Debug, Serialize, Clone)]
// struct ErrorResponse {
//     status: String,
//     message: String,
// }

// impl warp::reject::Reject for ErrorResponse {}

// pub fn jwt_middleware(
//     config: Config,
// ) -> impl warp::Filter<Extract = (Uuid,), Error = Rejection> + Clone {
//     warp::any()
//         .map(move || {
//             let token: Option<String> = Some("hfjyggtgufrirytfrgkuytkyufgkuytkt".to_string()); // Replace with your actual token extraction logic
//             if let Some(token_str) = token {
//                 match decode::<TokenClaims>(
//                     &token_str,
//                     &DecodingKey::from_secret(config.jwt_secret.as_ref()),
//                     &Validation::default(),
//                 ) {
//                     Ok(claims) => {
//                         if let Ok(user_id) = Uuid::parse_str(&claims.claims.sub) {
//                             // Convert Uuid to Result<_, Rejection>
//                             return Ok(user_id);
//                         } else {
//                             let json_error = ErrorResponse {
//                                 status: "fail".to_string(),
//                                 message: "Invalid token".to_string(),
//                             };
//                             // Return a custom rejection with ErrorResponse
//                             let rejection = warp::reject::custom(json_error);
//                             return Err(rejection);
//                         }
//                     }
//                     Err(_) => {
//                         let json_error = ErrorResponse {
//                             status: "fail".to_string(),
//                             message: "Invalid token".to_string(),
//                         };
//                         // Return a custom rejection with ErrorResponse
//                         let rejection = warp::reject::custom(json_error);
//                         return Err(rejection);
//                     }
//                 }
//             } else {
//                 let json_error = ErrorResponse {
//                     status: "fail".to_string(),
//                     message: "You are not logged in, please provide a token".to_string(),
//                 };
//                 // Return a custom rejection with ErrorResponse
//                 let rejection = warp::reject::custom(json_error);
//                 return Err(rejection);
//             }
//         })
//         .and_then(move |result: Result<Uuid, Rejection>| async move {
//             match result {
//                 Ok(user_id) => {
//                     // Your middleware logic here, for example checking permissions
//                     // This is just an example, replace with your actual logic
//                     if user_id.is_nil() {
//                         // If user_id is nil, reject the request with custom ErrorResponse
//                         let json_error = ErrorResponse {
//                             status: "fail".to_string(),
//                             message: "Unauthorized".to_string(),
//                         };
//                         let rejection = warp::reject::custom(json_error);
//                         return Err(rejection);
//                     }

//                     // Otherwise, proceed with the request
//                     Ok(user_id)
//                 }
//                 Err(rejection) => Err(rejection),
//             }
//         })
// }







//3 Attempt

// use jsonwebtoken::{decode, DecodingKey, Validation};
// use serde::Serialize;
// use uuid::Uuid;
// use warp::{reject, Filter, Rejection, Reply};

// use crate::config::Config;
// use crate::model::TokenClaims;

// #[derive(Debug, Serialize, Clone)]
// struct ErrorResponse {
//     status: String,
//     message: String,
// }

// impl warp::reject::Reject for ErrorResponse {}

// pub fn jwt_middleware(
//     config: Config,
// ) -> impl warp::Filter<Extract = (Uuid,), Error = Rejection> + Clone {
//     warp::any()
//         .map(move || {
//             // let token: Option<String> = Some("hfjyggtgufrirytfrgkuytkyufgkuytkt".to_string()); // Replace with your actual token extraction logic
//             let token = auth_validation();
//             if  token {
//                 match decode::<TokenClaims>(
//                     &token_str,
//                     &DecodingKey::from_secret(config.jwt_secret.as_ref()),
//                     &Validation::default(),
//                 ) {
//                     Ok(claims) => {
//                         if let Ok(user_id) = Uuid::parse_str(&claims.claims.sub) {
//                             // Convert Uuid to Result<_, Rejection>
//                             return Ok(user_id);
//                         } else {
//                             let json_error = ErrorResponse {
//                                 status: "fail".to_string(),
//                                 message: "Invalid token".to_string(),
//                             };
//                             // Return a custom rejection with ErrorResponse
//                             let rejection = warp::reject::custom(json_error);
//                             return Err(rejection);
//                         }
//                     }
//                     Err(_) => {
//                         let json_error = ErrorResponse {
//                             status: "fail".to_string(),
//                             message: "Invalid token".to_string(),
//                         };
//                         // Return a custom rejection with ErrorResponse
//                         let rejection = warp::reject::custom(json_error);
//                         return Err(rejection);
//                     }
//                 }
//             } else {
//                 let json_error = ErrorResponse {
//                     status: "fail".to_string(),
//                     message: "You are not logged in, please provide a token".to_string(),
//                 };
//                 // Return a custom rejection with ErrorResponse
//                 let rejection = warp::reject::custom(json_error);
//                 return Err(rejection);
//             }
//         })
//         .and_then(move |result: Result<Uuid, Rejection>| async move {
//             match result {
//                 Ok(user_id) => {
//                     // Your middleware logic here, for example checking permissions
//                     // This is just an example, replace with your actual logic
//                     if user_id.is_nil() {
//                         // If user_id is nil, reject the request with custom ErrorResponse
//                         let json_error = ErrorResponse {
//                             status: "fail".to_string(),
//                             message: "Unauthorized".to_string(),
//                         };
//                         let rejection = warp::reject::custom(json_error);
//                         return Err(rejection);
//                     }

//                     // Otherwise, proceed with the request
//                     Ok(user_id)
//                 }
//                 Err(rejection) => Err(rejection),
//             }
//         })
// }





// pub fn auth_validation() -> impl Filter<Extract = (String,), Error = Rejection> + Copy {
//     warp::cookie::<String>("token").and_then(|token: String| async move {
//         println!("token: {}", token);
//         if token.is_empty() {
//             let json_error = ErrorResponse {
//                 status: "fail".to_string(),
//                 message: "You are not logged in, please provide a token".to_string(),
//             };
//             // Return a custom rejection with ErrorResponse
//             let rejection = warp::reject::custom(json_error);
//             return Err(rejection);
//         } else {
//             return  Ok(token);
//         }
//     })
// }





///4 th Attempt
// use jsonwebtoken::{decode, DecodingKey, Validation};
// use serde::Serialize;
// use uuid::Uuid;
// use warp::{reject, Filter, Rejection};

// use crate::config::Config;
// use crate::model::TokenClaims;

// #[derive(Debug, Serialize, Clone)]
// struct ErrorResponse {
//     status: String,
//     message: String,
// }

// impl warp::reject::Reject for ErrorResponse {}


// pub fn auth_validation(config: Config,) -> impl Filter<Extract = (Uuid,), Error = Rejection> + Clone {
//     warp::cookie::<String>("token")
//         .and_then(|token: String| async move {
//             if token.is_empty() {
//                 let json_error = ErrorResponse {
//                     status: "fail".to_string(),
//                     message: "You are not logged in, please provide a token".to_string(),
//                 };
//                 let rejection = reject::custom(json_error);
//                 Err(rejection)
//             } else {
//                 let claims = match decode::<TokenClaims>(
//                     &token,
//                     &DecodingKey::from_secret(config.jwt_secret.as_ref()),
//                     &Validation::default(),
//                 ) {
//                     Ok(c) => c.claims,
//                     Err(_) => {
//                         let json_error = ErrorResponse {
//                             status: "fail".to_string(),
//                             message: "Invalid token".to_string(),
//                         };
//                         return Err(warp::reject::custom(json_error));
//                     }
//                 };

//                 let user_id = match Uuid::parse_str(claims.sub.as_str()) {
//                     Ok(id) => id,
//                     Err(_) => {
//                         let json_error = ErrorResponse {
//                             status: "fail".to_string(),
//                             message: "Invalid token".to_string(),
//                         };
//                         return Err(warp::reject::custom(json_error));
//                     }
//                 };

//                 Ok(user_id)
//             }
//         })
// }




//ATTEMPT 5
// use jsonwebtoken::{decode, DecodingKey, Validation};
// use serde::Serialize;
// use uuid::Uuid;
// use warp::{reject, Filter, Rejection};

// use crate::config::Config;
// use crate::model::TokenClaims;

// #[derive(Debug, Serialize, Clone)]
// struct ErrorResponse {
//     status: String,
//     message: String,
// }

// impl warp::reject::Reject for ErrorResponse {}

// pub fn auth_validation(config: Config) -> impl Filter<Extract = (Uuid,), Error = Rejection> + Clone {
//     warp::cookie::<String>("token")
//         .and_then(move |token: String| {
//             let jwt_secret = config.jwt_secret.clone(); // Clone the jwt_secret
//             async move {
//                 if token.is_empty() {
//                     let json_error = ErrorResponse {
//                         status: "fail".to_string(),
//                         message: "You are not logged in, please provide a token".to_string(),
//                     };
//                     let rejection = reject::custom(json_error);
//                     Err(rejection)
//                 } else {
//                     println!("{:?}", token);
//                     let claims = match decode::<TokenClaims>(
//                         &token,
//                         &DecodingKey::from_secret(jwt_secret.as_ref()),
//                         &Validation::default(),
//                     ) {
//                         Ok(c) => c.claims,
//                         Err(_) => {
//                             let json_error = ErrorResponse {
//                                 status: "fail".to_string(),
//                                 message: "Invalid token".to_string(),
//                             };
//                             return Err(warp::reject::custom(json_error));
//                         }
//                     };

//                     let user_id = match Uuid::parse_str(claims.sub.as_str()) {
//                         Ok(id) => id,
//                         Err(_) => {
//                             let json_error = ErrorResponse {
//                                 status: "fail".to_string(),
//                                 message: "Invalid token".to_string(),
//                             };
//                             return Err(warp::reject::custom(json_error));
//                         }
//                     };

//                     Ok(user_id)
//                 }
//             }
//         })
// }


//ATTTEMT 6

// use cookie::Cookie;
// use jsonwebtoken::{decode, DecodingKey, Validation};
// use serde::Serialize;
// use uuid::Uuid;
// use warp::{reject, Filter, Rejection, Reply};

// use crate::config::Config;
// use crate::model::TokenClaims;

// #[derive(Debug, Serialize, Clone)]
// struct ErrorResponse {
//     status: String,
//     message: String,
// }

// impl warp::reject::Reject for ErrorResponse {}

// pub fn jwt_middleware(
//     config: Config,
// ) -> impl warp::Filter<Extract = (Uuid,), Error = Rejection> + Clone {
//     warp::any()
//         .map(move || {
//             let token: Option<String> = Some("hfjyggtgufrirytfrgkuytkyufgkuytkt".to_string()); // Replace with your actual token extraction logic
//             // let token = auth_validation();
//             if  token.is_none() {
//                 match decode::<TokenClaims>(
//                     &token,
//                     &DecodingKey::from_secret(config.jwt_secret.as_ref()),
//                     &Validation::default(),
//                 ) {
//                     Ok(claims) => {
//                         if let Ok(user_id) = Uuid::parse_str(&claims.claims.sub) {
//                             // Convert Uuid to Result<_, Rejection>
//                             return Ok(user_id);
//                         } else {
//                             let json_error = ErrorResponse {
//                                 status: "fail".to_string(),
//                                 message: "Invalid token".to_string(),
//                             };
//                             // Return a custom rejection with ErrorResponse
//                             let rejection = warp::reject::custom(json_error);
//                             return Err(rejection);
//                         }
//                     }
//                     Err(_) => {
//                         let json_error = ErrorResponse {
//                             status: "fail".to_string(),
//                             message: "Invalid token".to_string(),
//                         };
//                         // Return a custom rejection with ErrorResponse
//                         let rejection = warp::reject::custom(json_error);
//                         return Err(rejection);
//                     }
//                 }
//             } else {
//                 let json_error = ErrorResponse {
//                     status: "fail".to_string(),
//                     message: "You are not logged in, please provide a token".to_string(),
//                 };
//                 // Return a custom rejection with ErrorResponse
//                 let rejection = warp::reject::custom(json_error);
//                 return Err(rejection);
//             }
//         })
//         .and_then(move |result: Result<Uuid, Rejection>| async move {
//             match result {
//                 Ok(user_id) => {
//                     // Your middleware logic here, for example checking permissions
//                     // This is just an example, replace with your actual logic
//                     if user_id.is_nil() {
//                         // If user_id is nil, reject the request with custom ErrorResponse
//                         let json_error = ErrorResponse {
//                             status: "fail".to_string(),
//                             message: "Unauthorized".to_string(),
//                         };
//                         let rejection = warp::reject::custom(json_error);
//                         return Err(rejection);
//                     }

//                     // Otherwise, proceed with the request
//                     Ok(user_id)
//                 }
//                 Err(rejection) => Err(rejection),
//             }
//         })
// }



// ATTEMPT 7

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
