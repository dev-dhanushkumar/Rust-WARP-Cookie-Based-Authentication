use crate::{
    config::Config,
    jwt_auth,
    model::{LoginUserSchema, RegisterUserSchema, TokenClaims, User},
    response::FilteredUser,
};
// use cookie::Cookie;
// use time::Duration as Dur;

#[derive(Debug, Serialize, Clone)]
struct ErrorResponse {
    status: String,
    message: String,
}

impl warp::reject::Reject for ErrorResponse {}

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use cookie::time::Duration as Cdur;
use cookie::Cookie;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::Serialize;
use serde_json::json;
use sqlx::{Pool, Postgres, Row};
use uuid::Uuid;
use warp::{
     filters::header, http::HeaderMap, reply::{self, Response}, Filter, Rejection, Reply
};
use warp::http::header::{HeaderValue, SET_COOKIE, CONTENT_TYPE};
//use warp::{reply, http::header::SET_COOKIE, HeaderValue};

fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id.to_string(),
        email: user.email.to_string(),
        name: user.name.to_string(),
        photo: user.photo.to_string(),
        role: user.role.to_string(),
        verified: user.verified,
        createdAt: user.created_at.unwrap(),
        updatedAt: user.updated_at.unwrap(),
    }
}


async fn register_user_handler(
    body: RegisterUserSchema,
    pool: Pool<Postgres>,
) -> Result<impl Reply, Rejection> {
    let exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(body.email.to_owned())
        .fetch_one(&pool)
        .await
        .unwrap()
        .get(0);

    if exists {
        return Ok(warp::reply::json(&json!({
            "status": "fail",
            "message": "User with that email already exists"
        })));
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .expect("error while hashing password")
        .to_string();

    let query_result = sqlx::query_as!(
        User,
        "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
        body.name.to_string(),
        body.email.to_string().to_lowercase(),
        hashed_password
    )
    .fetch_one(&pool)
    .await;

    match query_result {
        Ok(user) => Ok(warp::reply::json(&json!({
            "status": "success",
            "data": json!({
                "user": filter_user_record(&user)
            })
        }))),
        Err(e) => Ok(warp::reply::json(&json!({
            "status": "error",
            "message": format!("{:?}", e)
        }))),
    }
}

async fn login_user_handler(
    body: LoginUserSchema,
    config: Config,
    pool: Pool<Postgres>,
) -> Result<warp::reply::WithHeader<warp::reply::Json>, Rejection> {
    let query_result = sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", body.email)
        .fetch_optional(&pool)
        .await
        .unwrap();

    let is_valid = query_result.to_owned().map_or(false, |user| {
        let parsed_hash = PasswordHash::new(&user.password).unwrap();
        Argon2::default()
            .verify_password(body.password.as_bytes(), &parsed_hash)
            .map_or(false, |_| true)
    });

    if !is_valid {
        let json_response = reply::json(&json!({
            "status": "fail",
            "message": "Invalid email or password."
        }));

        let response_with_fail = warp::reply::with_header(
            json_response,
            CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        return Ok(response_with_fail);
    }

    let user = query_result.unwrap();

    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + Duration::minutes(60)).timestamp() as usize;
    let claims: TokenClaims = TokenClaims {
        sub: user.id.to_string(),
        exp,
        iat,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_ref()),
    )
    .unwrap();

    let cookie_value = format!("token={}; Path=/; Max-Age={}; HttpOnly", token, 3600);

    let json_response = reply::json(&json!({
        "status": "success"
    }));

    let response_with_cookie = warp::reply::with_header(
        json_response,
        SET_COOKIE,
        HeaderValue::from_str(&cookie_value).unwrap(),
    );
    return Ok(response_with_cookie);
}

// async fn logout_handler() -> Result<warp::reply::WithHeader<warp::reply::WithHeader<warp::reply::Json>>, Rejection> {
//     // let cookie_value = "token=; Path=/; Max-Age=0; HttpOnly";
//     let foo_cookie_filter = warp::cookie::<String>("token");
//     let jwt = warp::test::request().filter(&foo_cookie_filter).await.unwrap();
//     println!("JWT token : {:?}", jwt);

//     let cookie = "token=; Path=/; Max-Age=-1; HttpOnly";

//     let json_response = warp::reply::json(&json!({
//         "status": "success"
//     }));

//     let response_with_cookie = warp::reply::with_header(
//         json_response,
//         SET_COOKIE,
//         HeaderValue::from_str(&cookie.to_string()).unwrap(),
//     );

//     let response_with_json_content_type = warp::reply::with_header(
//         response_with_cookie,
//         CONTENT_TYPE,
//         HeaderValue::from_static("application/json"),
//     );

//     Ok(response_with_json_content_type)
// }

//ATTEMP 3
async fn logout_handler(id:Uuid) -> Result<impl Reply, warp::Rejection> {
    println!("User id: {}", id);
    let cookie_str = format!("token=; Max-Age=-1; httponly; path=/");
    let json_response = reply::json(&json!({
        "status": "success"
    }));

    let response_with_cookie = warp::reply::with_header(
        json_response,
        SET_COOKIE,
        HeaderValue::from_str(&cookie_str).unwrap(),
    );
    return Ok(response_with_cookie);
}
    

    // match token {
    //     Some(token) => {
    //         println!("{:?}", token);
    //         let cookie_str = format!("token=; Max-Age=-1; httponly; path=/");
    //         response.headers_mut().insert(
    //             "Set-Cookie",
    //             warp::http::HeaderValue::from_str(&cookie_str).unwrap(),
    //         );
    //         Ok(response)
    //     }
    //     None => {
    //         let json_error = ErrorResponse {
    //             status: "fail".to_string(),
    //             message: "You are not logged in, please provide a token".to_string(),
    //         };
    //         let rejection = warp::reject::custom(json_error);
    //         Err(rejection)
    //     }
    // }
// }

//ATTEMPT 5

// async fn logout_handler(config: Config, headers: HeaderMap) -> Result<impl Reply, Rejection> {
//     let token = extract_token_from_headers(&headers);

//     match token {
//         Some(token) => {
//             match decode::<TokenClaims>(
//                 &token,
//                 &DecodingKey::from_secret(config.jwt_secret.as_ref()),
//                 &Validation::default(),
//             ) {
//                 Ok(_) => {
//                     let mut response = Response::new("Logout successful".to_string().into());
//                     response.headers_mut().insert(
//                         "Set-Cookie",
//                         warp::http::HeaderValue::from_static("token=; Max-Age=-1; Path=/"),
//                     );
//                     Ok(response)
//                 }
//                 Err(_) => {
//                     let json_error = ErrorResponse {
//                         status: "fail".to_string(),
//                         message: "Invalid token".to_string(),
//                     };
//                     Err(warp::reject::custom(json_error))
//                 }
//             }
//         }
//         None => {
//             let json_error = ErrorResponse {
//                 status: "fail".to_string(),
//                 message: "Token not found in cookies".to_string(),
//             };
//             Err(warp::reject::custom(json_error))
//         }
//     }
// }

// fn extract_token_from_headers(headers: &HeaderMap) -> Option<String> {
//     headers.get("Cookie").and_then(|cookie_header| {
//         let header_str = cookie_header.to_str().ok()?;
//         let token = header_str
//             .split(';')
//             .find(|cookie| cookie.trim().starts_with("token="))?;
//         let token = token.split('=').nth(1)?.to_string();
//         Some(token)
//     })
// }

// fn logout_handler() ->Result<impl Reply, Rejection> {
//     let cookie_value = "token=; Path=/; Max-Age=-1; HttpOnly";

//     let json_response = reply::json(&json!({
//         "status": "success"
//     }));

//     let response_with_cookie = warp::reply::with_header(
//         json_response,
//         SET_COOKIE,
//         HeaderValue::from_str(cookie_value).unwrap(),
//     );

//     Ok(response_with_cookie)
// }


//ATTEMPT 2



async fn get_me_handler(user_id:Uuid, pool: Pool<Postgres>) -> Result<impl Reply, Rejection> {
    let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let json_response = json!({
        "status": "success",
        "data": json!({
            "user": filter_user_record(&user)
        })
    });

    Ok(warp::reply::json(&json_response))
}

pub fn routes(
    pool: Pool<Postgres>,
    config: Config,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let register_user_handler = warp::path("api")
        .and(warp::path("auth"))
        .and(warp::path("register"))
        .and(warp::post())
        .and(warp::body::json())
        .and(with_pool(pool.clone()))
        .and_then(register_user_handler);

    let login_user_handler = warp::path("api")
        .and(warp::path("auth"))
        .and(warp::path("login"))
        .and(warp::post())
        .and(warp::body::json())
        .and(with_config(config.clone()))
        .and(with_pool(pool.clone()))
        .and_then(login_user_handler);

    let logout_handler = warp::path("api")
        .and(warp::path("auth"))
        .and(warp::path("logout"))
        .and(warp::get())
        .and(jwt_auth::auth_validation(config.clone()))
        .and_then(logout_handler);

    let get_me_handler = warp::path("api")
        .and(warp::path("users"))
        .and(warp::path("me"))
        .and(warp::get())
        .and(jwt_auth::auth_validation(config.clone()))
        .and(with_pool(pool.clone()))
        .and_then(get_me_handler);

     register_user_handler
        .or(login_user_handler)
        .or(logout_handler)
        .or(get_me_handler)
}

fn with_pool(
    pool: Pool<Postgres>,
) -> impl Filter<Extract = (Pool<Postgres>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || pool.clone())
}

fn with_config(
    config: Config,
) -> impl Filter<Extract = (Config,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || config.clone())
}