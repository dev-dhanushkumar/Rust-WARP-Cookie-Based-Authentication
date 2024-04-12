use crate::{
    config::Config,
    jwt_auth,
    model::{LoginUserSchema, RegisterUserSchema, TokenClaims, User, ForgotPasswordSchema, ResetPasswordSchema},
    response::FilteredUser,
    email::Email
};


use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;
use sqlx::{Pool, Postgres, Row};
use uuid::Uuid;
use warp::{
     reply, Filter, Rejection, Reply,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use warp::http::header::{HeaderValue, SET_COOKIE, CONTENT_TYPE};

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

#[derive(Debug, Serialize, Clone)]
struct ErrorResponse {
    status: String,
    message: String,
}

impl warp::reject::Reject for ErrorResponse {}


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

async fn logout_handler(id:Uuid) -> Result<impl Reply, warp::Rejection> {
    println!("User id: {}", id);
    let current_time_utc: chrono::DateTime<Utc> = Utc::now();
    println!("{:?}", current_time_utc);
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


async fn forgot_password_handler(
    body: ForgotPasswordSchema,
    pool: Pool<Postgres>,
    config: Config,
 ) -> Result<impl Reply, Rejection> {
    let err_message = "You will receive a password reset email if user with that email exist";

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(&body.email.to_owned().to_ascii_lowercase())
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            let error_response = ErrorResponse {
                status: "error".to_owned(),
                message: format!("Database error: {}", e),
            };
            warp::reject::custom(error_response)
        })?
        .ok_or_else(|| {
            let error_response = ErrorResponse {
                status: "fail".to_owned(),
                message: err_message.to_string(),
            };
            warp::reject::custom(error_response)
        })?;

    if user.verified {
        let error_response = ErrorResponse {
            status: "fail".to_owned(),
            message: "Account not verified".to_string(),
        };
        return Err(warp::reject::custom(error_response));
    }

    let password_reset_token: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(char::from)
        .collect();
    let password_token_expires_in = 10; // 10 minutes
    let password_reset_at = Utc::now() + Duration::minutes(password_token_expires_in);
    let password_reset_url = format!(
        "{}/resetpassword/{}",
        config.frontend_origin.to_owned(),
        password_reset_token
    );

    sqlx::query(
        "UPDATE users SET password_reset_token = $1, password_reset_at = $2 WHERE email = $3",
    )
    .bind(&password_reset_token)
    .bind(password_reset_at)
    .bind(&user.email.to_ascii_lowercase())
    .execute(&pool)
    .await
    .map_err(|e| {
        let json_error = ErrorResponse {
            status: "fail".to_owned(),
            message: format!("Error updating user: {}", e),
        };
        warp::reject::custom(json_error)
    })?;

    let email_instance = Email::new(user, password_reset_url, config.clone());
    if let Err(_) = email_instance
        .send_password_reset_token(password_token_expires_in)
        .await
    {
        let json_error = ErrorResponse {
            status: "fail".to_owned(),
            message: "Something bad happended while sending the password reset code".to_string(),
        };
        return Err(warp::reject::custom(json_error));
    }

    let response = json!({
        "status": "success",
        "message": err_message
    });

    Ok(warp::reply::json(&response))
}



async fn reset_password_handler(
    pool: Pool<Postgres>,
    password_reset_token: String,
    body: ResetPasswordSchema,
) -> Result<impl Reply, Rejection> {
    if body.password != body.password_confirm {
        let error_response = ErrorResponse {
            status: "fail".to_owned(),
            message: "Passwords do not match".to_string(),
        };
        return Err(warp::reject::custom(error_response));
    }

    // let current_time_utc: chrono::DateTime<Utc> = Utc::now();
    let user: User = sqlx::query_as(
        "SELECT * FROM users WHERE password_reset_token = $1 AND password_reset_at > $2",
    )
    .bind(&password_reset_token)
    .bind(chrono::Utc::now())
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        let error_response = ErrorResponse {
            status: "error".to_owned(),
            message: format!("Database error: {}", e),
        };
        warp::reject::custom(error_response)
    })?
    .ok_or_else(|| {
        let error_response = ErrorResponse {
            status: "fail".to_owned(),
            message: "The password reset token is invalid or has expired".to_string(),
        };
        warp::reject::custom( error_response)
    })?;

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| {
            let error_response = ErrorResponse {
                status: "fail".to_owned(),
                message: format!("Error while hashing password: {}", e),
            };
            warp::reject::custom( error_response)
        })
        .map(|hash| hash.to_string())?;

    sqlx::query(
        "UPDATE users SET password = $1, password_reset_token = $2, password_reset_at = NULL WHERE email = $3",
    )
    .bind(&hashed_password)
    .bind(Option::<String>::None)
    // .bind(Option::<String>::None)
    .bind(&user.email.to_ascii_lowercase())
    .execute(&pool)
    .await
    .map_err(|e| {
        let error_response = ErrorResponse {
            status: "fail".to_owned(),
            message: format!("Error updating user: {}", e),
        };
        warp::reject::custom( error_response)
    })?;

    let cookie_str = format!("token=; Max-Age=-1; httponly; path=/");

    let  json_response = reply::json(&json!({
        "status": "success",
        "message": "Password data updated successfully"
    }));

    let response_with_cookie = warp::reply::with_header(
        json_response,
        SET_COOKIE,
        HeaderValue::from_str(&cookie_str).unwrap(),
    );

    Ok(response_with_cookie)
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
    
    let forgot_password_handler = warp::path("api")
        .and(warp::path("auth"))
        .and(warp::path("forgotpassword"))
        .and(warp::post())
        .and(warp::body::json())
        .and(with_pool(pool.clone()))
        .and(with_config(config.clone()))
        .and_then(forgot_password_handler);

    let  reset_password_handler = warp::path("api")
        .and(warp::path("auth"))
        .and(warp::path("resetpassword"))
        .and(warp::patch())
        .and(with_pool(pool.clone()))
        .and(warp::path::param::<String>())
        .and(warp::body::json())
        // .and_then(reset_password_handler);
        .and_then(|pool: Pool<Postgres>, token: String, body: ResetPasswordSchema| {
            reset_password_handler( pool,token, body)
        });


    register_user_handler
        .or(login_user_handler)
        .or(get_me_handler)
        .or(logout_handler)
        .or(forgot_password_handler)
        .or(reset_password_handler)

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

// fn with_appstate(
//     app_state: AppState,
// ) -> impl Filter<Extract = (AppState,), Error = std::convert::Infallible> + Clone {
//     warp::any().map(move || app_state.clone())
// }