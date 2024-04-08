mod config;
mod handler;
mod jwt_auth;
mod model;
mod response;

use config::Config;
use dotenv::dotenv;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use warp::{
    http::header::{self, HeaderValue},
    Filter, Reply, Rejection,
};
use handler::routes;

#[derive(Clone)]
pub struct AppState {
    db: Pool<Postgres>,
    env: Config,
}

async fn checking(app_state: AppState) -> Result<impl Reply, warp::Rejection> {
    const MESSAGE: &str = "JWT Authentication in Rust Warp, Postegres, and SqlX";

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "message": MESSAGE
    })))
}

#[tokio::main]
async fn main() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "warp=info");
    }
    dotenv().ok();
    env_logger::init();

    let config = Config::init();

    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("✅Connection to the database is successful!");
            pool
        }
        Err(err) => {
            println!("🔥 Failed to connect to the database: {:?}", err);
            std::process::exit(1);
        }
    };

    println!("🚀 Server started successfully");

    // let cors = warp::cors()
    //     .allow_origins(vec!["http://localhost:3000".parse().unwrap()])
    //     .allow_methods(vec![
    //         HeaderValue::from_static("GET"),
    //         HeaderValue::from_static("POST"),
    //     ])
    //     .allow_headers(vec![
    //         header::CONTENT_TYPE,
    //         header::AUTHORIZATION,
    //         header::ACCEPT,
    //     ])
    //     .allow_credentials(true);

    // let routes = warp::path("api")
    //     .and(warp::path("auth"))
    //     .and(warp::get())
    //     .and(with_appstate(AppState {
    //         db: pool,
    //         env: config,
    //     }))
    //     .and_then(checking);

    let routes = routes(pool, config);

    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
}

fn with_appstate(
    app_state: AppState,
) -> impl Filter<Extract = (AppState,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || app_state.clone())
}