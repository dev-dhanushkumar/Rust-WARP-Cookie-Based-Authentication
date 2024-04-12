mod config;
mod handler;
mod jwt_auth;
mod model;
mod response;
mod email;

use config::Config;
use dotenv::dotenv;
// use header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use sqlx::postgres::PgPoolOptions;
use handler::routes;
// use tower_http::cors::CorsLayer;


use warp::{
    http::{header, Method}, Filter, 
};
// #[derive(Clone)]
// pub struct AppState {
//     db: Pool<Postgres>,
//     config: Config,
// }




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

    let cors = warp::cors()
    .allow_origins(vec!["http://localhost:3000"])
    .allow_methods(vec![Method::GET, Method::POST, Method::PATCH])
    .allow_headers(vec![
        header::CONTENT_TYPE,
        header::AUTHORIZATION,
        header::ACCEPT,
        header::SET_COOKIE,
    ])
    .allow_credentials(true);

    let routes = routes(pool, config)
        .with(cors);

    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;

    //START COMMAND:   cargo watch -w src -w Cargo.toml -w .env -x run
}

