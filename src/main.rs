mod config;
mod handler;
mod jwt_auth;
mod model;
mod response;

use config::Config;
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use handler::routes;





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


    let routes = routes(pool, config);

    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
}

