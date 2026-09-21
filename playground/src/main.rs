use coggate_playground::{AppState, Config, Database, router};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("admin") {
        return admin(&args[2..]);
    }

    let config = Config::from_env()?;
    let database = Database::open(&config.database_path)?;
    let state = AppState::new(config.clone(), database)?;
    state.start_background_tasks()?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(address=%config.listen, "CogGate Arena listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn admin(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let database_path =
        std::env::var("ARENA_DATABASE_PATH").unwrap_or_else(|_| "./data/arena.sqlite3".into());
    let database = Database::open(std::path::Path::new(&database_path))?;
    let actor = std::env::var("USER").unwrap_or_else(|_| "local-operator".into());
    match args.first().map(String::as_str) {
        Some("create-round") if args.len() == 5 => {
            let round = database.create_round(&args[1], &args[2], &args[3], &args[4])?;
            println!("{} {} {}", round.id, round.epoch, round.status);
        }
        Some("open-round") if args.len() == 2 => {
            database.open_round(&args[1], &actor)?;
            println!("opened {}", args[1]);
        }
        Some("maintenance") if args.len() == 2 => {
            let round_id = database.enter_maintenance(&actor, &args[1])?;
            println!("maintenance {round_id}");
        }
        Some("archive-round") if args.len() == 3 => {
            database.archive_round(&args[1], &actor, &args[2])?;
            println!("archived {}", args[1]);
        }
        Some("disable-user") | Some("enable-user") if args.len() == 3 => {
            let github_id: i64 = args[1].parse()?;
            database.set_user_disabled(github_id, args[0] == "disable-user", &actor, &args[2])?;
            println!("updated user {github_id}");
        }
        Some("credit") if args.len() == 4 => {
            let github_id: i64 = args[1].parse()?;
            let amount: i64 = args[2].parse()?;
            database.add_manual_credit(github_id, amount, &actor, &args[3])?;
            println!("credited user {github_id}");
        }
        Some("retry-issue") if args.len() == 2 => {
            database.retry_issue(&args[1])?;
            println!("queued {}", args[1]);
        }
        Some("integrity-check") if args.len() == 1 => {
            if !database.integrity_check()? {
                return Err("SQLite integrity check failed".into());
            }
            println!("ok");
        }
        _ => {
            eprintln!(
                "usage:\n  coggate-playground admin create-round <sdk-version> <sdk-commit> <generator-version> <runner-manifest-digest>\n  coggate-playground admin open-round <round-id>\n  coggate-playground admin maintenance <reason-code>\n  coggate-playground admin archive-round <round-id> <reason-code>\n  coggate-playground admin disable-user|enable-user <github-id> <reason-code>\n  coggate-playground admin credit <github-id> <amount> <reason-code>\n  coggate-playground admin retry-issue <event-id>\n  coggate-playground admin integrity-check"
            );
            std::process::exit(2);
        }
    }
    Ok(())
}
