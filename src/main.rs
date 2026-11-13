mod agent;
mod algolia;
mod asn;
mod cli;
mod commands;
mod constants;
mod context;
mod display;
mod error;
mod http;
mod output;
mod safety;

use clap::{CommandFactory, Parser};
use cli::{Cli, Commands};
use context::AppContext;
use error::AppResult;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Completions/manpage need no HTTP client, no credentials — intercept
    // before AppContext is built (Manpage in particular must not require
    // network/filesystem side effects).
    match &cli.command {
        Commands::Completions(args) => {
            generate_completions(args);
            return;
        }
        Commands::Manpage => {
            generate_manpage();
            return;
        }
        _ => {}
    }

    let ctx = AppContext::new(&cli);

    let result = dispatch(&ctx, &cli.command).await;

    // Single exit-point mapping AppError variant -> exit code (D5).
    if let Err(e) = result {
        let code = e.exit_code();
        ctx.presenter.error(&e);
        std::process::exit(code);
    }
}

async fn dispatch(ctx: &AppContext, command: &Commands) -> AppResult<()> {
    match command {
        Commands::Doctor => commands::doctor::run(ctx).await,

        Commands::Logs(sub) => match sub {
            cli::LogsCommands::Sample(args) => commands::logs::run_sample(ctx, args).await,
            cli::LogsCommands::Offsite(args) => commands::logs::run_offsite(ctx, args).await,
            cli::LogsCommands::Errors(args) => commands::logs::run_errors(ctx, args).await,
        },

        Commands::Keys(sub) => match sub {
            cli::KeysCommands::Audit(args) => commands::keys::run_audit(ctx, args).await,
        },

        Commands::Usage(sub) => match sub {
            cli::UsageCommands::Summary(args) => commands::usage::run_summary(ctx, args).await,
            cli::UsageCommands::Series(args) => commands::usage::run_series(ctx, args).await,
            cli::UsageCommands::Meters(args) => commands::usage::run_meters(ctx, args).await,
        },

        Commands::Analytics(sub) => match sub {
            cli::AnalyticsCommands::TopSearches(args) => {
                commands::analytics::run_top_searches(ctx, args).await
            }
            cli::AnalyticsCommands::NoResults(args) => {
                commands::analytics::run_no_results(ctx, args).await
            }
            cli::AnalyticsCommands::ScrapeSignals(args) => {
                commands::analytics::run_scrape_signals(ctx, args).await
            }
            cli::AnalyticsCommands::Clicks(args) => {
                commands::analytics::run_clicks(ctx, args).await
            }
            cli::AnalyticsCommands::Conversions(args) => {
                commands::analytics::run_conversions(ctx, args).await
            }
            cli::AnalyticsCommands::Revenue(args) => {
                commands::analytics::run_revenue(ctx, args).await
            }
        },

        Commands::Events(sub) => match sub {
            cli::EventsCommands::Metrics(args) => commands::events::run_metrics(ctx, args).await,
            cli::EventsCommands::Sample(args) => commands::events::run_sample(ctx, args).await,
            cli::EventsCommands::Errors(args) => commands::events::run_errors(ctx, args).await,
        },

        Commands::Completions(_) | Commands::Manpage => unreachable!(),
    }
}

fn generate_completions(args: &cli::CompletionsArgs) {
    use clap_complete::{generate, Shell};

    let shell = match args.shell {
        cli::ShellType::Bash => Shell::Bash,
        cli::ShellType::Zsh => Shell::Zsh,
        cli::ShellType::Fish => Shell::Fish,
        cli::ShellType::PowerShell => Shell::PowerShell,
    };

    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "alx", &mut std::io::stdout());
}

fn generate_manpage() {
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    man.render(&mut std::io::stdout())
        .expect("failed to generate man page");
}
