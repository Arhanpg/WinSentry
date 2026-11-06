use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "winsentry")]
#[command(author = "Arhan Ghosarwade")]
#[command(version = scanner_core::VERSION)]
#[command(about = "WinSentry - High-velocity Windows Storage Reclamation & Security Auditing Engine", long_about = None)]
struct Cli {
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();
    println!("{} v{} initialized (verbose: {})", scanner_core::APP_NAME, scanner_core::VERSION, cli.verbose);
}
