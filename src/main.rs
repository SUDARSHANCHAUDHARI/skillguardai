mod findings;
mod score;
mod rules;
mod skill;
mod walker;
mod engine;
mod baseline;
mod report;
mod sarif;
mod cli;

fn main() { std::process::exit(cli::run()); }
