mod agent;
mod app;
mod cvss;
mod cwe;
mod git;
mod model;
mod progress;
mod project;
mod prompts;
mod release;
mod render;
mod subtasks;
mod tools;

fn main() {
    if let Err(error) = app::run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
