mod agent;
mod app;
mod cvss;
mod cwe;
#[cfg(test)]
mod fixtures;
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
        // As a shell reports a command killed by SIGINT.
        let code = if error.is::<agent::Interrupted>() {
            130
        } else {
            1
        };
        std::process::exit(code);
    }
}
