mod config;
mod private_fs;
mod ipc;
mod crypto;
mod scanner;
mod daemon;
mod cli;
mod attachment;

fn main() {
    private_fs::restrict_umask();
    if std::env::var("WX_DAEMON_MODE").is_ok() {
        daemon::run();
    } else {
        cli::run();
    }
}
