//! irohlan — a P2P layer-2 (TAP) VPN for Linux built on [iroh].
//!
//! [iroh]: https://iroh.computer

mod allocator;
mod bus;
mod cli;
mod config;
mod crypto;
mod flow;
mod membership;
mod mesh;
mod metrics;
mod netaddr;
mod node;
mod proto;
mod relay;
mod routing;
mod switch;
mod tap;
mod ticket;

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let cli = <cli::Cli as clap::Parser>::parse();
    if let Err(err) = rt.block_on(cli::run(cli)) {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
