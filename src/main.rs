mod server;

use std::io;
use env_logger::Env;
use log::{debug, error, info};
use structopt::StructOpt;
use tokio::net::TcpListener;
use crate::server::process;

#[derive(Debug, StructOpt)]
#[structopt(name = "nestedsocks")]
struct Opt {
    #[structopt(short, long, default_value = "127.0.0.1:5000")]
    pub listen_addr: String,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init_from_env(Env::new().default_filter_or("info"));

    let opts = Opt::from_args();

    let listener = TcpListener::bind(&opts.listen_addr).await?;
    info!("listening on {:?}", opts.listen_addr);

    loop {
        let (client, peer_addr) = listener.accept().await?;

        debug!("received connection from {:?}", peer_addr);
        tokio::spawn(async move {
            if let Err(e) = process(client).await {
                error!("an error occurred: {:?}", e);
            }
        });
    }
}
