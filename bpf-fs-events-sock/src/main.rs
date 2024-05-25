extern crate bpf_fs_events;
mod unix_sock_stream_client;
mod unix_sock_stream_server;
use unix_sock_stream_client::Client;
use unix_sock_stream_server::Server;
use clap::Parser;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum Role {
    Server,
    Client,
}

#[derive(clap::Parser)]
#[command(name = "bpf-fs-events")]
struct Cli {
    #[arg(short, long, default_value = "/var/run/fs-events")]
    sockpath: String,
    #[arg(value_enum, default_value = "server")]
    role: Role,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let sock_path = args.sockpath.as_str();
    match args.role {
        Role::Server => {
            let mut server = Server::try_new(sock_path)?;
            loop {
                match server.try_send_fs_events_blocking() {
                    Ok(_) => (),
                    Err(e) => return Err(Box::new(std::io::Error::new(e, "server"))),
                }
            }
        },
        Role::Client => {
            let mut client = Client::try_new(sock_path)?;
            loop {
                match client.try_read() {
                    Ok(msg) => println!("{}", msg),
                    Err(std::io::ErrorKind::WouldBlock) => continue,
                    Err(std::io::ErrorKind::ConnectionReset) => {
                        eprintln!("connection reset");
                        return Ok(());
                    }
                    Err(e) => return Err(Box::new(std::io::Error::new(e, "client"))),
                }
            }
        }
    }
}
