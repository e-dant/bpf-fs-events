use bpf_fs_events_sock::Client;
use bpf_fs_events_sock::Server;
use clap::Parser;

const SOCK_PATH_DEFAULT: &str = concat!(
    "/var/run/fs-events.v",
    env!("CARGO_PKG_VERSION_MAJOR"),
    "-",
    env!("CARGO_PKG_VERSION_MINOR"),
    ".sock"
);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum Role {
    Server,
    Client,
    Stdio,
}

#[derive(clap::Parser)]
#[command(name = "bpf-fs-events")]
struct Cli {
    #[arg(short, long, default_value = SOCK_PATH_DEFAULT)]
    sockpath: String,
    #[arg(value_enum, short, long, default_value = "stdio")]
    role: Role,
}

fn event_to_string(event: bpf_fs_events::Event) -> String {
    use bpf_fs_events::EffectType;
    use bpf_fs_events::PathType;
    let et = match event.effect_type {
        EffectType::Create => "create",
        EffectType::Rename => "rename",
        EffectType::Link => "link",
        EffectType::Delete => "delete",
        EffectType::Cont => "unexpected:cont",
        EffectType::Assoc => "unexpected:assoc",
    };
    let pt = match event.path_type {
        PathType::Dir => "dir",
        PathType::File => "file",
        PathType::Symlink => "symlink",
        PathType::Hardlink => "hardlink",
        PathType::Blockdev => "blockdev",
        PathType::Socket => "socket",
        PathType::Cont => "unexpected:cont",
        PathType::Unknown => "unexpected:unknown",
    };
    let ts = event.timestamp;
    let pid = event.pid;
    let pn = event.path_name;
    if let Some(associated) = event.associated {
        format!("@ {ts} {et} {pt} pid:{pid}\n> {pn}\n> {associated}")
    } else {
        format!("@ {ts} {et} {pt} pid:{pid}\n> {pn}")
    }
}

fn event_to_bytes(event: bpf_fs_events::Event) -> Vec<u8> {
    event_to_string(event).into_bytes()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    match args.role {
        Role::Server => {
            let mut server = Server::try_new(args.sockpath.as_str(), event_to_bytes)?;
            loop {
                match server.try_send_fs_events_blocking() {
                    Ok(_) => (),
                    Err(e) => return Err(Box::new(std::io::Error::new(e, "server"))),
                }
            }
        }
        Role::Client => {
            let mut client = Client::try_new(args.sockpath.as_str())?;
            loop {
                match client.try_read() {
                    Ok(msg) => println!("{msg}"),
                    Err(std::io::ErrorKind::WouldBlock) => continue,
                    Err(std::io::ErrorKind::ConnectionReset) => {
                        eprintln!("connection reset");
                        return Ok(());
                    }
                    Err(e) => return Err(Box::new(std::io::Error::new(e, "client"))),
                }
            }
        }
        Role::Stdio => {
            ctrlc::set_handler(|| std::process::exit(0))?;
            let watcher = bpf_fs_events::FsEvents::try_new()?;
            loop {
                match watcher.poll_indefinite() {
                    Err(e) => return Err(format!("{:?}", e).into()),
                    Ok(Some(event)) => println!("{}", event_to_string(event)),
                    Ok(None) => (),
                }
            }
        }
    }
}
