extern crate bpf_fs_events;

fn show_event(event: bpf_fs_events::Event) {
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
    let pn = event.pathname;
    let hdr = format!("@ {ts} {et} {pt} pid:{pid}");
    if let Some(associated) = event.associated {
        println!("{hdr}\n> {pn}\n> {associated}");
    } else {
        println!("{hdr}\n> {pn}");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ctrlc::set_handler(|| std::process::exit(0))?;
    let watcher = bpf_fs_events::FsEvents::try_new()?;
    loop {
        match watcher.poll_indefinite() {
            Err(e) => return Err(format!("{:?}", e).into()),
            Ok(Some(event)) => show_event(event),
            Ok(None) => (),
        }
    }
}
