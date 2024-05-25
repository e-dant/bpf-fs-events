extern crate bpf_fs_events;

pub fn event_str(event: bpf_fs_events::Event) -> String {
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
        format!("{hdr}\n> {pn}\n> {associated}")
    } else {
        format!("{hdr}\n> {pn}")
    }
}
