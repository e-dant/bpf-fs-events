use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::Path;

macro_rules! known_env {
    ($name:literal) => {
        env::var($name).expect(concat!($name, " must be set in build script"))
    };
}

fn cargo_arch_to_kernel_arch(arch: &str) -> &str {
    match arch {
        "aarch64" => "arm64",
        "loongarch64" => "loongarch",
        "powerpc64" => "powerpc",
        "riscv64" => "riscv",
        "x86_64" => "x86",
        _ => "host",
    }
}

enum DiffError {
    File1Read,
    File2Read,
    Io,
}

fn try_file_content_differs(file1: &str, file2: &str) -> Result<bool, DiffError> {
    use std::fs;
    use std::io::Read;
    let mut buf1 = Vec::new();
    let mut buf2 = Vec::new();
    let mut file1 = fs::File::open(file1).map_err(|_| DiffError::File1Read)?;
    let mut file2 = fs::File::open(file2).map_err(|_| DiffError::File2Read)?;
    if file1.read_to_end(&mut buf1).is_err() || file2.read_to_end(&mut buf2).is_err() {
        Err(DiffError::Io)
    } else {
        Ok(buf1 != buf2)
    }
}

struct LnList {
    from: String,
    to: String,
}

impl LnList {
    fn link_when_files_differ(&self) -> Result<(), std::io::Error> {
        let differs = try_file_content_differs(&self.from, &self.to);
        match differs {
            Err(DiffError::File1Read) => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Link source file not found: {}", self.from),
            )),
            Ok(false) => Ok(()),
            _ => {
                std::fs::remove_file(&self.to).ok();
                std::os::unix::fs::symlink(&self.from, &self.to)?;
                Ok(())
            }
        }
    }
}

fn try_build_bpf(prog_name: &str) -> Result<(), std::io::Error> {
    let crate_manifest_dir = known_env!("CARGO_MANIFEST_DIR").to_string();
    let crate_out_dir = known_env!("OUT_DIR").to_string();
    let cargo_arch = known_env!("CARGO_CFG_TARGET_ARCH").to_string();
    let kernel_arch = cargo_arch_to_kernel_arch(&cargo_arch).to_string();
    let vmlinux_hdr_dir = format!("{crate_manifest_dir}/include/vmlinux/{kernel_arch}");
    let vmlinux_file = format!("{vmlinux_hdr_dir}/vmlinux.h");
    let vmlinux_visible_file = format!("{crate_manifest_dir}/src/bpf/vmlinux.h");
    let prog_src_file = format!("{crate_manifest_dir}/src/bpf/{prog_name}.bpf.c");
    let skel_out_file = format!("{crate_out_dir}/{prog_name}.skel.rs");
    let skel_visible_file = format!("{crate_manifest_dir}/src/skel_{prog_name}.rs");
    let links = vec![
        LnList {
            from: skel_out_file.clone(),
            to: skel_visible_file.clone(),
        },
        LnList {
            from: vmlinux_file.clone(),
            to: vmlinux_visible_file.clone(),
        },
    ];
    // If the kernel header dir doesn't exist,
    // we can run 'tool/gen-vmlinux.sh' to set things up.
    if !Path::new(&vmlinux_hdr_dir).exists() {
        let cmd = format!("{crate_manifest_dir}/tool/gen-vmlinux.sh");
        let status = std::process::Command::new(&cmd).status().unwrap();
        if !status.success() {
            panic!("Failed to run: {}", cmd);
        }
    }
    // To build the elf manually:
    // clang -g -target bpf -D__TARGET_ARCH_x86 -c src/bpf/watcher.bpf.c
    // Which can be nice to actually see the compiler errors, if any.
    SkeletonBuilder::new()
        .source(prog_src_file.clone())
        .debug(true)
        .clang_args(["-I", vmlinux_hdr_dir.as_str()])
        .build_and_generate(Path::new(&skel_out_file))
        .map_err(|e| {
            println!("Failed to build BPF program: {e}");
            std::io::ErrorKind::Other
        })?;
    for l in links {
        l.link_when_files_differ()?;
    }
    println!("cargo:rerun-if-changed={prog_src_file}");
    Ok(())
}

fn build_bpf_or_panic(name: &str) {
    try_build_bpf(name).unwrap();
}

fn main() {
    ["watcher"].map(build_bpf_or_panic);
}
