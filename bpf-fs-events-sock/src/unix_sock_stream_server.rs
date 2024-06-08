use std::io::Read;
use std::io::Write;

const BUF_MAX: usize = 4096 * 2;

pub struct Server<'a> {
    clients: Vec<std::os::unix::net::UnixStream>,
    sock_path: String,
    pid_path: String,
    accepted_rx: std::sync::mpsc::Receiver<std::os::unix::net::UnixStream>,
    removed_tx: std::sync::mpsc::Sender<usize>,
    removed_rx: std::sync::mpsc::Receiver<usize>,
    watcher: bpf_fs_events::FsEvents<'a>,
    event_serializer: fn(bpf_fs_events::Event) -> Vec<u8>,
    _accept_task: std::thread::JoinHandle<()>,
}

impl Drop for Server<'_> {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.sock_path) {
            eprintln!("error removing socket file: {}", e);
        }
        if let Err(e) = std::fs::remove_file(&self.pid_path) {
            eprintln!("error removing pid file: {}", e);
        }
    }
}

impl Server<'_> {
    pub fn try_new(
        sock_path: &str,
        event_serializer: fn(bpf_fs_events::Event) -> Vec<u8>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pid_path = format!("{sock_path}.pid");
        if let Ok(pid) = std::fs::read_to_string(&pid_path) {
            if let Ok(pid) = pid.parse::<i32>() {
                eprintln!("killing existing server process at pid {pid}");
                unsafe {
                    use libc::*;
                    if kill(pid, SIGTERM) != 0 {
                        match *__errno_location() {
                            ESRCH => (),
                            errno => {
                                return Err(format!("error killing pid {pid}, errno {errno}").into())
                            }
                        }
                    }
                }
            } else {
                eprintln!("ignoring pidfile with invalid pid at {pid_path}");
            }
        }
        for path in &[sock_path, &pid_path] {
            if std::fs::metadata(path).is_ok() {
                std::fs::remove_file(path)?;
            }
        }
        std::fs::write(&pid_path, std::process::id().to_string())?;
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let (removed_tx, removed_rx) = std::sync::mpsc::channel();
        Ok(Self {
            clients: Vec::new(),
            sock_path: sock_path.to_string(),
            pid_path,
            accepted_rx,
            removed_tx,
            removed_rx,
            watcher: bpf_fs_events::FsEvents::try_new()?,
            event_serializer,
            _accept_task: Self::spawn_accept_task(sock_path.to_string(), accepted_tx),
        })
    }

    fn spawn_accept_task(
        sock_path: String,
        accepted_tx: std::sync::mpsc::Sender<std::os::unix::net::UnixStream>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let srv = std::os::unix::net::UnixListener::bind(sock_path).unwrap();
            srv.set_nonblocking(false).unwrap();
            loop {
                let client = srv.accept();
                match client {
                    Ok((mut stream, _)) => {
                        let mut buf = [0; BUF_MAX];
                        eprintln!("client connected");
                        match stream.read(&mut buf) {
                            Ok(0) => {
                                eprintln!("client disconnected");
                                continue;
                            }
                            Ok(n) => match std::str::from_utf8(&buf[..n]) {
                                Ok(msg) => eprintln!("client said: {}", msg),
                                Err(_) => {
                                    eprintln!("invalid utf8");
                                    continue;
                                }
                            },
                            Err(e) => eprintln!("read error: {}", e),
                        }
                        accepted_tx.send(stream).unwrap();
                    }
                    Err(e) => eprintln!("accept error: {}", e),
                }
            }
        })
    }

    pub fn try_send_fs_events_blocking(&mut self) -> Result<(), std::io::ErrorKind> {
        if let Ok(stream) = self.accepted_rx.try_recv() {
            self.clients.push(stream);
        }
        if let Ok(client) = self.removed_rx.try_recv() {
            self.clients.remove(client);
        }
        if let Some(event) = self.watcher.poll_indefinite()? {
            let msg = (self.event_serializer)(event);
            for idx in 0..self.clients.len() {
                match self.clients[idx].write_all(&msg) {
                    Ok(_) => (),
                    Err(e) => match e.kind() {
                        std::io::ErrorKind::BrokenPipe => {
                            eprintln!("client disconnected");
                            // We'll get it next time on errors this time
                            let _ = self.removed_tx.send(idx);
                        }
                        _ => eprintln!("write error: {}", e),
                    },
                }
            }
        }
        Ok(())
    }
}
