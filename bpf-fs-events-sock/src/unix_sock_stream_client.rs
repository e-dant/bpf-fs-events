use bpf_fs_events_sock::limits::BUF_MAX;
use crate::limits::BUF_MAX;
use std::io::Read;
use std::io::Write;

pub struct Client {
    read_buf: [u8; BUF_MAX],
    sock: std::os::unix::net::UnixStream,
}

impl Client {
    pub fn try_new(sock_path: &str) -> Result<Self, std::io::Error> {
        let read_buf = [0; BUF_MAX];
        let mut sock = std::os::unix::net::UnixStream::connect(sock_path)?;
        // Say hello
        sock.write_all(b"hello")?;
        Ok(Self { read_buf, sock })
    }

    pub fn try_read(&mut self) -> Result<&str, std::io::ErrorKind> {
        let n = self.sock.read(&mut self.read_buf);
        match n {
            Ok(0) => Err(std::io::ErrorKind::ConnectionReset),
            Ok(n) => match std::str::from_utf8(&self.read_buf[..n]) {
                Ok(msg) => Ok(msg),
                Err(_) => Err(std::io::ErrorKind::InvalidData),
            },
            Err(e) => Err(e.kind()),
        }
    }
}
