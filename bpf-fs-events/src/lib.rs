mod event;
mod ingest;
mod skel_watcher;
use core::time::Duration;
pub use event::EffectType;
pub use event::Event;
pub use event::PathType;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use skel_watcher::*;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(feature = "ev-array")]
type EvBuf<'a> = libbpf_rs::PerfBuffer<'a>;
#[cfg(feature = "ev-ringbuf")]
type EvBuf<'a> = libbpf_rs::RingBuffer<'a>;

pub struct FsEvents<'cls> {
    // Need to hold this to keep the attached probes alive
    _skel: WatcherSkel<'cls>,
    ev_buf: EvBuf<'cls>,
    rx: std::sync::mpsc::Receiver<Event>,
}

fn bump_memlock_rlimit() -> Result<(), std::io::Error> {
    let hard = rlimit::Resource::MEMLOCK.get_hard()?;
    let target = core::cmp::min(hard, 128 << 20); // 128^4/2
    rlimit::Resource::MEMLOCK.set(target, hard)?;
    Ok(())
}

fn open_skel_interface<'a>() -> Result<WatcherSkel<'a>, Box<dyn std::error::Error>> {
    let skel_builder = if cfg!(debug_assertions) {
        let mut skel = WatcherSkelBuilder::default();
        skel.obj_builder.debug(true);
        skel
    } else {
        WatcherSkelBuilder::default()
    };
    let mut skel = skel_builder.open()?.load()?;
    skel.attach()?;
    Ok(skel)
}

impl FsEvents<'_> {
    pub fn try_new() -> Result<Self, Box<dyn std::error::Error>> {
        bump_memlock_rlimit()?;
        let mut skel = open_skel_interface()?;
        let mut maps = skel.maps_mut();
        let (tx, rx) = std::sync::mpsc::channel();
        #[cfg(feature = "ev-array")]
        {
            let on_event = ingest::accumulating_event_stream_proxy(tx);
            let ev_buf = libbpf_rs::PerfBufferBuilder::new(maps.events())
                .sample_cb(on_event)
                .build()?;
            Ok(Self {
                _skel: skel,
                ev_buf,
                rx,
            })
        }
        #[cfg(feature = "ev-ringbuf")]
        {
            let on_event = ingest::accumulating_event_stream_proxy(tx);
            let mut ev_buf = libbpf_rs::RingBufferBuilder::new();
            ev_buf.add(maps.events(), on_event)?;
            let ev_buf = ev_buf.build()?;
            Ok(Self {
                _skel: skel,
                ev_buf,
                rx,
            })
        }
    }

    pub fn poll_with_timeout(
        &self,
        duration: Duration,
    ) -> Result<Option<Event>, std::io::ErrorKind> {
        match self.ev_buf.poll(duration) {
            Ok(_) => match self.rx.try_recv() {
                Ok(event) => Ok(Some(event)),
                Err(std::sync::mpsc::TryRecvError::Empty) => Ok(None),
                Err(_) => Err(std::io::ErrorKind::Other),
            },
            Err(_) => Err(std::io::ErrorKind::Other),
        }
    }

    pub fn poll_immediate(&self) -> Result<Option<Event>, std::io::ErrorKind> {
        self.poll_with_timeout(Duration::from_secs(0))
    }

    pub fn poll_indefinite(&self) -> Result<Option<Event>, std::io::ErrorKind> {
        self.poll_with_timeout(Duration::MAX)
    }
}

impl Future for FsEvents<'_> {
    type Output = Result<Event, std::io::ErrorKind>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match self.poll_immediate() {
            Ok(Some(event)) => Poll::Ready(Ok(event)),
            Ok(None) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}
