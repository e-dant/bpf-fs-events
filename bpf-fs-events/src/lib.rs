mod skel_watcher;
use core::time::Duration;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use plain::Plain;
use skel_watcher::*;
use std::future::Future;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::task::{Context, Poll};

type RawEvent = watcher_types::event;

unsafe impl Plain for RawEvent {}

#[derive(Clone, Copy)]
pub enum PathType {
    Dir,
    File,
    Symlink,
    Hardlink,
    Blockdev,
    Socket,
    Unknown,
    Cont,
}

impl From<u8> for PathType {
    fn from(value: u8) -> Self {
        match value {
            0 => PathType::Dir,
            1 => PathType::File,
            2 => PathType::Symlink,
            3 => PathType::Hardlink,
            4 => PathType::Blockdev,
            5 => PathType::Socket,
            6 => PathType::Cont,
            _ => PathType::Unknown,
        }
    }
}

impl From<MaybeUninit<u8>> for PathType {
    fn from(value: MaybeUninit<u8>) -> Self {
        let value = unsafe { value.assume_init() };
        PathType::from(value)
    }
}

#[derive(Clone, Copy)]
pub enum EffectType {
    Create,
    Rename,
    Link,
    Delete,
    Cont,
    Assoc,
}

impl From<u8> for EffectType {
    fn from(value: u8) -> Self {
        match value {
            0 => EffectType::Create,
            1 => EffectType::Rename,
            2 => EffectType::Link,
            3 => EffectType::Delete,
            4 => EffectType::Cont,
            5 => EffectType::Assoc,
            _ => unreachable!(),
        }
    }
}

impl From<MaybeUninit<u8>> for EffectType {
    fn from(value: MaybeUninit<u8>) -> Self {
        let value = unsafe { value.assume_init() };
        EffectType::from(value)
    }
}

pub struct EventFragment {
    pub path_name: String,
    pub timestamp: u64,
    pub pid: u32,
    pub path_type: PathType,
    pub effect_type: EffectType,
}

pub struct Event {
    pub path_name: String,
    pub associated: Option<String>,
    pub timestamp: u64,
    pub pid: u32,
    pub path_type: PathType,
    pub effect_type: EffectType,
}

#[derive(Clone, Copy)]
enum Continuation {
    Pending,
    Complete,
}

struct PartialPaths {
    path_names: std::collections::VecDeque<String>,
    associated: std::collections::VecDeque<String>,
    event_group_id: u16,
    state: Continuation,
}

fn path_name_from_bpf_event(event: &RawEvent) -> &str {
    let len = event.buf_len as usize;
    let buf = event.buf.as_ptr() as *const u8;
    let span = unsafe { std::slice::from_raw_parts(buf, len) };
    std::str::from_utf8(span).unwrap()
}

impl PartialPaths {
    const fn new() -> Self {
        Self {
            path_names: std::collections::VecDeque::new(),
            associated: std::collections::VecDeque::new(),
            event_group_id: 0,
            state: Continuation::Pending,
        }
    }

    fn deque_to_path_name(deque: &std::collections::VecDeque<String>) -> String {
        deque
            .iter()
            .fold(String::with_capacity(256), |path, part| path + "/" + part)
    }

    // If the group ID of the "next" event differs from whatever we stored
    // before, we'll clear out what we have and start a new group.
    // If the event is a continuation, we'll add the path_name to the list.
    // Unless the continuation event is the root directory and belongs to
    // the same group as the previous event. In that case, we're
    // associating the "next" path_names with what we have stored.
    // (Such as rename to-and-from, or link to-and-from.)
    fn continue_with(&mut self, event: &RawEvent) -> Option<Event> {
        let groups_differ = event.event_group_id != self.event_group_id;
        if groups_differ {
            self.path_names.clear();
            self.associated.clear();
            self.event_group_id = event.event_group_id;
        }
        let effect_type = EffectType::from(event.effect_type);
        match effect_type {
            EffectType::Assoc => {
                self.associated.push_front("".to_string());
                self.state = Continuation::Pending;
                None
            }
            EffectType::Cont => {
                let path_name = path_name_from_bpf_event(event);
                match self.associated.len() {
                    0 => self.path_names.push_front(path_name.to_string()),
                    _ => self.associated.push_front(path_name.to_string()),
                }
                self.state = Continuation::Pending;
                None
            }
            _ => {
                self.state = Continuation::Complete;
                let path_name = Self::deque_to_path_name(&self.path_names);
                let associated = match &self.associated.len() {
                    0 => None,
                    _ => Some(Self::deque_to_path_name(&self.associated)),
                };
                Some(Event {
                    path_name,
                    associated,
                    timestamp: event.timestamp,
                    pid: event.pid,
                    path_type: event.path_type.into(),
                    effect_type,
                })
            }
        }
    }
}

pub struct FsEvents<'cls> {
    // Need to hold this to keep the attached probes alive
    _skel: WatcherSkel<'cls>,
    ringbuf: libbpf_rs::RingBuffer<'cls>,
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

fn accumulating_event_handler(tx: std::sync::mpsc::Sender<Event>) -> impl FnMut(&[u8]) -> i32 {
    let mut path_parsing_state = PartialPaths::new();
    move |data: &[u8]| {
        let event = match plain::from_bytes(data) {
            Ok(event) => event,
            // Big oops, unexpected event format, mismatch between BPF and Rust types
            Err(_) => return 1,
        };
        // Event paths may be sent in pieces. Accumulating them here...
        let next_state = path_parsing_state.continue_with(event);
        match next_state {
            // Holding back until we have something meaningful
            None => 0,
            // Sending them along when we do
            Some(completed) => {
                match tx.send(completed) {
                    Ok(_) => 0,
                    // If the receiver has not been dropped, of course.
                    Err(_) => 1,
                }
            }
        }
    }
}

impl FsEvents<'_> {
    pub fn try_new() -> Result<Self, Box<dyn std::error::Error>> {
        bump_memlock_rlimit()?;
        let mut skel = open_skel_interface()?;
        let mut maps = skel.maps_mut();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut ringbuf = libbpf_rs::RingBufferBuilder::new();
        ringbuf.add(maps.events(), accumulating_event_handler(tx))?;
        let ringbuf = ringbuf.build()?;
        Ok(Self {
            _skel: skel,
            ringbuf,
            rx,
        })
    }

    pub fn poll_with_timeout(
        &self,
        duration: Duration,
    ) -> Result<Option<Event>, std::io::ErrorKind> {
        match self.ringbuf.poll(duration) {
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
