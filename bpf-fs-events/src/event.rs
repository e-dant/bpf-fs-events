use std::mem::MaybeUninit;

pub(crate) type RawEvent = crate::watcher_types::event;

#[derive(Clone, Copy, Debug)]
pub enum PathType {
    Dir,
    File,
    Symlink,
    Hardlink,
    Blockdev,
    Socket,
    Continuation,
    Unknown,
}

#[derive(Clone, Copy, Debug)]
pub enum EffectType {
    Create,
    Rename,
    Link,
    Delete,
    Continuation,
    Association,
}

// If we want to make associated events represent something other than
// moved-to paths, like on a rename event, we can make a structure like this:
//   pub struct EventFragment {
//       pub path_name: String,
//       pub timestamp: u64,
//       pub pid: u32,
//       pub path_type: PathType,
//       pub effect_type: EffectType,
//   }
// Which is just a subset of the Event struct. In the Event struct, we can
// associate an Option<EventFragment> with the Event instead of a String.

pub struct Event {
    pub path_name: String,
    pub associated: Option<String>,
    pub timestamp: u64,
    pub pid: u32,
    pub path_type: PathType,
    pub effect_type: EffectType,
}

unsafe impl plain::Plain for RawEvent {}

impl RawEvent {
    fn buf_as_bytes(&self) -> &[u8] {
        let buf = self.buf.as_ptr() as *const u8;
        let len = self.buf_len as usize;
        unsafe { std::slice::from_raw_parts(buf, len) }
    }

    #[cfg(feature = "ev-ringbuf")]
    fn buf_as_str(&self) -> &str {
        let buf_bytes = self.buf_as_bytes();
        std::str::from_utf8(buf_bytes).unwrap()
    }

    #[cfg(feature = "ev-ringbuf")]
    pub(crate) fn buf_to_string(&self) -> String {
        self.buf_as_str().to_string()
    }

    // Name offsets come left-padded and then in reverse order:
    //   [0.. snip .., 20, 15, 9]
    // We can parse those out with the offsets in the correct order:
    //   [9, 15, 20, 0..]
    // And return a list of pairs of offsets:
    //   [(0, 9), (9, 15), (15, 20)]
    #[cfg(feature = "ev-array")]
    fn reordered_name_offsets(&self) -> Vec<(u16, u16)> {
        log::trace!("raw name offsets: {:?}", self.name_offsets);
        let mut reordered = Vec::with_capacity(64);
        reordered.push((0, self.name_offsets[self.name_offsets.len() - 1] as u16));
        for idx in (1..self.name_offsets.len()).rev() {
            let beg = self.name_offsets[idx] as u16;
            let end = self.name_offsets[idx - 1] as u16;
            if end == 0 {
                log::trace!("idx: {idx}, @ end: {end}");
                break;
            } else if beg < end && end <= self.buf_len {
                log::trace!("idx: {idx}, beg: {beg}, end: {end}");
                reordered.push((beg, end));
            } else {
                log::error!("Invariant violated (beg < end && end <= buf_len) where beg: {beg}, end: {end}, buf_len: {}, idx: {idx}", self.buf_len);
            }
        }
        reordered.reverse();
        reordered
    }

    #[cfg(feature = "ev-array")]
    pub(crate) fn reordered_buf_to_string(&self) -> String {
        let name_offsets = self.reordered_name_offsets();
        let buf = self.buf_as_bytes();
        let mut name = String::with_capacity(256);
        let push_path_component = |name: &mut String, beg, end| {
            let span = &buf[beg as usize..end as usize];
            let utf8 = std::str::from_utf8(span).unwrap();
            log::trace!("(beg, end): ({beg}, {end}), utf8: {utf8}");
            name.push_str("/");
            name.push_str(utf8);
        };
        for (beg, end) in name_offsets {
            push_path_component(&mut name, beg, end);
        }
        log::trace!("raw buf: {:?}, name: {name}", buf);
        name
    }
}

impl From<MaybeUninit<u8>> for EffectType {
    fn from(value: MaybeUninit<u8>) -> Self {
        EffectType::from(unsafe { value.assume_init() })
    }
}

impl From<MaybeUninit<u8>> for PathType {
    fn from(value: MaybeUninit<u8>) -> Self {
        PathType::from(unsafe { value.assume_init() })
    }
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
            6 => PathType::Continuation,
            _ => PathType::Unknown,
        }
    }
}

impl From<u8> for EffectType {
    fn from(value: u8) -> Self {
        match value {
            0 => EffectType::Create,
            1 => EffectType::Rename,
            2 => EffectType::Link,
            3 => EffectType::Delete,
            4 => EffectType::Continuation,
            5 => EffectType::Association,
            _ => unreachable!(),
        }
    }
}
