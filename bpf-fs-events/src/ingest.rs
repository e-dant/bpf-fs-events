use crate::event::EffectType;
use crate::event::Event;
use crate::event::RawEvent;

#[derive(Clone, Copy)]
enum Continuation {
    Pending,
    Complete,
}

#[cfg(feature = "ev-array")]
type PathAcc = String;

struct PartialPaths {
    path_name: PathAcc,
    associated: Option<PathAcc>,
    // event_group_id: u16,
    state: Continuation,
}

#[cfg(feature = "ev-ringbuf")]
struct PathAcc {
    items: std::collections::VecDeque<String>,
}

#[cfg(feature = "ev-ringbuf")]
impl PathAcc {
    fn new() -> Self {
        Self {
            #[cfg(feature = "ev-ringbuf")]
            items: std::collections::VecDeque::new(),
            #[cfg(feature = "ev-array")]
            items: std::path::PathBuf::new(),
        }
    }

    fn concat_items_to_path_name(&self) -> String {
        self.items
            .iter()
            .rev()
            .fold(String::with_capacity(256), |path_acc, next_part| {
                path_acc + "/" + &next_part
            })
    }
}

impl PartialPaths {
    fn new() -> Self {
        Self {
            path_name: PathAcc::new(),
            associated: None,
            // event_group_id: 0,
            state: Continuation::Pending,
        }
    }

    /// For the ringbuf case, when we don't have dentry_path_raw, we have some tricks
    /// for working with several sub-events, representing path components of a single
    /// logical event. I call those sub-events "continuations".
    /// - If the group ID of the "next" event differs from whatever we stored before,
    ///   we'll clear out what we have and start a new group.
    ///   Group IDs are a bit of an insurance policy. Normally, all events are
    ///   terminal on the first non-continuation or non-association event. Rarely,
    ///   especially under heavy load when we don't have a chance to drain the buffer
    ///   before it fills it, events can be skipped.
    /// - If the event is a continuation, we'll accumulate its path_name component.
    ///   We'll keep on doing that until we hit a terminal event or an association.
    /// - If the event is an association, we'll begin associating all the upcoming path
    ///   names in the same group with what we have already stored for the event.
    ///   Associations are expected for rename-to or link-to events.
    ///
    /// The flow is much simpler for the array case. We already have most of the data we
    /// need. The exception is associated events. They are handled in the same way as
    /// associations in the ringbuf case.
    #[cfg(feature = "ev-ringbuf")]
    fn continue_with(&mut self, event: &RawEvent) -> Option<Event> {
        /*
        if event.event_group_id != self.event_group_id {
            self.path_name.clear();
            self.associated = None;
            self.event_group_id = event.event_group_id;
        }
        */
        eprintln!(
            "  effect type: {:?}, path type: {:?}, path name: {}",
            EffectType::from(event.effect_type),
            crate::event::PathType::from(event.path_type),
            event.path_name_buf_to_str()
        );
        match EffectType::from(event.effect_type) {
            EffectType::Continuation => {
                let path_name = event.path_name_buf_to_str().to_string();
                match self.associated {
                    Some(ref mut associated) => associated.items.push_back(path_name),
                    None => self.path_name.items.push_back(path_name),
                }
                self.state = Continuation::Pending;
                None
            }
            EffectType::Association => {
                self.associated = Some(PathAcc::new());
                self.state = Continuation::Pending;
                None
            }
            terminal_effect_type => {
                let path_name = self.path_name.concat_items_to_path_name();
                let associated = match self.associated {
                    Some(ref associated) => Some(associated.concat_items_to_path_name()),
                    None => None,
                };
                self.path_name.items.clear();
                self.associated = None;
                self.state = Continuation::Complete;
                Some(Event {
                    path_name,
                    associated,
                    timestamp: event.timestamp,
                    pid: event.pid,
                    path_type: event.path_type.into(),
                    effect_type: terminal_effect_type,
                })
            }
        }
    }

    #[cfg(feature = "ev-array")]
    fn continue_with(&mut self, event: &RawEvent) -> Option<Event> {
        match EffectType::from(event.effect_type) {
            EffectType::Association => {
                self.associated = Some(event.reordered_buf_to_string());
                None
            }
            terminal_effect_type => {
                let associated = match &self.associated {
                    Some(associated) => Some(associated.clone()),
                    None => None,
                };
                self.associated = None;
                Some(Event {
                    path_name: event.reordered_buf_to_string(),
                    associated,
                    timestamp: event.timestamp,
                    pid: event.pid,
                    path_type: event.path_type.into(),
                    effect_type: terminal_effect_type,
                })
            }
        }
    }
}

#[cfg(feature = "ev-ringbuf")]
pub(crate) fn accumulating_event_stream_proxy(
    tx: std::sync::mpsc::Sender<Event>,
) -> impl FnMut(&[u8]) -> i32 {
    let mut path_parsing_state = PartialPaths::new();
    move |data: &[u8]| {
        let event = match plain::from_bytes(data) {
            Ok(event) => event,
            // Big oops, unexpected event format, mismatch between BPF and Rust types
            Err(_) => return 1,
        };
        // Event paths may be sent in pieces. Accumulating them here...
        let event = path_parsing_state.continue_with(event);
        match event {
            // Holding back until we have something meaningful
            None => 0,
            // Sending them along when we do
            Some(complete_event) => {
                match tx.send(complete_event) {
                    Ok(_) => 0,
                    // If the receiver has not been dropped, of course.
                    Err(_) => 1,
                }
            }
        }
    }
}

#[cfg(feature = "ev-array")]
pub(crate) fn accumulating_event_stream_proxy(
    tx: std::sync::mpsc::Sender<Event>,
) -> impl FnMut(i32, &[u8]) -> () {
    let mut path_parsing_state = PartialPaths::new();
    move |_cpu: i32, event_as_bytes: &[u8]| {
        // Copying these bytes into an event ensures the correct alignment
        let mut event = crate::event::RawEvent::default();
        match plain::copy_from_bytes(&mut event, event_as_bytes) {
            Ok(_) => {
                if let Some(complete_event) = path_parsing_state.continue_with(&event) {
                    let _ = tx.send(complete_event);
                }
            }
            Err(e) => {
                log::error!("Error parsing bytes as an event: {:?}", e);
            }
        }
    }
}
