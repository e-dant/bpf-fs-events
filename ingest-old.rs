use crate::event::EffectType;
use crate::event::Event;
use crate::event::RawEvent;

#[derive(Clone, Copy)]
enum Continuation {
    Pending,
    Complete,
}

struct PathAcc {
    items: std::collections::VecDeque<String>
}

impl PathAcc {
    fn concat_items_to_path_name(&self) -> String {
        self.items.iter()
            .fold(String::with_capacity(256), |path_acc, next_part| {
                path_acc + "/" + &next_part
            })
    }
}

struct PartialPaths {
    path_names: PathAcc,
    associated: PathAcc,
    event_group_id: u16,
    state: Continuation,
}

impl PartialPaths {
    const fn new() -> Self {
        Self {
            path_names: PathAcc { items: std::collections::VecDeque::new() },
            associated: PathAcc { items: std::collections::VecDeque::new() },
            event_group_id: 0,
            state: Continuation::Pending,
        }
    }

    // If the group ID of the "next" event differs from whatever we stored
    // before, we'll clear out what we have and start a new group.
    // If the event is a continuation, we'll add the path_name to the list.
    // Unless the continuation event is the root directory and belongs to
    // the same group as the previous event. In that case, we're
    // associating the "next" path names with what we have stored.
    // (Such as rename to-and-from, or link to-and-from.)
    fn continue_with(&mut self, event: &RawEvent) -> Option<Event> {
        let groups_differ = event.event_group_id != self.event_group_id;
        if groups_differ {
            self.path_names.items.clear();
            self.associated.items.clear();
            self.event_group_id = event.event_group_id;
        }
        let effect_type = EffectType::from(event.effect_type);
        match effect_type {
            EffectType::Continuation => {
                let path_name = event.path_name_to_str();
                match self.associated.items.len() {
                    0 => self.path_names.items.push_front(path_name.to_string()),
                    _ => self.associated.items.push_front(path_name.to_string()),
                }
                self.state = Continuation::Pending;
                None
            }
            EffectType::Association => {
                self.associated.items.push_front("".to_string());
                self.state = Continuation::Pending;
                None
            }
            _ => {
                self.state = Continuation::Complete;
                let path_name = self.path_names.concat_items_to_path_name();
                let associated = match &self.associated.items.len() {
                    0 => None,
                    _ => Some(self.associated.concat_items_to_path_name()),
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
