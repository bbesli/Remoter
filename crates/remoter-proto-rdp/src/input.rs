//! Turning [`InputEvent`]s into RDP input. MS-RDPBCGR §2.2.8.1.
//!
//! Everything here goes out on the **fast path** (§2.2.8.1.2) rather than the
//! slow path: it is the encoding every server since RDP 5.0 accepts, it has no
//! share header, and a keystroke that costs fewer bytes is a keystroke that
//! arrives sooner.
//!
//! # The scancode boundary
//!
//! [`InputEvent::Key`] carries a **PS/2 Set 1 make code** with the `E0` prefix
//! represented as bit 8 (`0x100`), which is exactly what
//! `MS-RDPBCGR §2.2.8.1.1.3.1.1.1` encodes as an 8-bit `keyCode` beside a
//! `KBDFLAGS_EXTENDED` flag. This module's whole keyboard job is that
//! translation and the lock-state synchronisation below.
//!
//! The mapping from a browser `KeyboardEvent.code` to a scancode belongs in the
//! frontend and stays there. `remoter_proto::InputEvent`'s documentation says
//! why at length; the short version is that `code` is the *physical* key and is
//! what a scancode means, `key` is what the layout produced and is what a VNC
//! keysym means, and `keyCode` is neither despite the name. Re-deriving any of
//! them in Rust would need the user's layout, which lives in the browser.
//!
//! **The server applies the layout.** The scancode says which key was struck;
//! the keyboard layout in the Client Core Data (MS-RDPBCGR §2.2.1.3.2) says
//! what Windows makes of it. A session connected with the wrong layout types
//! the wrong characters and nothing in this file can tell.
//!
//! # Lock states are not modifiers
//!
//! Caps Lock is a *latch*, and RDP synchronises latches explicitly with a
//! Client Synchronize Event (§2.2.8.1.1.3.1.1.5) rather than inferring them
//! from keystrokes. A session that never sends one types in the wrong case
//! until the user notices and presses the key twice — so this module sends one
//! whenever the lock state it is told about differs from the last one it sent.

use ironrdp::input::{Database, MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use ironrdp::pdu::input::fast_path::FastPathInputEvent;
use remoter_proto::{InputEvent, Modifiers, PointerButtons};

/// Bit 8 of [`InputEvent::Key::scancode`]: the `E0` prefix.
///
/// Right Control is `0x11d` and Left Control is `0x1d`; the two produce
/// different Windows virtual keys and a client that drops the bit makes the
/// right-hand modifiers behave as the left-hand ones.
const EXTENDED: u32 = 0x100;

/// One notch of a wheel, in RDP's `rotationUnits`
/// (MS-RDPBCGR §2.2.8.1.1.3.1.1.3). Matches `WHEEL_DELTA`, which is what every
/// mouse driver reports and what [`InputEvent::Pointer::wheel`] carries.
pub const WHEEL_DELTA: i16 = 120;

/// Encodes input, and remembers enough to undo it.
///
/// The state is not an optimisation. RDP input is a stream of *transitions* —
/// key down, key up, button down, button up — while [`InputEvent::Pointer`]
/// carries a full button state, because that is what RFB carries and the two
/// protocols share one event type. Diffing against the previous state is what
/// turns one into the other, and holding that state is also what makes
/// [`InputEncoder::release_all`] possible: a tab closed with Alt held must not
/// leave the remote session with Alt held.
pub struct InputEncoder {
    database: Database,
    buttons: PointerButtons,
    /// The lock states last synchronised, or `None` before the first event.
    locks: Option<Modifiers>,
}

impl Default for InputEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for InputEncoder {
    /// Hand-written and redacting. The database holds which keys are currently
    /// down, and "which keys are down" during a password prompt is the
    /// password, one bit at a time.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InputEncoder")
            .field("buttons", &self.buttons.bits())
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl InputEncoder {
    /// An encoder with nothing held.
    #[must_use]
    pub fn new() -> Self {
        Self {
            database: Database::new(),
            buttons: PointerButtons::NONE,
            locks: None,
        }
    }

    /// Encodes one event.
    ///
    /// Returns the fast-path events to send, in order. An event that produces
    /// nothing — a pointer update that moved nothing and pressed nothing —
    /// returns an empty vector rather than an error: the interface sends
    /// pointer state liberally and refusing a no-op would be noise.
    #[must_use]
    pub fn encode(&mut self, event: &InputEvent) -> Vec<FastPathInputEvent> {
        match event {
            // Terminal bytes have no meaning to a framebuffer protocol. The
            // interface should not send them to an RDP tab, and dropping them
            // is quieter than failing a working session over a routing
            // mistake elsewhere.
            InputEvent::Bytes(_) => Vec::new(),

            InputEvent::Key {
                scancode,
                modifiers,
                pressed,
                // The keysym is what a VNC session needs and what an RDP one
                // must not use: the server applies the layout, so sending a
                // character would be sending the layout twice.
                keysym: _,
            } => {
                let mut events = self.synchronise_locks(*modifiers);
                let code = to_scancode(*scancode);
                let operation = if *pressed {
                    Operation::KeyPressed(code)
                } else {
                    Operation::KeyReleased(code)
                };
                events.extend(self.database.apply(core::iter::once(operation)));
                events
            }

            InputEvent::Pointer {
                x,
                y,
                buttons,
                wheel,
                wheel_x,
            } => {
                let mut operations = vec![Operation::MouseMove(MousePosition { x: *x, y: *y })];
                operations.extend(self.button_transitions(*buttons));
                // A wheel notch is a rotation, not a button, and the two axes
                // are separate events: a tilt wheel is a different axis, not a
                // different sign.
                if *wheel != 0 {
                    operations.push(Operation::WheelRotations(WheelRotations {
                        is_vertical: true,
                        rotation_units: *wheel,
                    }));
                }
                if *wheel_x != 0 {
                    operations.push(Operation::WheelRotations(WheelRotations {
                        is_vertical: false,
                        rotation_units: *wheel_x,
                    }));
                }
                self.database.apply(operations).into_iter().collect()
            }
        }
    }

    /// Releases everything currently held.
    ///
    /// Sent before a clean disconnect. A tab closed while Alt is down leaves
    /// the *server* believing Alt is down, and the next session inherits it —
    /// which looks like a broken keyboard and is nothing of the kind.
    #[must_use]
    pub fn release_all(&mut self) -> Vec<FastPathInputEvent> {
        self.buttons = PointerButtons::NONE;
        self.database.release_all().into_iter().collect()
    }

    /// A Client Synchronize Event, if the lock states changed.
    ///
    /// MS-RDPBCGR §2.2.8.1.1.3.1.1.5. Sent before the keystroke it accompanies
    /// so that the server has the right latch state when it interprets it.
    fn synchronise_locks(&mut self, modifiers: Modifiers) -> Vec<FastPathInputEvent> {
        let locks = Modifiers::CAPS_LOCK
            .with(Modifiers::NUM_LOCK)
            .with(Modifiers::SCROLL_LOCK);
        let current = Modifiers(modifiers.bits() & locks.bits());
        if self.locks == Some(current) {
            return Vec::new();
        }
        self.locks = Some(current);
        vec![ironrdp::input::synchronize_event(
            current.contains(Modifiers::SCROLL_LOCK),
            current.contains(Modifiers::NUM_LOCK),
            current.contains(Modifiers::CAPS_LOCK),
            // Kana lock has no representation in `Modifiers` and no key on a
            // keyboard outside Japan. Reporting it as off is what every
            // non-Japanese client does.
            false,
        )]
    }

    /// The press and release operations that take the pointer from its last
    /// known button state to `next`.
    fn button_transitions(&mut self, next: PointerButtons) -> Vec<Operation> {
        const BUTTONS: [(PointerButtons, MouseButton); 5] = [
            (PointerButtons::LEFT, MouseButton::Left),
            (PointerButtons::RIGHT, MouseButton::Right),
            (PointerButtons::MIDDLE, MouseButton::Middle),
            // `PTRXFLAGS_BUTTON1` and `PTRXFLAGS_BUTTON2` of
            // MS-RDPBCGR §2.2.8.1.1.3.1.1.4 — "back" and "forward" on a mouse.
            (PointerButtons::BACK, MouseButton::X1),
            (PointerButtons::FORWARD, MouseButton::X2),
        ];

        let mut operations = Vec::new();
        for (bit, button) in BUTTONS {
            let was = self.buttons.contains(bit);
            let is = next.contains(bit);
            match (was, is) {
                (false, true) => operations.push(Operation::MouseButtonPressed(button)),
                (true, false) => operations.push(Operation::MouseButtonReleased(button)),
                _ => {}
            }
        }
        self.buttons = next;
        operations
    }
}

/// Splits the `E0` prefix out of a Set 1 scancode.
///
/// [`InputEvent::Key`] carries the prefix as bit 8; RDP carries it as
/// `KBDFLAGS_EXTENDED` beside an 8-bit code (MS-RDPBCGR §2.2.8.1.1.3.1.1.1).
/// Anything above bit 8 is discarded: no Set 1 make code is wider, and a value
/// that is would otherwise wrap into a different key.
#[must_use]
pub fn to_scancode(scancode: u32) -> Scancode {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the mask keeps only the low byte, which is the whole make code"
    )]
    let code = (scancode & 0xff) as u8;
    Scancode::from_u8(scancode & EXTENDED != 0, code)
}

/// `Modifiers` has no public constructor from raw bits, so the lock mask is
/// rebuilt through the constants. A thin newtype-local helper rather than a
/// change to `remoter-proto`, which would be the wrong crate to widen for
/// this.
#[allow(non_snake_case, reason = "reads as a constructor for the shared type")]
fn Modifiers(bits: u8) -> Modifiers {
    let mut out = remoter_proto::Modifiers::NONE;
    for flag in [
        remoter_proto::Modifiers::CAPS_LOCK,
        remoter_proto::Modifiers::NUM_LOCK,
        remoter_proto::Modifiers::SCROLL_LOCK,
    ] {
        if bits & flag.bits() != 0 {
            out = out.with(flag);
        }
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code, per the workspace convention"
)]
mod tests {
    use super::*;
    use ironrdp::pdu::input::fast_path::{KeyboardFlags, SynchronizeFlags};
    use ironrdp::pdu::input::mouse::PointerFlags;

    fn key(scancode: u32, pressed: bool, modifiers: Modifiers) -> InputEvent {
        InputEvent::Key {
            scancode,
            keysym: None,
            modifiers,
            pressed,
        }
    }

    fn pointer(x: u16, y: u16, buttons: PointerButtons, wheel: i16, wheel_x: i16) -> InputEvent {
        InputEvent::Pointer {
            x,
            y,
            buttons,
            wheel,
            wheel_x,
        }
    }

    #[test]
    fn the_extended_bit_separates_the_right_hand_modifiers_from_the_left() {
        // Left Control is 0x1d; Right Control is the same make code with an
        // E0 prefix. A client that drops the prefix makes the right-hand
        // modifiers behave as the left-hand ones, which breaks AltGr on every
        // non-US layout.
        let left = to_scancode(0x1d);
        assert_eq!(left.as_u8(), (false, 0x1d));
        let right = to_scancode(0x11d);
        assert_eq!(right.as_u8(), (true, 0x1d));
        assert_ne!(left, right);

        // Right Alt — AltGr — is E0 38.
        assert_eq!(to_scancode(0x138).as_u8(), (true, 0x38));
        // And a value wider than a make code cannot wrap into another key.
        assert_eq!(to_scancode(0xffff_ff1d).as_u8(), (true, 0x1d));
    }

    #[test]
    fn a_keypress_becomes_a_make_code_and_a_release_becomes_a_break() {
        let mut encoder = InputEncoder::new();
        // The first event also carries the lock synchronisation, which is
        // asserted separately below.
        let events = encoder.encode(&key(0x1e, true, Modifiers::NONE));
        let scancodes: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                FastPathInputEvent::KeyboardEvent(flags, code) => Some((*flags, *code)),
                _ => None,
            })
            .collect();
        assert_eq!(scancodes, vec![(KeyboardFlags::empty(), 0x1e)]);

        let events = encoder.encode(&key(0x1e, false, Modifiers::NONE));
        let scancodes: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                FastPathInputEvent::KeyboardEvent(flags, code) => Some((*flags, *code)),
                _ => None,
            })
            .collect();
        assert_eq!(scancodes, vec![(KeyboardFlags::RELEASE, 0x1e)]);
    }

    #[test]
    fn the_lock_states_are_synchronised_when_they_change_and_not_otherwise() {
        // A session that never synchronises types in the wrong case until the
        // user notices; one that synchronises on every keystroke doubles the
        // input traffic.
        let mut encoder = InputEncoder::new();

        let first = encoder.encode(&key(0x1e, true, Modifiers::CAPS_LOCK));
        let sync: Vec<_> = first
            .iter()
            .filter_map(|event| match event {
                FastPathInputEvent::SyncEvent(flags) => Some(*flags),
                _ => None,
            })
            .collect();
        assert_eq!(sync, vec![SynchronizeFlags::CAPS_LOCK]);

        // Same lock state: no second synchronisation.
        let second = encoder.encode(&key(0x1f, true, Modifiers::CAPS_LOCK));
        assert!(
            !second
                .iter()
                .any(|event| matches!(event, FastPathInputEvent::SyncEvent(_)))
        );

        // A held Shift is not a latch and must not trigger one.
        let third = encoder.encode(&key(
            0x20,
            true,
            Modifiers::CAPS_LOCK.with(Modifiers::SHIFT),
        ));
        assert!(
            !third
                .iter()
                .any(|event| matches!(event, FastPathInputEvent::SyncEvent(_)))
        );

        // Turning Caps Lock off is a change and is synchronised.
        let fourth = encoder.encode(&key(0x21, true, Modifiers::NUM_LOCK));
        let sync: Vec<_> = fourth
            .iter()
            .filter_map(|event| match event {
                FastPathInputEvent::SyncEvent(flags) => Some(*flags),
                _ => None,
            })
            .collect();
        assert_eq!(sync, vec![SynchronizeFlags::NUM_LOCK]);
    }

    #[test]
    fn a_full_button_state_becomes_press_and_release_transitions() {
        // The event type carries a full state because RFB does; RDP wants
        // transitions. Diffing is what turns one into the other, and a client
        // that sends a press per event leaves buttons stuck down.
        let mut encoder = InputEncoder::new();

        let pressed = encoder.encode(&pointer(10, 20, PointerButtons::LEFT, 0, 0));
        let flags: Vec<_> = pressed
            .iter()
            .filter_map(|event| match event {
                FastPathInputEvent::MouseEvent(mouse) => Some(mouse.flags),
                _ => None,
            })
            .collect();
        assert!(
            flags
                .iter()
                .any(|f| f.contains(PointerFlags::LEFT_BUTTON) && f.contains(PointerFlags::DOWN))
        );

        // Still held: a move, and no second press.
        let moved = encoder.encode(&pointer(30, 40, PointerButtons::LEFT, 0, 0));
        assert!(
            !moved
                .iter()
                .filter_map(|event| match event {
                    FastPathInputEvent::MouseEvent(mouse) => Some(mouse.flags),
                    _ => None,
                })
                .any(|f| f.contains(PointerFlags::DOWN))
        );

        let released = encoder.encode(&pointer(30, 40, PointerButtons::NONE, 0, 0));
        assert!(
            released
                .iter()
                .filter_map(|event| match event {
                    FastPathInputEvent::MouseEvent(mouse) => Some(mouse.flags),
                    _ => None,
                })
                .any(|f| f.contains(PointerFlags::LEFT_BUTTON) && !f.contains(PointerFlags::DOWN))
        );
    }

    #[test]
    fn the_extra_buttons_travel_as_the_extended_pointer_event() {
        // MS-RDPBCGR §2.2.8.1.1.3.1.1.4. "Back" and "forward" are not the
        // first three buttons and have their own PDU.
        let mut encoder = InputEncoder::new();
        let events = encoder.encode(&pointer(0, 0, PointerButtons::BACK, 0, 0));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, FastPathInputEvent::MouseEventEx(_))),
            "the back button must use the extended pointer event: {events:?}"
        );
    }

    #[test]
    fn the_two_wheel_axes_produce_two_different_events() {
        let mut encoder = InputEncoder::new();
        let events = encoder.encode(&pointer(0, 0, PointerButtons::NONE, WHEEL_DELTA, 0));
        let vertical: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                FastPathInputEvent::MouseEvent(mouse) => Some(mouse.flags),
                _ => None,
            })
            .filter(|flags| flags.contains(PointerFlags::VERTICAL_WHEEL))
            .collect();
        assert_eq!(vertical.len(), 1, "{events:?}");

        let events = encoder.encode(&pointer(0, 0, PointerButtons::NONE, 0, -WHEEL_DELTA));
        let horizontal: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                FastPathInputEvent::MouseEvent(mouse) => Some(mouse.flags),
                _ => None,
            })
            .filter(|flags| flags.contains(PointerFlags::HORIZONTAL_WHEEL))
            .collect();
        assert_eq!(horizontal.len(), 1, "{events:?}");
    }

    #[test]
    fn closing_a_tab_with_a_key_held_releases_it() {
        // Otherwise the *server* still believes the key is down, and the next
        // session inherits it. It looks like a broken keyboard and is not one.
        let mut encoder = InputEncoder::new();
        let _ = encoder.encode(&key(0x38, true, Modifiers::NONE)); // Left Alt
        let _ = encoder.encode(&pointer(0, 0, PointerButtons::LEFT, 0, 0));

        let released = encoder.release_all();
        assert!(
            released.iter().any(|event| matches!(
                event,
                FastPathInputEvent::KeyboardEvent(flags, 0x38) if flags.contains(KeyboardFlags::RELEASE)
            )),
            "{released:?}"
        );
        assert!(
            released
                .iter()
                .any(|event| matches!(event, FastPathInputEvent::MouseEvent(_))),
            "{released:?}"
        );
        // And nothing is left to release.
        assert!(encoder.release_all().is_empty());
    }

    #[test]
    fn terminal_bytes_are_dropped_rather_than_failing_the_session() {
        let mut encoder = InputEncoder::new();
        assert!(
            encoder
                .encode(&InputEvent::Bytes(bytes::Bytes::from_static(b"ls\n")))
                .is_empty()
        );
    }

    #[test]
    fn the_encoder_never_debug_prints_which_keys_are_held() {
        // "Which keys are down" during a password prompt is the password, one
        // bit at a time.
        let mut encoder = InputEncoder::new();
        let _ = encoder.encode(&key(0x23, true, Modifiers::NONE));
        let rendered = format!("{encoder:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("0x23"), "{rendered}");
    }
}
