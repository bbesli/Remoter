//! Turning pointer movement, buttons and a wheel into RFB `PointerEvent`s.
//!
//! RFC 6143 §7.5.5 is a small message and a surprising amount of translation.
//! It carries an absolute position and a `button-mask` of eight bits, "with
//! bit 0 being button 1", and it has **no notion of a wheel at all**: a wheel
//! notch is a press and release of button 4 or 5, which is what X11 has always
//! done and what every VNC server therefore expects.
//!
//! # The button order is X11's, not the mouse's
//!
//! Bit 0 is button 1, the left button. Bit 1 is button 2, which in X11 is the
//! **middle** button, not the right one. Bit 2 is button 3, the right button.
//! Getting this wrong produces a session where right-click pastes the primary
//! selection, which is a bug that survives a lot of testing because it looks
//! like a remote-desktop quirk rather than a wrong constant.
//!
//! # Back and forward have nowhere to go
//!
//! [`remoter_proto::PointerButtons`] carries them because RDP does
//! (MS-RDPBCGR §2.2.8.1.1.3.1.1.4, `PTRXFLAGS_BUTTON1` and `2`). RFB's eight
//! bits are buttons 1 to 8, and 4 to 7 are already the wheel — leaving button 8
//! as the only spare, with no agreement anywhere about what it means. There is
//! a community extension that widens the mask, and it is not implemented by
//! `vnc-rs`. So the two buttons are **dropped**, deliberately and visibly,
//! rather than aimed at a bit and hoped for.

use remoter_proto::PointerButtons;

/// Button 1, the left button (RFC 6143 §7.5.5).
pub const BUTTON_LEFT: u8 = 1 << 0;
/// Button 2, which in X11 is the **middle** button.
pub const BUTTON_MIDDLE: u8 = 1 << 1;
/// Button 3, the right button.
pub const BUTTON_RIGHT: u8 = 1 << 2;
/// Button 4: one wheel notch away from the user.
pub const BUTTON_WHEEL_UP: u8 = 1 << 3;
/// Button 5: one wheel notch towards the user.
pub const BUTTON_WHEEL_DOWN: u8 = 1 << 4;
/// Button 6: one notch of a tilt wheel to the left.
pub const BUTTON_WHEEL_LEFT: u8 = 1 << 5;
/// Button 7: one notch of a tilt wheel to the right.
pub const BUTTON_WHEEL_RIGHT: u8 = 1 << 6;

/// One wheel notch, in the units [`remoter_proto::InputEvent::Pointer`] uses.
///
/// 120 is `WHEEL_DELTA`: what every mouse driver reports for one detent, and
/// what RDP's `rotationUnits` carries (MS-RDPBCGR §2.2.8.1.1.3.1.1.3). The
/// finer number is carried through the input event precisely so that this
/// module can divide rather than having to guess.
pub const WHEEL_NOTCH: i32 = 120;

/// The most notches one input event may be turned into.
///
/// A trackpad flick can report several thousand units at once, and each notch
/// becomes two RFB messages. Without a ceiling one gesture would put hundreds
/// of messages into a bounded channel and stall the session behind its own
/// scroll. Sixteen notches is more than any real scroll wheel produces in one
/// report and is still a page or two of movement.
pub const MAX_NOTCHES_PER_EVENT: i32 = 16;

/// The `button-mask` for the buttons currently held.
///
/// Back and forward are not represented; see the module documentation.
#[must_use]
pub fn button_mask(buttons: PointerButtons) -> u8 {
    let mut mask = 0;
    if buttons.contains(PointerButtons::LEFT) {
        mask |= BUTTON_LEFT;
    }
    if buttons.contains(PointerButtons::MIDDLE) {
        mask |= BUTTON_MIDDLE;
    }
    if buttons.contains(PointerButtons::RIGHT) {
        mask |= BUTTON_RIGHT;
    }
    mask
}

/// Whether any button in `buttons` has no RFB encoding.
///
/// Used to log the drop once rather than silently doing nothing: a user whose
/// browser back button does nothing in a VNC tab should be able to find out
/// why from a debug log rather than from the source.
#[must_use]
pub fn has_unencodable_button(buttons: PointerButtons) -> bool {
    buttons.contains(PointerButtons::BACK) || buttons.contains(PointerButtons::FORWARD)
}

/// Accumulates sub-notch wheel movement until it amounts to a notch.
///
/// A high-resolution wheel or a trackpad reports a fraction of a notch per
/// event — 8 units, 13 units — and integer division alone would round every one
/// of them to zero, so the page would never scroll. Keeping the remainder is
/// what makes a slow scroll work at all, and it is why this is a struct with
/// state rather than a function.
#[derive(Debug, Clone, Copy, Default)]
pub struct WheelAccumulator {
    vertical: i32,
    horizontal: i32,
}

impl WheelAccumulator {
    /// A fresh accumulator with nothing carried over.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            vertical: 0,
            horizontal: 0,
        }
    }

    /// Folds in one event's deltas and returns the whole notches to send.
    ///
    /// The first value is vertical, positive away from the user; the second is
    /// horizontal, positive to the right. Both are clamped to
    /// [`MAX_NOTCHES_PER_EVENT`], and the clamped-away remainder is
    /// **discarded** rather than carried: a flick that overflows the ceiling is
    /// a gesture the user wanted to end, and paying it out over the next
    /// several events would make the desktop keep scrolling after they stopped.
    pub fn push(&mut self, wheel: i16, wheel_x: i16) -> (i32, i32) {
        let vertical = Self::drain(&mut self.vertical, wheel);
        let horizontal = Self::drain(&mut self.horizontal, wheel_x);
        (vertical, horizontal)
    }

    fn drain(carried: &mut i32, delta: i16) -> i32 {
        *carried = carried.saturating_add(i32::from(delta));
        let whole = *carried / WHEEL_NOTCH;
        let notches = whole.clamp(-MAX_NOTCHES_PER_EVENT, MAX_NOTCHES_PER_EVENT);
        if notches == 0 {
            return 0;
        }
        if whole == notches {
            // Only the notches actually emitted are taken out of the carry, so
            // a partial notch survives into the next event. `saturating_mul`
            // cannot overflow here — the product is at most 16 * 120 — and is
            // written that way so a future change to the ceiling cannot wrap.
            *carried -= notches.saturating_mul(WHEEL_NOTCH);
        } else {
            // The gesture overflowed the ceiling. Paying the rest out over the
            // following events would make the desktop keep scrolling after the
            // user stopped, so it is dropped with the flick that caused it.
            *carried = 0;
        }
        notches
    }

    /// The masks to send for one event's wheel movement, in order.
    ///
    /// RFC 6143 §7.5.5 has no wheel: a notch is a *press and release* of the
    /// wheel button, so each notch is two messages, and the button bit is
    /// combined with whatever buttons are genuinely held — dragging while
    /// scrolling is a thing people do.
    pub fn notch_masks(&mut self, held: u8, wheel: i16, wheel_x: i16) -> Vec<u8> {
        let (vertical, horizontal) = self.push(wheel, wheel_x);
        let mut masks = Vec::new();
        let mut emit = |bit: u8, count: i32| {
            for _ in 0..count {
                masks.push(held | bit);
                masks.push(held);
            }
        };
        emit(BUTTON_WHEEL_UP, vertical.max(0));
        emit(BUTTON_WHEEL_DOWN, (-vertical).max(0));
        emit(BUTTON_WHEEL_RIGHT, horizontal.max(0));
        emit(BUTTON_WHEEL_LEFT, (-horizontal).max(0));
        masks
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]
mod tests {
    use super::*;

    #[test]
    fn the_middle_button_is_bit_one_because_x11_says_so() {
        // Swapping bits 1 and 2 produces a session where right-click pastes
        // the primary selection, which looks like a remote-desktop quirk
        // rather than a wrong constant.
        assert_eq!(button_mask(PointerButtons::LEFT), 0b0000_0001);
        assert_eq!(button_mask(PointerButtons::MIDDLE), 0b0000_0010);
        assert_eq!(button_mask(PointerButtons::RIGHT), 0b0000_0100);
    }

    #[test]
    fn several_buttons_held_at_once_are_one_mask_not_a_transition() {
        let held = PointerButtons::LEFT.with(PointerButtons::RIGHT);
        assert_eq!(button_mask(held), 0b0000_0101);
        assert_eq!(button_mask(PointerButtons::NONE), 0);
    }

    #[test]
    fn back_and_forward_are_dropped_rather_than_aimed_at_a_spare_bit() {
        let extra = PointerButtons::BACK.with(PointerButtons::FORWARD);
        assert_eq!(button_mask(extra), 0, "RFB has nowhere to put them");
        assert!(has_unencodable_button(extra));
        assert!(!has_unencodable_button(PointerButtons::LEFT));
        // And they do not disturb the buttons that do have an encoding.
        assert_eq!(
            button_mask(PointerButtons::LEFT.with(PointerButtons::BACK)),
            BUTTON_LEFT
        );
    }

    #[test]
    fn one_notch_is_a_press_and_a_release() {
        let mut wheel = WheelAccumulator::new();
        assert_eq!(
            wheel.notch_masks(0, 120, 0),
            vec![BUTTON_WHEEL_UP, 0],
            "button 4 down, then up"
        );
        assert_eq!(
            wheel.notch_masks(0, -120, 0),
            vec![BUTTON_WHEEL_DOWN, 0],
            "button 5 down, then up"
        );
    }

    #[test]
    fn a_sub_notch_delta_is_carried_rather_than_rounded_to_nothing() {
        // A high-resolution wheel reports 8 or 13 units at a time. Integer
        // division alone would round every one of them away and the page would
        // never move.
        let mut wheel = WheelAccumulator::new();
        for _ in 0..14 {
            assert!(wheel.notch_masks(0, 8, 0).is_empty());
        }
        // 15 * 8 = 120, exactly one notch.
        assert_eq!(wheel.notch_masks(0, 8, 0), vec![BUTTON_WHEEL_UP, 0]);
        // And the carry restarts from zero rather than from a stale remainder.
        assert!(wheel.notch_masks(0, 8, 0).is_empty());
    }

    #[test]
    fn the_two_axes_carry_independently() {
        let mut wheel = WheelAccumulator::new();
        assert!(wheel.notch_masks(0, 60, 60).is_empty());
        // Each axis has half a notch; neither has a whole one.
        let masks = wheel.notch_masks(0, 60, 0);
        assert_eq!(masks, vec![BUTTON_WHEEL_UP, 0], "the vertical axis alone");
        let masks = wheel.notch_masks(0, 0, 60);
        assert_eq!(
            masks,
            vec![BUTTON_WHEEL_RIGHT, 0],
            "the horizontal axis kept its own remainder"
        );
    }

    #[test]
    fn a_tilt_wheel_uses_buttons_six_and_seven() {
        let mut wheel = WheelAccumulator::new();
        assert_eq!(
            wheel.notch_masks(0, 0, 120),
            vec![BUTTON_WHEEL_RIGHT, 0],
            "positive is to the right"
        );
        assert_eq!(wheel.notch_masks(0, 0, -120), vec![BUTTON_WHEEL_LEFT, 0]);
    }

    #[test]
    fn buttons_held_while_scrolling_stay_held() {
        // Dragging a selection while the wheel moves is a thing people do, and
        // dropping the held button mid-drag ends the drag.
        let mut wheel = WheelAccumulator::new();
        assert_eq!(
            wheel.notch_masks(BUTTON_LEFT, 120, 0),
            vec![BUTTON_LEFT | BUTTON_WHEEL_UP, BUTTON_LEFT]
        );
    }

    #[test]
    fn a_flick_is_capped_and_the_overflow_is_not_paid_out_later() {
        // A trackpad flick can report thousands of units. Each notch is two
        // messages into a bounded channel, so an uncapped burst stalls the
        // session behind its own scroll — and carrying the remainder would
        // make the desktop keep scrolling after the user stopped.
        let mut wheel = WheelAccumulator::new();
        let masks = wheel.notch_masks(0, i16::MAX, 0);
        assert_eq!(
            masks.len(),
            usize::try_from(MAX_NOTCHES_PER_EVENT).unwrap() * 2
        );
        let after = wheel.notch_masks(0, 0, 0);
        assert!(
            after.is_empty(),
            "the clamped remainder is discarded, not queued"
        );
    }

    #[test]
    fn a_zero_delta_produces_no_messages_at_all() {
        // Pointer movement with no wheel is the overwhelmingly common event;
        // it must not cost two messages.
        let mut wheel = WheelAccumulator::new();
        assert!(wheel.notch_masks(BUTTON_LEFT, 0, 0).is_empty());
    }
}
