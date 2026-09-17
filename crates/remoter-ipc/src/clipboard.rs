//! The system clipboard, for the terminal's copy and paste.
//!
//! Two selections, because Linux has two and a terminal there uses both:
//!
//! - **`clipboard`** is the one every platform has — what Ctrl+C / Cmd+C put
//!   there and Ctrl+V / Cmd+V take back.
//! - **`primary`** is the X11 and Wayland PRIMARY selection: whatever was last
//!   selected with the mouse, pasted with the middle button. Every native Linux
//!   terminal writes it on selection and reads it on middle-click, and a
//!   terminal that does not feels broken to the people who use one daily. It
//!   does not exist on Windows or macOS, where asking for it is answered with
//!   nothing rather than with an error — the frontend asks only on Linux, and a
//!   caller that asks elsewhere is owed "there is none", not a failure.
//!
//! **What crosses this boundary is the user's own clipboard text**, taken or
//! given at their explicit request — a paste, a copy, a selection. It is not a
//! vault secret and nothing here reads one; the rule that a decrypted secret
//! never reaches the frontend is untouched. Nothing is logged: a clipboard
//! routinely holds a password the user copied from elsewhere.
//!
//! **A graphical session reaches the same clipboard.** An RDP tab offers the
//! clipboard's text to the remote desktop through [`text_for_remote`] — the
//! text goes from here to the session, and never through the frontend — and
//! text copied on the remote desktop arrives through [`put_text_from_remote`].
//! Both are the user's own clipboard moving where they pointed it; what may
//! move is the connection's clipboard policy, enforced in the adapter.
//!
//! One `arboard::Clipboard` lives for the life of the process. On X11 and
//! Wayland the application *serves* what it copied — the text lives in this
//! process until another application takes ownership — and a handle created
//! and dropped per call can take the contents with it.

use parking_lot::Mutex;
use serde::Deserialize;

use crate::error::IpcError;

/// Which clipboard a request means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Selection {
    Clipboard,
    Primary,
}

/// The process's clipboard handle, opened on first use.
static CLIPBOARD: Mutex<Option<arboard::Clipboard>> = Mutex::new(None);

/// The most text one paste will carry, in bytes.
///
/// A clipboard can hold a whole log file. Pasting four megabytes into a remote
/// shell is almost never what was meant, and it arrives there as keystrokes;
/// the cap keeps an accident from becoming a flood.
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;

/// The clipboard's text, or `None` when it holds no text.
#[tauri::command]
pub(crate) fn clipboard_read_text(selection: Selection) -> Result<Option<String>, IpcError> {
    if selection == Selection::Primary && !has_primary() {
        return Ok(None);
    }
    with_clipboard(|clipboard| {
        let text = read(clipboard, selection);
        match text {
            Ok(text) => Ok(Some(text)),
            // Empty, or holding an image or files: nothing to paste, which is
            // not a failure of the clipboard.
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(err) => Err(err),
        }
    })
    .map(|text| text.filter(|text| !text.is_empty()))
    .and_then(|text| match text {
        Some(text) if text.len() > MAX_TEXT_BYTES => Err(IpcError::new(
            "clipboard.too-large",
            "The clipboard holds more text than a terminal paste will send. Nothing was pasted.",
        )
        .with_detail(format!(
            "{} bytes; the limit is {MAX_TEXT_BYTES}",
            text.len()
        ))
        .with_actions(["Copy a smaller part", "Transfer the file over SFTP instead"])),
        other => Ok(other),
    })
}

/// Puts text on the clipboard.
#[tauri::command]
pub(crate) fn clipboard_write_text(selection: Selection, text: String) -> Result<(), IpcError> {
    if selection == Selection::Primary && !has_primary() {
        return Ok(());
    }
    if text.is_empty() {
        return Ok(());
    }
    with_clipboard(|clipboard| write(clipboard, selection, text))
}

/// The clipboard's text, for offering to a remote session.
///
/// The same read, and the same bound, as a terminal paste: four megabytes is
/// also what the RDP adapter will announce.
pub(crate) fn text_for_remote() -> Result<Option<String>, IpcError> {
    clipboard_read_text(Selection::Clipboard)
}

/// Puts text a remote session copied onto the clipboard.
pub(crate) fn put_text_from_remote(text: String) -> Result<(), IpcError> {
    clipboard_write_text(
        Selection::Clipboard,
        local_line_endings(text, cfg!(windows)),
    )
}

/// A session hands text over with LF line endings. The Windows clipboard's
/// text is CRLF, and what reads it — Notepad on an older build, a form field in
/// a native application — shows LF alone as one long line.
fn local_line_endings(text: String, windows: bool) -> String {
    if windows {
        text.replace("\r\n", "\n").replace('\n', "\r\n")
    } else {
        text
    }
}

fn with_clipboard<T>(
    action: impl FnOnce(&mut arboard::Clipboard) -> Result<T, arboard::Error>,
) -> Result<T, IpcError> {
    let mut guard = CLIPBOARD.lock();
    if guard.is_none() {
        *guard = Some(arboard::Clipboard::new().map_err(unavailable)?);
    }
    // Opened just above when it was not already.
    let Some(clipboard) = guard.as_mut() else {
        return Err(unavailable(arboard::Error::ClipboardNotSupported));
    };
    action(clipboard).map_err(|err| {
        // A handle whose connection to the display server has gone — the
        // compositor restarted, the X server went away — stays broken. Dropping
        // it means the next copy opens a fresh one instead of failing forever.
        if matches!(
            err,
            arboard::Error::ClipboardNotSupported | arboard::Error::Unknown { .. }
        ) {
            *guard = None;
        }
        unavailable(err)
    })
}

fn unavailable(err: arboard::Error) -> IpcError {
    IpcError::new(
        "clipboard.unavailable",
        "The system clipboard could not be reached, so nothing was copied or pasted.",
    )
    .with_actions(["Try again"])
    // The kind of failure only, never the contents: `arboard::Error` carries no
    // clipboard text, and its description names the mechanism that failed.
    .with_detail(err.to_string())
}

const fn has_primary() -> bool {
    cfg!(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn read(
    clipboard: &mut arboard::Clipboard,
    selection: Selection,
) -> Result<String, arboard::Error> {
    use arboard::{GetExtLinux, LinuxClipboardKind};
    let kind = match selection {
        Selection::Clipboard => LinuxClipboardKind::Clipboard,
        Selection::Primary => LinuxClipboardKind::Primary,
    };
    clipboard.get().clipboard(kind).text()
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn read(
    clipboard: &mut arboard::Clipboard,
    _selection: Selection,
) -> Result<String, arboard::Error> {
    clipboard.get_text()
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn write(
    clipboard: &mut arboard::Clipboard,
    selection: Selection,
    text: String,
) -> Result<(), arboard::Error> {
    use arboard::{LinuxClipboardKind, SetExtLinux};
    let kind = match selection {
        Selection::Clipboard => LinuxClipboardKind::Clipboard,
        Selection::Primary => LinuxClipboardKind::Primary,
    };
    clipboard.set().clipboard(kind).text(text)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn write(
    clipboard: &mut arboard::Clipboard,
    _selection: Selection,
    text: String,
) -> Result<(), arboard::Error> {
    clipboard.set_text(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_primary_selection_is_answered_with_nothing_where_it_does_not_exist() {
        if has_primary() {
            return;
        }
        assert!(matches!(clipboard_read_text(Selection::Primary), Ok(None)));
        assert!(clipboard_write_text(Selection::Primary, String::from("x")).is_ok());
    }

    #[test]
    fn remote_text_gets_the_line_endings_of_the_clipboard_it_lands_on() {
        let text = String::from("one\ntwo\n");
        assert_eq!(local_line_endings(text.clone(), false), "one\ntwo\n");
        assert_eq!(local_line_endings(text, true), "one\r\ntwo\r\n");
        // Never doubled, whatever arrived.
        assert_eq!(local_line_endings(String::from("a\r\nb"), true), "a\r\nb");
    }

    #[test]
    fn a_selection_is_named_the_way_the_frontend_names_it() {
        let parsed: Result<Selection, _> = serde_json::from_str("\"primary\"");
        assert!(matches!(parsed, Ok(Selection::Primary)));
        let parsed: Result<Selection, _> = serde_json::from_str("\"clipboard\"");
        assert!(matches!(parsed, Ok(Selection::Clipboard)));
    }
}
