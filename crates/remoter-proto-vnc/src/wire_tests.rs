//! The adapter, driven against a scripted RFB server over an in-memory pipe.
//!
//! # What these tests are for
//!
//! The unit tests beside each module check one function. These check the thing
//! the user actually gets: a handshake completed, a desktop drawn, a key typed.
//! Every one of them runs the real `vnc-rs` engine over a
//! `tokio::io::duplex` pair with bytes written by hand from RFC 6143, so there
//! is no fixture container, no port and no network — and, incidentally, no way
//! for them to pass if this crate ever opened a connection of its own.
//!
//! # The decoders are given hostile input on purpose
//!
//! Each encoding gets a well-formed rectangle *and* a malformed one, because a
//! framebuffer update is the most dangerous input in the application
//! (`docs/security/threat-model.md` §T4) and "it renders my desktop" says
//! nothing about what a compromised host can do with it.
//!
//! Two of these tests make `vnc-rs` panic. That is the finding, not the test
//! failing: the library's decoders are not bounds-checked, and what these prove
//! is the containment ADR-0011 promises — the panic happens inside a task the
//! *library* spawned, the session ends, and the process carries on. The panic
//! message on stderr during a test run is expected.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::collections::BTreeMap;
use std::time::Duration;

use remoter_core::{
    EffectiveConnection, GatewayChain, NodeId, ProtocolId, Provenance, ReconnectPolicy,
    RecordingPolicy, Resolved,
};
use remoter_proto::{
    ClipboardData, ClipboardOp, CloseReason, CredentialKind, CredentialProvider, FrameEncoding,
    FrameMessage, HostPort, InputEvent, KeyBorrow, PointerButtons, ProtocolError, SessionCommand,
    SessionContext, SessionEvent, SessionId, SessionWarning, event_channel,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::encoding::RfbEncoding;
use crate::protocol::{VncProtocol, WARNING_PASSWORD_TRUNCATED, WEAK_ALGORITHM_VNC_AUTH};
use crate::session::run_vnc_session;
use crate::testing::{PipeTransport, RfbServer, Security, transport_pair, tunnelled_pair};

/// No test may hang. A deadlock in the session loop would otherwise show up as
/// a CI job that never finishes rather than as a failure with a name.
const PATIENCE: Duration = Duration::from_secs(5);

const WIDTH: u16 = 64;
const HEIGHT: u16 = 32;

// --- fixtures ---------------------------------------------------------------

struct Password(&'static [u8]);

impl CredentialProvider for Password {
    fn username(&self) -> Option<&str> {
        None
    }
    fn kind(&self) -> CredentialKind {
        CredentialKind::Password
    }
    fn borrow_password(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        f(self.0);
        true
    }
    fn borrow_private_key(&self, _f: &mut KeyBorrow<'_>) -> bool {
        false
    }
}

struct NoCredential;

impl CredentialProvider for NoCredential {
    fn username(&self) -> Option<&str> {
        None
    }
    fn kind(&self) -> CredentialKind {
        CredentialKind::None
    }
    fn borrow_password(&self, _f: &mut dyn FnMut(&[u8])) -> bool {
        false
    }
    fn borrow_private_key(&self, _f: &mut KeyBorrow<'_>) -> bool {
        false
    }
}

fn root<T>(value: T) -> Resolved<T> {
    Resolved::new(value, Provenance::DefaultAtRoot)
}

/// A resolved connection to loopback, so no clear-text warning is raised and
/// the events under test are the only ones on the channel.
fn connection(settings: &[(&str, &str)]) -> EffectiveConnection {
    EffectiveConnection {
        node: NodeId::new(),
        name: "desktop".to_owned(),
        protocol: ProtocolId::new("vnc").unwrap(),
        host: "127.0.0.1".to_owned(),
        port: root(Some(5900)),
        credential: root(None),
        username: root(None),
        credential_attached: false,
        gateway: root(GatewayChain::direct()),
        connect_timeout_ms: root(Some(5_000)),
        keepalive_secs: root(None),
        settings: settings
            .iter()
            .map(|(key, value)| ((*key).to_owned(), root((*value).to_owned())))
            .collect::<BTreeMap<_, _>>(),
        on_connect: root(Vec::new()),
        on_disconnect: root(Vec::new()),
        recording: root(RecordingPolicy::Never),
        auto_reconnect: root(ReconnectPolicy::Never),
        icon: root(None),
        colour: root(None),
    }
}

fn target() -> HostPort {
    HostPort::new("127.0.0.1", 5900).unwrap()
}

/// A running session, and everything a test needs to poke at it.
struct Live {
    server: RfbServer,
    events: mpsc::Receiver<SessionEvent>,
    commands: mpsc::Sender<SessionCommand>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<Result<CloseReason, ProtocolError>>,
    /// The encoding numbers the client actually promised in `SetEncodings`.
    offered_encodings: Vec<i32>,
}

impl Live {
    /// Waits for the session task to finish and reports why it ended.
    async fn finish(self) -> CloseReason {
        // Dropping the command sender is what a closed tab looks like from the
        // supervisor's side when nothing cancelled the token.
        drop(self.commands);
        self.cancel.cancel();
        tokio::time::timeout(PATIENCE, self.task)
            .await
            .expect("the session task must stop when its token is cancelled")
            .expect("the session task must not panic")
            .expect("the session loop folds failures into a close reason")
    }
}

/// Brings up a session over a pipe and leaves both ends usable.
async fn live(
    transport: PipeTransport,
    server: RfbServer,
    security: Security,
    creds: &dyn CredentialProvider,
    settings: &[(&str, &str)],
) -> Result<Live, ProtocolError> {
    let handshake = tokio::spawn(async move {
        let mut server = server;
        let auth = server.handshake(security).await.expect("handshake");
        let encodings = server.initialise(WIDTH, HEIGHT).await.expect("ServerInit");
        (server, encodings, auth)
    });

    let (sink, events) = event_channel(256);
    let cancel = CancellationToken::new();
    let protocol = VncProtocol::new()?;
    let session = tokio::time::timeout(
        PATIENCE,
        protocol.connect_session(
            Box::new(transport),
            &connection(settings),
            creds,
            sink.clone(),
            cancel.clone(),
        ),
    )
    .await
    .expect("the handshake must not hang")?;

    let (server, offered_encodings, _auth) =
        handshake.await.expect("the server script must finish");

    let (commands, receiver) = mpsc::channel(16);
    let ctx = SessionContext {
        id: SessionId::from_raw(7),
        cancel: cancel.clone(),
        events: sink,
        commands: receiver,
    };
    let task = tokio::spawn(run_vnc_session(session, ctx));

    Ok(Live {
        server,
        events,
        commands,
        cancel,
        task,
        offered_encodings,
    })
}

/// The next framebuffer or cursor message, skipping control events.
async fn next_frame(events: &mut mpsc::Receiver<SessionEvent>) -> FrameMessage {
    tokio::time::timeout(PATIENCE, async {
        while let Some(event) = events.recv().await {
            if let SessionEvent::Data(bytes) = event {
                return FrameMessage::decode(&bytes)
                    .expect("the adapter must emit a well-formed frame message")
                    .1;
            }
        }
        panic!("the event stream ended before a frame arrived");
    })
    .await
    .expect("a frame must arrive")
}

/// The next control event of a kind the test cares about.
async fn next_matching<T>(
    events: &mut mpsc::Receiver<SessionEvent>,
    mut pick: impl FnMut(SessionEvent) -> Option<T>,
) -> T {
    tokio::time::timeout(PATIENCE, async {
        while let Some(event) = events.recv().await {
            if let Some(found) = pick(event) {
                return found;
            }
        }
        panic!("the event stream ended before the event under test arrived");
    })
    .await
    .expect("the event under test must arrive")
}

/// One raw rectangle's worth of pixels, in the BGRX the adapter asks for.
fn raw_pixels(width: u16, height: u16, seed: u8) -> Vec<u8> {
    (0..usize::from(width) * usize::from(height) * 4)
        .map(|index| seed.wrapping_add(u8::try_from(index % 251).unwrap_or(0)))
        .collect()
}

// --- the session end to end -------------------------------------------------

#[tokio::test]
async fn a_desktop_is_drawn_over_a_transport_that_is_not_a_socket() {
    // The whole point of ADR-0003, exercised: an in-memory pipe is a
    // `Transport`, and the adapter cannot tell.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("a server offering None authentication connects");

    let pixels = raw_pixels(4, 4, 0x10);
    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(8, 8, 4, 4, RfbEncoding::RAW.to_wire())
        .await
        .unwrap();
    live.server.write(&pixels).await.unwrap();

    let FrameMessage::Framebuffer(update) = next_frame(&mut live.events).await else {
        panic!("a raw rectangle is a framebuffer message");
    };
    assert_eq!(update.rects.len(), 1);
    let rect = &update.rects[0];
    assert_eq!(rect.rect, remoter_proto::Rect::new(8, 8, 4, 4));
    assert_eq!(rect.encoding, FrameEncoding::Raw);
    assert_eq!(rect.payload().as_ref(), &pixels[..]);

    assert_eq!(live.finish().await, CloseReason::ClosedByUser);
}

#[tokio::test]
async fn a_tunnelled_session_needs_no_code_in_this_crate() {
    // "Secure this with SSH" is built entirely above this layer. The only thing
    // that changes here is that the clear-text warning is not raised — the
    // pixels, the handshake and the decoders are the same code path.
    let (transport, server) = tunnelled_pair(
        HostPort::new("desktop.internal", 5900).unwrap(),
        vec!["bastion-1".to_owned(), "bastion-2".to_owned()],
    );
    let mut live = live(
        transport,
        server,
        Security::VncAuth,
        &Password(b"hunter2"),
        &[],
    )
    .await
    .expect("a tunnelled session connects like any other");

    let pixels = raw_pixels(2, 2, 0x33);
    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(0, 0, 2, 2, RfbEncoding::RAW.to_wire())
        .await
        .unwrap();
    live.server.write(&pixels).await.unwrap();

    let FrameMessage::Framebuffer(update) = next_frame(&mut live.events).await else {
        panic!("the tunnelled path draws the same rectangles");
    };
    assert_eq!(update.rects[0].payload().as_ref(), &pixels[..]);

    // A routable hostname over a plain socket would have earned the blocking
    // warning; through an SSH channel it must not.
    live.cancel.cancel();
    let mut warnings = Vec::new();
    while let Ok(Some(event)) = tokio::time::timeout(PATIENCE, live.events.recv()).await {
        if let SessionEvent::Warning(SessionWarning::UnencryptedTransport { detail }) = event {
            warnings.push(detail);
        }
    }
    assert!(
        warnings.is_empty(),
        "a tunnelled session is not clear text: {warnings:?}"
    );
}

#[tokio::test]
async fn the_encodings_promised_on_the_wire_are_the_ones_this_build_can_decode() {
    // RFC 6143 §7.5.2 is a promise. Promising RRE or Hextile would not lose a
    // rectangle, it would desynchronise the stream — `vnc-rs` folds every
    // unrecognised encoding number onto Raw and then reads width * height * 4
    // bytes of a much shorter rectangle.
    let (transport, server) = transport_pair(target());
    let live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    assert!(
        !live.offered_encodings.contains(&RfbEncoding::RRE.to_wire()),
        "{:?}",
        live.offered_encodings
    );
    assert!(
        !live
            .offered_encodings
            .contains(&RfbEncoding::HEXTILE.to_wire()),
        "{:?}",
        live.offered_encodings
    );
    // Raw is mandatory for every client (RFC 6143 §7.7.1), and DesktopSize is
    // what makes a resize visible at all.
    assert!(live.offered_encodings.contains(&RfbEncoding::RAW.to_wire()));
    assert!(
        live.offered_encodings
            .contains(&RfbEncoding::DESKTOP_SIZE.to_wire())
    );
    assert!(
        live.offered_encodings
            .contains(&RfbEncoding::CURSOR.to_wire())
    );
    assert_eq!(
        live.offered_encodings.first(),
        Some(&RfbEncoding::TIGHT.to_wire()),
        "the default preference leads with Tight"
    );

    live.finish().await;
}

#[tokio::test]
async fn the_encoding_preference_reaches_the_wire() {
    let (transport, server) = transport_pair(target());
    let live = live(
        transport,
        server,
        Security::None,
        &NoCredential,
        &[("encoding", "zrle"), ("cursor", "remote")],
    )
    .await
    .expect("connects");

    assert_eq!(
        live.offered_encodings.first(),
        Some(&RfbEncoding::ZRLE.to_wire())
    );
    assert!(
        !live
            .offered_encodings
            .contains(&RfbEncoding::CURSOR.to_wire()),
        "remote cursor mode does not ask for the pseudo-encoding"
    );

    live.finish().await;
}

// --- authentication ---------------------------------------------------------

#[tokio::test]
async fn vnc_authentication_discards_everything_past_the_eighth_password_byte() {
    // RFC 6143 §7.2.2 builds the DES key from the first eight bytes. This is
    // the weakness stated as an executable fact: two different passwords that
    // agree in their first eight bytes produce the *same* response to the same
    // challenge, so a long passphrase buys nothing at all.
    async fn response_for(password: &'static [u8]) -> Vec<u8> {
        let (transport, server) = transport_pair(target());
        let handshake = tokio::spawn(async move {
            let mut server = server;
            let auth = server
                .handshake(Security::VncAuth)
                .await
                .expect("handshake");
            let encodings = server.initialise(WIDTH, HEIGHT).await.expect("ServerInit");
            (encodings, auth)
        });

        let (sink, _events) = event_channel(64);
        let protocol = VncProtocol::new().unwrap();
        let session = protocol
            .connect_session(
                Box::new(transport),
                &connection(&[]),
                &Password(password),
                sink,
                CancellationToken::new(),
            )
            .await
            .expect("the scripted server accepts any response");
        let (_encodings, auth) = handshake.await.expect("the server script finishes");
        drop(session);
        auth.expect("VNC authentication produces a response")
    }

    let eight = response_for(b"12345678").await;
    let longer = response_for(b"12345678-and-a-great-deal-more").await;
    assert_eq!(eight.len(), 16, "RFC 6143 §7.2.2: sixteen bytes");
    assert_eq!(
        eight, longer,
        "the ninth byte onwards is discarded, so the extra length is not security"
    );

    // And a genuinely different password does produce a different response, so
    // the assertion above is not vacuous.
    let different = response_for(b"87654321").await;
    assert_ne!(eight, different);
}

#[tokio::test]
async fn a_password_longer_than_eight_bytes_is_reported_before_the_desktop_appears() {
    let (transport, server) = transport_pair(target());
    let mut live = live(
        transport,
        server,
        Security::VncAuth,
        &Password(b"a-long-passphrase"),
        &[],
    )
    .await
    .expect("connects");

    let mut warnings = Vec::new();
    live.cancel.cancel();
    while let Ok(Some(event)) = tokio::time::timeout(PATIENCE, live.events.recv()).await {
        match event {
            SessionEvent::Warning(SessionWarning::Other { detail }) => warnings.push(detail),
            SessionEvent::Warning(SessionWarning::WeakAlgorithm { algorithm }) => {
                assert_eq!(algorithm, WEAK_ALGORITHM_VNC_AUTH);
            }
            _ => {}
        }
    }
    assert!(
        warnings.iter().any(|w| w == WARNING_PASSWORD_TRUNCATED),
        "{warnings:?}"
    );
}

#[tokio::test]
async fn a_server_offering_only_vencrypt_names_what_it_offered() {
    // The failure a user meets on a TigerVNC server configured for TLS. Without
    // the handshake observer this is "the handshake failed" and nothing else.
    let (transport, server) = transport_pair(target());
    let script = tokio::spawn(async move {
        let mut server = server;
        let _ = server.handshake(Security::VeNCrypt).await;
        server.hang_up().await;
    });

    let (sink, _events) = event_channel(64);
    let protocol = VncProtocol::new().unwrap();
    let error = protocol
        .connect_session(
            Box::new(transport),
            &connection(&[]),
            &Password(b"hunter2"),
            sink,
            CancellationToken::new(),
        )
        .await
        .expect_err("this build implements neither VeNCrypt nor anything like it");
    script.await.unwrap();

    let ProtocolError::AuthMethodUnavailable { offered, .. } = error else {
        panic!("this is an authentication failure with a name, not a mystery");
    };
    assert_eq!(offered, vec!["VeNCrypt".to_owned()]);
}

#[tokio::test]
async fn a_server_that_goes_away_mid_handshake_is_a_disconnection_not_a_hang() {
    let (transport, server) = transport_pair(target());
    let script = tokio::spawn(async move {
        let mut server = server;
        server.write(b"RFB 003.0").await.unwrap();
        server.hang_up().await;
    });

    let (sink, _events) = event_channel(64);
    let protocol = VncProtocol::new().unwrap();
    let error = tokio::time::timeout(
        PATIENCE,
        protocol.connect_session(
            Box::new(transport),
            &connection(&[]),
            &NoCredential,
            sink,
            CancellationToken::new(),
        ),
    )
    .await
    .expect("a truncated version string must not hang the handshake")
    .expect_err("nine bytes is not a version string");
    script.await.unwrap();

    assert!(
        matches!(error, ProtocolError::Disconnected { .. }),
        "{error:?}"
    );
}

// --- one test per encoding, well formed and malformed -----------------------

#[tokio::test]
async fn copy_rect_carries_four_bytes_and_no_pixels() {
    // RFC 6143 §7.7.2. This is what makes a window drag cost nothing.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(0, 0, 8, 8, RfbEncoding::COPY_RECT.to_wire())
        .await
        .unwrap();
    live.server.write(&16_u16.to_be_bytes()).await.unwrap();
    live.server.write(&8_u16.to_be_bytes()).await.unwrap();

    let FrameMessage::Framebuffer(update) = next_frame(&mut live.events).await else {
        panic!("a copy rectangle is a framebuffer message");
    };
    let rect = &update.rects[0];
    assert_eq!(rect.encoding, FrameEncoding::CopyRect);
    assert_eq!(rect.copy_source(), Some((16, 8)));
    assert_eq!(rect.payload().len(), 4);

    live.finish().await;
}

#[tokio::test]
async fn a_copy_rect_reading_from_outside_the_framebuffer_ends_the_session() {
    // The source is what the presenter *reads*, and there are no pixels on the
    // wire to give a bad one away. Letting it through would be an out-of-bounds
    // read in whatever renders the surface.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(0, 0, 8, 8, RfbEncoding::COPY_RECT.to_wire())
        .await
        .unwrap();
    // x = 60 with a width of 8 runs off the right edge of a 64-pixel desktop.
    live.server.write(&60_u16.to_be_bytes()).await.unwrap();
    live.server.write(&0_u16.to_be_bytes()).await.unwrap();

    let reason = tokio::time::timeout(PATIENCE, live.task)
        .await
        .expect("the session must end rather than draw it")
        .expect("and must not panic")
        .expect("failures are folded into a close reason");
    assert!(matches!(reason, CloseReason::Failed(_)), "{reason:?}");
}

#[tokio::test]
async fn a_raw_rectangle_larger_than_the_framebuffer_ends_the_session() {
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    // A rectangle at x = 60 of width 8, on a desktop 64 wide. The pixels are
    // sent so the library's decoder is satisfied and the rejection is this
    // crate's bounds check rather than a short read.
    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(60, 0, 8, 8, RfbEncoding::RAW.to_wire())
        .await
        .unwrap();
    live.server.write(&raw_pixels(8, 8, 1)).await.unwrap();

    let reason = tokio::time::timeout(PATIENCE, live.task)
        .await
        .expect("the session must end")
        .expect("and must not panic")
        .expect("failures are folded into a close reason");
    assert!(matches!(reason, CloseReason::Failed(_)), "{reason:?}");
}

#[tokio::test]
async fn a_truncated_raw_rectangle_ends_the_session_without_drawing_anything() {
    // The rectangle promises 4x4 pixels and the server sends eight bytes and
    // hangs up. Nothing may be drawn from a buffer that never arrived.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(0, 0, 4, 4, RfbEncoding::RAW.to_wire())
        .await
        .unwrap();
    live.server.write(&[0xaa; 8]).await.unwrap();
    live.server.hang_up().await;

    let reason = tokio::time::timeout(PATIENCE, live.task)
        .await
        .expect("a truncated rectangle must not hang the session")
        .expect("and must not panic")
        .expect("failures are folded into a close reason");
    assert!(
        matches!(reason, CloseReason::Disconnected | CloseReason::Failed(_)),
        "{reason:?}"
    );

    // And no framebuffer message was produced from the partial buffer.
    let mut frames = 0;
    while let Ok(Some(event)) = tokio::time::timeout(PATIENCE, live.events.recv()).await {
        if matches!(event, SessionEvent::Data(_)) {
            frames += 1;
        }
    }
    assert_eq!(frames, 0, "a rectangle that never arrived is not drawn");
}

#[tokio::test]
async fn a_tight_fill_rectangle_becomes_a_solid_raw_rectangle() {
    // Tight is registry number 7 and is defined outside RFC 6143. A control
    // byte of 0x80 is "fill", followed by three bytes of colour.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(0, 0, 2, 2, RfbEncoding::TIGHT.to_wire())
        .await
        .unwrap();
    live.server.write(&[0x80, 0x12, 0x34, 0x56]).await.unwrap();

    let FrameMessage::Framebuffer(update) = next_frame(&mut live.events).await else {
        panic!("a Tight fill is a framebuffer message");
    };
    let rect = &update.rects[0];
    assert_eq!(rect.encoding, FrameEncoding::Raw, "a fill is expanded");
    assert_eq!(rect.payload().len(), 2 * 2 * 4);
    // BGRX, which is the format `SetPixelFormat` asked for: the red byte the
    // server sent (0x12) lands third.
    assert_eq!(rect.payload()[0..4], [0x56, 0x34, 0x12, 0xff]);

    live.finish().await;
}

#[tokio::test]
async fn a_tight_jpeg_rectangle_keeps_its_own_colour_space() {
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    // Control byte 0x90 is "JPEG", then a length in Tight's 7-bit continuation
    // form, then the image. The bytes are not a real JPEG; nothing in this
    // crate decodes one, and the presenter is what would.
    let image = [0xff_u8, 0xd8, 0xff, 0xe0, 0x00, 0x10];
    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(0, 0, 8, 8, RfbEncoding::TIGHT.to_wire())
        .await
        .unwrap();
    live.server.write(&[0x90]).await.unwrap();
    live.server
        .write(&[u8::try_from(image.len()).unwrap()])
        .await
        .unwrap();
    live.server.write(&image).await.unwrap();

    let FrameMessage::Framebuffer(update) = next_frame(&mut live.events).await else {
        panic!("a Tight JPEG is a framebuffer message");
    };
    let rect = &update.rects[0];
    assert_eq!(rect.encoding, FrameEncoding::Jpeg);
    assert_eq!(rect.payload().as_ref(), &image[..]);

    live.finish().await;
}

#[tokio::test]
async fn a_tight_rectangle_with_an_illegal_compression_ends_the_session() {
    // Control values 0x0b through 0x0f are not defined by the Tight encoding.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(0, 0, 8, 8, RfbEncoding::TIGHT.to_wire())
        .await
        .unwrap();
    live.server.write(&[0xf0]).await.unwrap();

    let reason = tokio::time::timeout(PATIENCE, live.task)
        .await
        .expect("an illegal compression must not hang the session")
        .expect("and must not panic")
        .expect("failures are folded into a close reason");
    assert!(matches!(reason, CloseReason::Failed(_)), "{reason:?}");
}

/// One 64x64-or-smaller ZRLE tile, solid-colour subencoding.
///
/// RFC 6143 §7.7.6. The control byte is `palette-size` with the RLE bit clear;
/// a palette size of one means "the whole tile is this colour". The pixel is a
/// CPIXEL — three bytes rather than four, because the format the adapter asked
/// for puts all of the colour in the low 24 bits.
///
/// The zlib stream is flushed with `Sync` and never finished, because RFC 6143
/// §7.7.6 keeps one zlib stream for the whole connection: a finished stream is
/// what a server never sends and what the decoder treats as an error.
fn zrle_solid_tile(colour: [u8; 3]) -> Vec<u8> {
    let mut raw = vec![0x01_u8];
    raw.extend_from_slice(&colour);

    let mut compressor = flate2::Compress::new(flate2::Compression::default(), true);
    let mut compressed = Vec::with_capacity(64);
    compressor
        .compress_vec(&raw, &mut compressed, flate2::FlushCompress::Sync)
        .expect("zlib compression of four bytes cannot fail");

    let mut out = Vec::with_capacity(compressed.len() + 4);
    out.extend_from_slice(&u32::try_from(compressed.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&compressed);
    out
}

#[tokio::test]
async fn a_zrle_solid_tile_fills_its_rectangle() {
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(0, 0, 4, 4, RfbEncoding::ZRLE.to_wire())
        .await
        .unwrap();
    live.server
        .write(&zrle_solid_tile([0x11, 0x22, 0x33]))
        .await
        .unwrap();

    let FrameMessage::Framebuffer(update) = next_frame(&mut live.events).await else {
        panic!("a ZRLE tile is a framebuffer message");
    };
    let rect = &update.rects[0];
    assert_eq!(rect.rect, remoter_proto::Rect::new(0, 0, 4, 4));
    assert_eq!(rect.payload().len(), 4 * 4 * 4);
    // Every pixel is the same, and the fourth byte is the opaque padding the
    // contract's BGRX format requires.
    for pixel in rect.payload().chunks_exact(4) {
        assert_eq!(pixel, [0x11, 0x22, 0x33, 0xff]);
    }

    // How the session ends afterwards is deliberately not asserted: the
    // library checks that its zlib input was fully consumed and a synthetic
    // one-tile stream leaves the sync-flush trailer behind. The rectangle is
    // emitted before that check runs, which is the behaviour under test.
    live.cancel.cancel();
}

#[tokio::test]
async fn a_zrle_tile_with_an_unusable_subencoding_ends_the_session() {
    // Subencoding 1 with the RLE bit set is not a combination RFC 6143 §7.7.6
    // defines. The library rejects it, and the session must end rather than
    // draw whatever happened to be in the buffer.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    let mut raw = vec![0x81_u8];
    raw.extend_from_slice(&[0x11, 0x22, 0x33]);
    let mut compressor = flate2::Compress::new(flate2::Compression::default(), true);
    let mut compressed = Vec::new();
    compressor
        .compress_vec(&raw, &mut compressed, flate2::FlushCompress::Sync)
        .unwrap();

    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(0, 0, 4, 4, RfbEncoding::ZRLE.to_wire())
        .await
        .unwrap();
    live.server
        .write(&u32::try_from(compressed.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    live.server.write(&compressed).await.unwrap();

    let reason = tokio::time::timeout(PATIENCE, live.task)
        .await
        .expect("a malformed tile must not hang the session")
        .expect("and must not panic the runtime")
        .expect("failures are folded into a close reason");
    // Either close reason is the same outcome from the user's side: the session
    // is over and nothing was drawn. Which of the two arrives depends on
    // whether the library reports the malformed tile as a decoder error or as
    // an end-of-stream on its internal bridge, and it reports it both ways
    // depending on how far into the tile the failure is.
    assert!(
        matches!(reason, CloseReason::Failed(_) | CloseReason::Disconnected),
        "{reason:?}"
    );

    let mut frames = 0;
    while let Ok(Some(event)) = tokio::time::timeout(PATIENCE, live.events.recv()).await {
        if matches!(event, SessionEvent::Data(_)) {
            frames += 1;
        }
    }
    assert_eq!(frames, 0, "a tile that could not be decoded is not drawn");
}

#[tokio::test]
async fn a_zrle_palette_index_past_the_palette_takes_down_one_tab_and_nothing_else() {
    // A finding, stated as a test. `vnc-rs` indexes its ZRLE palette without a
    // bounds check, so this input panics its decoding task. What is asserted is
    // the containment ADR-0011 promises: the panic is inside a task the library
    // spawned, this session ends, and the test process — every other tab —
    // carries on. A panic message on stderr during this test is expected.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    // RLE bit set with a palette of two entries, then an index of 5.
    let mut raw = vec![0x82_u8];
    raw.extend_from_slice(&[0x11, 0x22, 0x33]);
    raw.extend_from_slice(&[0x44, 0x55, 0x66]);
    raw.push(0x05);
    let mut compressor = flate2::Compress::new(flate2::Compression::default(), true);
    let mut compressed = Vec::new();
    compressor
        .compress_vec(&raw, &mut compressed, flate2::FlushCompress::Sync)
        .unwrap();

    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(0, 0, 4, 4, RfbEncoding::ZRLE.to_wire())
        .await
        .unwrap();
    live.server
        .write(&u32::try_from(compressed.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    live.server.write(&compressed).await.unwrap();

    let reason = tokio::time::timeout(PATIENCE, live.task)
        .await
        .expect("the session must end rather than hang")
        .expect("the *session* task must not panic, whatever the library's does")
        .expect("failures are folded into a close reason");
    assert!(
        matches!(
            reason,
            CloseReason::Disconnected | CloseReason::Failed(_) | CloseReason::ClosedByUser
        ),
        "{reason:?}"
    );
}

#[tokio::test]
async fn a_colour_map_message_ends_the_session_rather_than_the_process() {
    // A second finding. RFC 6143 §7.6.2 `SetColorMapEntries` is server message
    // type 1, and `vnc-rs` reaches `unimplemented!()` on it — so one byte from
    // a hostile server panics its decoding task. The adapter always asks for a
    // true-colour pixel format, so a conforming server has no reason to send
    // one; this checks what happens when a server is not conforming.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.server.write(&[1_u8, 0, 0, 0, 0, 1]).await.unwrap();

    let reason = tokio::time::timeout(PATIENCE, live.task)
        .await
        .expect("the session must end rather than hang")
        .expect("the session task must not panic")
        .expect("failures are folded into a close reason");
    assert!(
        matches!(
            reason,
            CloseReason::Disconnected | CloseReason::Failed(_) | CloseReason::ClosedByUser
        ),
        "{reason:?}"
    );
}

#[tokio::test]
async fn an_unknown_server_message_type_ends_the_session() {
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.server.write(&[0xfe_u8]).await.unwrap();

    let reason = tokio::time::timeout(PATIENCE, live.task)
        .await
        .expect("the session must end rather than hang")
        .expect("and must not panic")
        .expect("failures are folded into a close reason");
    assert!(matches!(reason, CloseReason::Failed(_)), "{reason:?}");
}

// --- cursor, resize, clipboard ---------------------------------------------

#[tokio::test]
async fn the_server_sets_the_cursor_shape_and_it_arrives_as_rgba() {
    // RFC 6143 §7.8.1: the rectangle's x and y are the hot spot, the pixels are
    // followed by a bitmask, and the mask becomes the alpha channel.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(1, 1, 2, 2, RfbEncoding::CURSOR.to_wire())
        .await
        .unwrap();
    // Four BGRX pixels, then a 2x2 bitmask packed one row per byte: the first
    // row opaque, the second transparent.
    let mut pixels = Vec::new();
    for _ in 0..4 {
        pixels.extend_from_slice(&[0x11, 0x22, 0x33, 0x00]);
    }
    live.server.write(&pixels).await.unwrap();
    live.server
        .write(&[0b1100_0000, 0b0000_0000])
        .await
        .unwrap();

    let FrameMessage::Cursor(cursor) = next_frame(&mut live.events).await else {
        panic!("a cursor pseudo-encoding is a cursor message");
    };
    assert_eq!((cursor.hotspot_x, cursor.hotspot_y), (1, 1));
    assert_eq!((cursor.width, cursor.height), (2, 2));
    assert_eq!(cursor.format, remoter_proto::PixelFormat::Rgba8888);
    // Red and blue swapped, and the mask in the alpha byte.
    assert_eq!(cursor.image()[0..4], [0x33, 0x22, 0x11, 0xff]);
    assert_eq!(cursor.image()[8..12], [0x33, 0x22, 0x11, 0x00]);

    live.finish().await;
}

#[tokio::test]
async fn a_desktop_resize_is_reported_and_the_whole_screen_is_asked_for_again() {
    // RFC 6143 §7.8.2. The pending rectangles described the old surface and
    // cannot be applied to the new one, so the next request must be
    // non-incremental — otherwise the tab shows a desktop-sized hole.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(0, 0, 128, 96, RfbEncoding::DESKTOP_SIZE.to_wire())
        .await
        .unwrap();

    let (width, height) = next_matching(&mut live.events, |event| match event {
        SessionEvent::Resized { width, height } if width == 128 => Some((width, height)),
        _ => None,
    })
    .await;
    assert_eq!((width, height), (128, 96));

    let request = tokio::time::timeout(PATIENCE, live.server.read_exact(10))
        .await
        .expect("a request must follow a resize")
        .expect("the pipe is open");
    assert_eq!(request[0], 3, "FramebufferUpdateRequest");
    assert_eq!(request[1], 0, "non-incremental after a resize");

    // A defect pinned rather than papered over. `vnc-rs` builds the request
    // rectangle from the size it learned at `ServerInit` and never updates it
    // when RFC 6143 §7.8.2 changes the desktop, so the request still covers the
    // *old* 64x32 area. A desktop that grows therefore leaves the new region
    // unpainted, and there is no API on `VncClient` that can ask for a
    // different rectangle. Recorded in `lib.rs`; when the library is fixed this
    // assertion fails and says so.
    assert_eq!(
        u16::from_be_bytes([request[6], request[7]]),
        WIDTH,
        "the library asks for the pre-resize width"
    );
    assert_eq!(u16::from_be_bytes([request[8], request[9]]), HEIGHT);

    live.finish().await;
}

#[tokio::test]
async fn a_rectangle_in_the_new_size_is_accepted_after_a_resize() {
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(0, 0, 128, 96, RfbEncoding::DESKTOP_SIZE.to_wire())
        .await
        .unwrap();
    // Drain the non-incremental request the resize triggers.
    let _ = tokio::time::timeout(PATIENCE, live.server.read_exact(10)).await;

    // A rectangle at x = 100 would have been outside the original 64-wide
    // desktop and is inside the new one.
    let pixels = raw_pixels(8, 8, 0x77);
    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(100, 80, 8, 8, RfbEncoding::RAW.to_wire())
        .await
        .unwrap();
    live.server.write(&pixels).await.unwrap();

    let FrameMessage::Framebuffer(update) = next_frame(&mut live.events).await else {
        panic!("the rectangle is inside the new surface");
    };
    assert_eq!(update.rects[0].rect.x, 100);

    live.finish().await;
}

#[tokio::test]
async fn remote_clipboard_text_raises_an_offer() {
    // RFC 6143 §7.6.4. The offer says the remote has something; the content is
    // deliberately not retained, because the session contract has no event that
    // could deliver it and a password in memory for the life of a tab buys
    // nothing.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.server.cut_text(b"copied on the remote").await.unwrap();

    let formats = next_matching(&mut live.events, |event| match event {
        SessionEvent::ClipboardOffer(formats) => Some(formats),
        _ => None,
    })
    .await;
    assert!(formats.text);
    assert!(!formats.files, "there is no file clipboard in RFB");

    live.finish().await;
}

#[tokio::test]
async fn pasting_sends_client_cut_text_with_the_substitutions_reported() {
    // RFC 6143 §7.5.6: type 6, three padding bytes, a U32 length, then text.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.commands
        .send(SessionCommand::Clipboard(ClipboardOp::Offer(
            ClipboardData::Text("café\r\nsudo".to_owned()),
        )))
        .await
        .unwrap();

    let header = tokio::time::timeout(PATIENCE, live.server.read_exact(8))
        .await
        .expect("the paste must reach the wire")
        .unwrap();
    assert_eq!(header[0], 6, "ClientCutText is client message type 6");
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let text = live
        .server
        .read_exact(usize::try_from(length).unwrap())
        .await
        .unwrap();
    assert_eq!(
        text, b"caf?\nsudo",
        "the accent is substituted and CRLF became one LF"
    );

    let detail = next_matching(&mut live.events, |event| match event {
        SessionEvent::Warning(SessionWarning::Other { detail })
            if detail == crate::session::WARNING_CLIPBOARD_LOSSY =>
        {
            Some(detail)
        }
        _ => None,
    })
    .await;
    assert_eq!(detail, crate::session::WARNING_CLIPBOARD_LOSSY);

    live.finish().await;
}

// --- input ------------------------------------------------------------------

#[tokio::test]
async fn a_key_press_puts_the_layouts_keysym_on_the_wire() {
    // RFC 6143 §7.5.4: type 4, a down flag, two padding bytes, then a U32
    // keysym. The keysym is what the *layout* produced, not the physical key.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    let dotless_i = 0x0100_0131;
    live.commands
        .send(SessionCommand::Input(InputEvent::Key {
            scancode: 0x17,
            keysym: Some(dotless_i),
            modifiers: remoter_proto::Modifiers::NONE,
            pressed: true,
        }))
        .await
        .unwrap();

    let message = tokio::time::timeout(PATIENCE, live.server.read_exact(8))
        .await
        .expect("the key must reach the wire")
        .unwrap();
    assert_eq!(message[0], 4, "KeyEvent is client message type 4");
    assert_eq!(message[1], 1, "down");
    assert_eq!(
        u32::from_be_bytes([message[4], message[5], message[6], message[7]]),
        dotless_i
    );

    live.finish().await;
}

#[tokio::test]
async fn a_bare_modifier_is_named_by_its_physical_key() {
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.commands
        .send(SessionCommand::Input(InputEvent::Key {
            scancode: 0x2a,
            keysym: None,
            modifiers: remoter_proto::Modifiers::SHIFT,
            pressed: true,
        }))
        .await
        .unwrap();

    let message = tokio::time::timeout(PATIENCE, live.server.read_exact(8))
        .await
        .expect("the modifier must reach the wire")
        .unwrap();
    assert_eq!(
        u32::from_be_bytes([message[4], message[5], message[6], message[7]]),
        0xffe1,
        "XK_Shift_L"
    );

    live.finish().await;
}

#[tokio::test]
async fn a_pointer_click_and_a_wheel_notch_are_three_messages() {
    // RFC 6143 §7.5.5: type 5, a button mask, then two U16 coordinates. A wheel
    // notch is a press and release of button 4, because RFB has no wheel.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.commands
        .send(SessionCommand::Input(InputEvent::Pointer {
            x: 10,
            y: 20,
            buttons: PointerButtons::LEFT,
            wheel: 120,
            wheel_x: 0,
        }))
        .await
        .unwrap();

    let bytes = tokio::time::timeout(PATIENCE, live.server.read_exact(18))
        .await
        .expect("the pointer events must reach the wire")
        .unwrap();
    let messages: Vec<&[u8]> = bytes.chunks_exact(6).collect();
    for message in &messages {
        assert_eq!(message[0], 5, "PointerEvent is client message type 5");
        assert_eq!(u16::from_be_bytes([message[2], message[3]]), 10);
        assert_eq!(u16::from_be_bytes([message[4], message[5]]), 20);
    }
    assert_eq!(messages[0][1], 0b0000_0001, "the left button, held");
    assert_eq!(
        messages[1][1], 0b0000_1001,
        "button 4 pressed while the left button stays held"
    );
    assert_eq!(messages[2][1], 0b0000_0001, "button 4 released");

    live.finish().await;
}

#[tokio::test]
async fn a_pointer_position_past_the_edge_is_clamped_to_the_framebuffer() {
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.commands
        .send(SessionCommand::Input(InputEvent::Pointer {
            x: 4_000,
            y: 4_000,
            buttons: PointerButtons::NONE,
            wheel: 0,
            wheel_x: 0,
        }))
        .await
        .unwrap();

    let message = tokio::time::timeout(PATIENCE, live.server.read_exact(6))
        .await
        .expect("the pointer must reach the wire")
        .unwrap();
    assert_eq!(u16::from_be_bytes([message[2], message[3]]), WIDTH - 1);
    assert_eq!(u16::from_be_bytes([message[4], message[5]]), HEIGHT - 1);

    live.finish().await;
}

#[tokio::test]
async fn a_view_only_session_sends_nothing() {
    let (transport, server) = transport_pair(target());
    let mut live = live(
        transport,
        server,
        Security::None,
        &NoCredential,
        &[("view_only", "true")],
    )
    .await
    .expect("connects");

    live.commands
        .send(SessionCommand::Input(InputEvent::Key {
            scancode: 0x1e,
            keysym: Some(u32::from(b'a')),
            modifiers: remoter_proto::Modifiers::NONE,
            pressed: true,
        }))
        .await
        .unwrap();
    live.commands
        .send(SessionCommand::Input(InputEvent::Pointer {
            x: 1,
            y: 1,
            buttons: PointerButtons::LEFT,
            wheel: 0,
            wheel_x: 0,
        }))
        .await
        .unwrap();

    // Nothing is written, so the read must time out rather than return.
    let read = tokio::time::timeout(Duration::from_millis(250), live.server.read_exact(1)).await;
    assert!(read.is_err(), "a view-only session types nothing");

    live.finish().await;
}

#[tokio::test]
async fn asking_a_vnc_session_to_resize_the_desktop_says_it_cannot() {
    // Reported rather than accepted and quietly dropped: RFC 6143 §7.8.2 is
    // server-to-client, and the client-initiated direction is a community
    // extension this build does not implement.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.commands
        .send(SessionCommand::Resize {
            cols: 1024,
            rows: 768,
        })
        .await
        .unwrap();

    // The session survives it — an unsupported operation is not worth ending a
    // working desktop over — and still draws.
    let pixels = raw_pixels(2, 2, 0x05);
    live.server.framebuffer_update(1).await.unwrap();
    live.server
        .rectangle_header(0, 0, 2, 2, RfbEncoding::RAW.to_wire())
        .await
        .unwrap();
    live.server.write(&pixels).await.unwrap();
    let FrameMessage::Framebuffer(update) = next_frame(&mut live.events).await else {
        panic!("the session is still running");
    };
    assert_eq!(update.rects[0].payload().as_ref(), &pixels[..]);

    assert_eq!(live.finish().await, CloseReason::ClosedByUser);
}

// --- shutdown ---------------------------------------------------------------

#[tokio::test]
async fn cancelling_a_session_releases_the_transport() {
    // The requirement in one assertion: a closed tab frees its socket. The
    // server end of the pipe sees end-of-file, which it can only do if the
    // client end was dropped — so nothing is holding the transport open.
    let (transport, server) = transport_pair(target());
    let mut live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.cancel.cancel();
    let reason = tokio::time::timeout(PATIENCE, live.task)
        .await
        .expect("a cancelled session must stop promptly")
        .expect("and must not panic")
        .expect("cancellation is a close reason, not an error");
    assert_eq!(reason, CloseReason::ClosedByUser);

    let after = tokio::time::timeout(PATIENCE, live.server.read_exact(1))
        .await
        .expect("the far end must see the close rather than hang");
    assert!(
        after.is_err(),
        "the transport must be dropped, not merely idle"
    );
}

#[tokio::test]
async fn a_disconnect_command_ends_the_session_cleanly() {
    let (transport, server) = transport_pair(target());
    let live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.commands
        .send(SessionCommand::Disconnect)
        .await
        .unwrap();
    let reason = tokio::time::timeout(PATIENCE, live.task)
        .await
        .expect("a disconnect must be acted on")
        .expect("and must not panic")
        .expect("a clean close is a reason, not an error");
    assert_eq!(reason, CloseReason::ClosedByUser);
}

#[tokio::test]
async fn a_server_that_hangs_up_ends_the_session_as_a_disconnection() {
    let (transport, server) = transport_pair(target());
    let live = live(transport, server, Security::None, &NoCredential, &[])
        .await
        .expect("connects");

    live.server.hang_up().await;
    let reason = tokio::time::timeout(PATIENCE, live.task)
        .await
        .expect("the session must notice the far end going away")
        .expect("and must not panic")
        .expect("a disconnection is a reason, not an error");
    assert_eq!(reason, CloseReason::Disconnected);
}

#[tokio::test]
async fn cancelling_during_the_handshake_leaks_nothing() {
    // The defect this arrangement exists to prevent: one leaked task and one
    // leaked socket per cancelled connection attempt. Cancelling drops the
    // connector, and the connector owns the transport.
    let (transport, mut server) = transport_pair(target());
    let cancel = CancellationToken::new();
    let (sink, _events) = event_channel(16);
    let protocol = VncProtocol::new().unwrap();

    let token = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        token.cancel();
    });

    // The server announces its version and then says nothing more, so the
    // handshake is still in flight when the token fires.
    server.write(b"RFB 003.008\n").await.unwrap();

    let error = tokio::time::timeout(
        PATIENCE,
        protocol.connect_session(
            Box::new(transport),
            &connection(&[]),
            &NoCredential,
            sink,
            cancel,
        ),
    )
    .await
    .expect("cancellation must be prompt")
    .expect_err("a cancelled handshake does not produce a session");
    assert!(matches!(error, ProtocolError::Cancelled), "{error:?}");

    // The client answered the version handshake before the token fired
    // (RFC 6143 §7.1.1), so those twelve bytes are on the wire and have to be
    // drained before end-of-file can be observed.
    let echo = tokio::time::timeout(PATIENCE, server.read_exact(12))
        .await
        .expect("the version reply is already written")
        .expect("the pipe carried it");
    assert_eq!(&echo[..], b"RFB 003.008\n");

    let after = tokio::time::timeout(PATIENCE, server.read_exact(1))
        .await
        .expect("the far end must see the close");
    assert!(after.is_err(), "the transport is released with the attempt");
}
