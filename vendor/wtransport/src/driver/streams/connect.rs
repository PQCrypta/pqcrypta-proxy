use tracing::debug;
use wtransport_proto::bytes::IoReadError;
use wtransport_proto::capsule::capsules;
use wtransport_proto::capsule::Capsule;
use wtransport_proto::capsule::{self};
use wtransport_proto::error::ErrorCode;
use wtransport_proto::frame::FrameKind;
use wtransport_proto::varint::VarInt;

use super::session::StreamSession;
use super::ProtoReadError;
use crate::driver::DriverError;
use crate::error::ApplicationClose;
use std::future::pending;

pub struct ConnectStream {
    stream: Option<StreamSession>,
}

impl ConnectStream {
    pub fn empty() -> Self {
        Self { stream: None }
    }

    pub fn is_empty(&self) -> bool {
        self.stream.is_none()
    }

    pub fn set_stream(&mut self, stream: StreamSession) {
        self.stream = Some(stream);
    }

    /// Send WT_CLOSE_SESSION and FIN (draft-ietf-webtrans-http3 section 6),
    /// then wait a moment for the peer to close or reset the stream in
    /// response, so the capsule arrives before the connection closes.
    pub async fn close(&mut self, error_code: VarInt, reason: &[u8]) {
        let Some(stream) = self.stream.as_mut() else {
            return;
        };
        // The message is at most 1024 bytes, cut at a character
        let mut end = reason.len().min(1024);
        while end > 0 && std::str::from_utf8(&reason[..end]).is_err() {
            end -= 1;
        }
        let code = u32::try_from(error_code.into_inner()).unwrap_or(u32::MAX);
        let mut capsule = Vec::with_capacity(end + 16);
        put_varint(&mut capsule, 0x2843);
        put_varint(&mut capsule, 4 + end as u64);
        capsule.extend_from_slice(&code.to_be_bytes());
        capsule.extend_from_slice(&reason[..end]);
        let _ = stream
            .write_frame(wtransport_proto::frame::Frame::new_data(
                std::borrow::Cow::Owned(capsule),
            ))
            .await;
        stream.finish().await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while stream.read_frame().await.is_ok() {}
        })
        .await;
    }

    pub async fn run(&mut self) -> DriverError {
        let stream = match self.stream.as_mut() {
            Some(stream) => stream,
            None => pending().await,
        };

        loop {
            return match stream.read_frame().await {
                Ok(frame) => {
                    if !matches!(frame.kind(), FrameKind::Data) {
                        debug!("Skipping non-data frame of kind {:?}", frame.kind());
                        continue;
                    }

                    let capsule = match Capsule::with_frame(&frame) {
                        Some(capsule)
                            if matches!(
                                capsule.kind(),
                                capsule::CapsuleKind::CloseWebTransportSession
                            ) =>
                        {
                            capsule
                        }
                        // Unknown capsule, skip it
                        _ => {
                            debug!(
                                "Unknown capsule of kind {:?} of {}B",
                                frame.kind(),
                                frame.payload().len()
                            );

                            continue;
                        }
                    };

                    let close_session =
                        match capsules::CloseWebTransportSession::with_capsule(&capsule) {
                            Ok(close_session) => close_session,
                            Err(error_code) => return DriverError::Proto(error_code),
                        };

                    // reset right away to avoid receiving additional data which requires resetting with ErrorCode::Message.
                    self.stream
                        .take()
                        .unwrap()
                        .reset(ErrorCode::NoError.to_code());

                    DriverError::ApplicationClosed(ApplicationClose::new(
                        close_session.error_code(),
                        close_session
                            .reason()
                            .as_bytes()
                            .to_vec()
                            .into_boxed_slice(),
                    ))
                }
                Err(ProtoReadError::H3(error_code)) => DriverError::Proto(error_code),
                Err(ProtoReadError::IO(io_error)) => match io_error {
                    // Cleanly terminating a CONNECT stream without a CLOSE_WEBTRANSPORT_SESSION
                    // capsule SHALL be semantically equivalent to terminating it with a
                    // CLOSE_WEBTRANSPORT_SESSION capsule that has an error code of 0 and an empty error string.
                    IoReadError::ImmediateFin => DriverError::ApplicationClosed(
                        ApplicationClose::new(VarInt::from_u32(0), Box::new([])),
                    ),
                    IoReadError::UnexpectedFin | IoReadError::Reset => {
                        DriverError::Proto(ErrorCode::ClosedCriticalStream)
                    }
                    IoReadError::NotConnected => DriverError::NotConnected,
                },
            };
        }
    }
}

/// A QUIC variable-length integer in its shortest form (RFC 9000 section 16).
fn put_varint(out: &mut Vec<u8>, value: u64) {
    let (len, tag) = match value {
        0..=0x3f => (1, 0x00),
        0x40..=0x3fff => (2, 0x40),
        0x4000..=0x3fff_ffff => (4, 0x80),
        _ => (8, 0xc0),
    };
    let start = out.len();
    out.extend_from_slice(&value.to_be_bytes()[8 - len..]);
    out[start] |= tag;
}
