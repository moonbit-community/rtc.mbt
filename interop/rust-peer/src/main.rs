use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use log::{LevelFilter, Log, Metadata, Record};
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::{MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine};
use webrtc::api::setting_engine::SettingEngine;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::ice::network_type::NetworkType;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::rtp;
use webrtc::rtp_transceiver::rtp_codec::{RTCRtpCodecCapability, RTPCodecType};
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;
use webrtc::track::track_local::{TrackLocal, TrackLocalWriter};

const RUN_TIMEOUT: Duration = Duration::from_secs(30);

struct DtlsLogger;

impl Log for DtlsLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target().contains("dtls") || metadata.target().contains("sctp")
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            eprintln!(
                "Rust log {} {}: {}",
                record.level(),
                record.target(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

static DTLS_LOGGER: DtlsLogger = DtlsLogger;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerRole {
    Offerer,
    Answerer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InteropMode {
    Reliable,
    Partial,
    Media,
}

#[derive(Clone, Copy)]
enum ChannelBehavior {
    Initiate,
    Echo,
}

#[derive(Default)]
struct Observations {
    channel_opened: bool,
    saw_text: bool,
    saw_binary: bool,
    saw_audio: bool,
    saw_video: bool,
    failure: Option<String>,
}

#[derive(Clone)]
struct MediaSenders {
    audio: Arc<TrackLocalStaticRTP>,
    video: Arc<TrackLocalStaticRTP>,
}

fn binary_fixture() -> Bytes {
    (0..2500)
        .map(|index| ((index * 31 + 7) % 251) as u8)
        .collect()
}

fn record_failure(observations: &Arc<Mutex<Observations>>, error: anyhow::Error) {
    observations.lock().expect("observations mutex").failure = Some(format!("{error:#}"));
}

fn install_channel_handlers(
    channel: Arc<RTCDataChannel>,
    behavior: ChannelBehavior,
    mode: InteropMode,
    media_senders: Option<MediaSenders>,
    observations: Arc<Mutex<Observations>>,
) {
    let parameters_match = match mode {
        InteropMode::Reliable | InteropMode::Media => {
            channel.ordered() && channel.max_retransmits().is_none()
        }
        InteropMode::Partial => !channel.ordered() && channel.max_retransmits() == Some(2),
    };
    if !parameters_match {
        observations.lock().expect("observations mutex").failure = Some(format!(
            "unexpected DataChannel parameters for {mode:?}: ordered={}, max_retransmits={:?}",
            channel.ordered(),
            channel.max_retransmits()
        ));
    }
    let open_channel = Arc::clone(&channel);
    let open_observations = Arc::clone(&observations);
    channel.on_open(Box::new(move || {
        let channel = Arc::clone(&open_channel);
        let observations = Arc::clone(&open_observations);
        Box::pin(async move {
            observations
                .lock()
                .expect("observations mutex")
                .channel_opened = true;
            if matches!(behavior, ChannelBehavior::Initiate) {
                let binary = binary_fixture();
                let result: Result<()> = async {
                    channel.send_text("rust-moonbit-text").await?;
                    channel.send(&binary).await?;
                    if let Some(media) = media_senders {
                        for index in 0..30_u16 {
                            let packet = rtp::packet::Packet {
                                header: rtp::header::Header {
                                    version: 2,
                                    marker: true,
                                    sequence_number: index + 1,
                                    timestamp: u32::from(index + 1) * 960,
                                    ..Default::default()
                                },
                                payload: Bytes::from_static(b"\xf8\xff\xfe"),
                            };
                            media.audio.write_rtp(&packet).await?;
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        for index in 0..12_u16 {
                            let packet = rtp::packet::Packet {
                                header: rtp::header::Header {
                                    version: 2,
                                    marker: true,
                                    sequence_number: index + 1,
                                    timestamp: u32::from(index + 1) * 3000,
                                    ..Default::default()
                                },
                                payload: Bytes::from_static(b"\x98\x36\xbe\x88\x9e"),
                            };
                            media.video.write_rtp(&packet).await?;
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    }
                    Ok(())
                }
                .await;
                if let Err(error) = result {
                    record_failure(&observations, error);
                }
            }
        })
    }));

    let message_channel = Arc::clone(&channel);
    let message_observations = Arc::clone(&observations);
    channel.on_message(Box::new(move |message| {
        let channel = Arc::clone(&message_channel);
        let observations = Arc::clone(&message_observations);
        Box::pin(async move {
            let result: Result<()> = async {
                if message.is_string {
                    let text = String::from_utf8(message.data.to_vec())?;
                    let expected = match behavior {
                        ChannelBehavior::Initiate => "rust-moonbit-text",
                        ChannelBehavior::Echo => "moonbit-rust-text",
                    };
                    if text != expected {
                        bail!("unexpected text payload from MoonBit: {text:?}");
                    }
                    if matches!(behavior, ChannelBehavior::Echo) {
                        channel.send_text(text).await?;
                    }
                    observations.lock().expect("observations mutex").saw_text = true;
                } else {
                    if message.data != binary_fixture() {
                        bail!(
                            "unexpected binary payload from MoonBit: {} bytes",
                            message.data.len()
                        );
                    }
                    if matches!(behavior, ChannelBehavior::Echo) {
                        channel.send(&message.data).await?;
                    }
                    observations.lock().expect("observations mutex").saw_binary = true;
                }
                Ok(())
            }
            .await;
            if let Err(error) = result {
                record_failure(&observations, error);
            }
        })
    }));
}

async fn add_media_senders(peer: &Arc<RTCPeerConnection>) -> Result<MediaSenders> {
    let audio = Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_OPUS.to_owned(),
            clock_rate: 48_000,
            channels: 2,
            sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
            ..Default::default()
        },
        "rust-audio".to_owned(),
        "rust-media".to_owned(),
    ));
    let video = Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_VP8.to_owned(),
            clock_rate: 90_000,
            ..Default::default()
        },
        "rust-video".to_owned(),
        "rust-media".to_owned(),
    ));
    let audio_track: Arc<dyn TrackLocal + Send + Sync> = audio.clone();
    let video_track: Arc<dyn TrackLocal + Send + Sync> = video.clone();
    peer.add_track(audio_track).await?;
    peer.add_track(video_track).await?;
    Ok(MediaSenders { audio, video })
}

fn install_media_receiver(peer: &Arc<RTCPeerConnection>, observations: &Arc<Mutex<Observations>>) {
    let track_observations = Arc::clone(observations);
    peer.on_track(Box::new(move |track, _, _| {
        let observations = Arc::clone(&track_observations);
        tokio::spawn(async move {
            match track.read_rtp().await {
                Ok(_) => {
                    let mut current = observations.lock().expect("observations mutex");
                    match track.kind() {
                        RTPCodecType::Audio => current.saw_audio = true,
                        RTPCodecType::Video => current.saw_video = true,
                        RTPCodecType::Unspecified => {
                            current.failure =
                                Some("Rust received an unspecified media track".to_owned());
                        }
                    }
                }
                Err(error) => {
                    observations.lock().expect("observations mutex").failure =
                        Some(format!("Rust failed to read remote RTP: {error}"));
                }
            }
        });
        Box::pin(async {})
    }));
}

async fn await_file(path: &Path) -> Result<String> {
    let started = Instant::now();
    loop {
        match tokio::fs::read_to_string(path).await {
            Ok(contents) => return Ok(contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        }
        if started.elapsed() >= RUN_TIMEOUT {
            bail!("timed out waiting for {}", path.display());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn publish_file(path: &Path, contents: &str) -> Result<()> {
    let temporary = path.with_extension("tmp");
    tokio::fs::write(&temporary, contents)
        .await
        .with_context(|| format!("write {}", temporary.display()))?;
    tokio::fs::rename(&temporary, path)
        .await
        .with_context(|| format!("publish {}", path.display()))?;
    Ok(())
}

fn install_peer_handlers(peer: &Arc<RTCPeerConnection>, observations: &Arc<Mutex<Observations>>) {
    let state_observations = Arc::clone(observations);
    peer.on_peer_connection_state_change(Box::new(move |state| {
        let observations = Arc::clone(&state_observations);
        Box::pin(async move {
            eprintln!("Rust WebRTC peer connection state: {state}");
            if state == RTCPeerConnectionState::Failed {
                observations.lock().expect("observations mutex").failure =
                    Some("Rust WebRTC peer connection entered Failed".to_owned());
            }
        })
    }));
    peer.on_ice_connection_state_change(Box::new(move |state| {
        Box::pin(async move {
            eprintln!("Rust WebRTC ICE state: {state}");
            if state == RTCIceConnectionState::Failed {
                eprintln!("Rust WebRTC ICE failed");
            }
        })
    }));
}

async fn gathered_local_description(peer: &RTCPeerConnection) -> Result<RTCSessionDescription> {
    let mut gathering_complete = peer.gathering_complete_promise().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), gathering_complete.recv()).await;
    let description = peer
        .local_description()
        .await
        .context("WebRTC peer has no gathered local description")?;
    validate_loopback_candidates(&description.sdp)?;
    Ok(description)
}

fn validate_loopback_candidates(sdp: &str) -> Result<()> {
    let mut candidate_count = 0;
    for line in sdp.lines() {
        let Some(candidate) = line.strip_prefix("a=candidate:") else {
            continue;
        };
        candidate_count += 1;
        let fields: Vec<_> = candidate.split_ascii_whitespace().collect();
        if fields.len() < 8 || fields[6] != "typ" {
            bail!("malformed Rust ICE candidate: {line}");
        }
        if !fields[2].eq_ignore_ascii_case("udp") || fields[4] != "127.0.0.1" || fields[7] != "host"
        {
            bail!("Rust ICE candidate escaped the loopback-only fixture: {line}");
        }
    }
    if candidate_count == 0 {
        bail!("Rust local SDP contains no ICE candidates");
    }
    Ok(())
}

async fn exchange_descriptions(
    peer: &Arc<RTCPeerConnection>,
    role: PeerRole,
    offer_path: &Path,
    answer_path: &Path,
) -> Result<()> {
    match role {
        PeerRole::Offerer => {
            let offer = peer.create_offer(None).await?;
            peer.set_local_description(offer).await?;
            let local_description = gathered_local_description(peer).await?;
            publish_file(offer_path, &local_description.sdp).await?;
            eprintln!("Rust WebRTC offer published");
            let answer = RTCSessionDescription::answer(await_file(answer_path).await?)?;
            peer.set_remote_description(answer).await?;
        }
        PeerRole::Answerer => {
            let offer = RTCSessionDescription::offer(await_file(offer_path).await?)?;
            peer.set_remote_description(offer).await?;
            let answer = peer.create_answer(None).await?;
            peer.set_local_description(answer).await?;
            let local_description = gathered_local_description(peer).await?;
            publish_file(answer_path, &local_description.sdp).await?;
            eprintln!("Rust WebRTC answer published");
        }
    }
    Ok(())
}

async fn run_peer(
    role: PeerRole,
    mode: InteropMode,
    offer_path: &Path,
    answer_path: &Path,
    moon_result_path: &Path,
    rust_result_path: &Path,
) -> Result<()> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut setting_engine = SettingEngine::default();
    setting_engine.set_network_types(vec![NetworkType::Udp4]);
    setting_engine.set_include_loopback_candidate(true);
    setting_engine.set_ip_filter(Box::new(|ip| ip == IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let peer = Arc::new(
        APIBuilder::new()
            .with_media_engine(media_engine)
            .with_setting_engine(setting_engine)
            .build()
            .new_peer_connection(RTCConfiguration::default())
            .await?,
    );
    let observations = Arc::new(Mutex::new(Observations::default()));
    install_peer_handlers(&peer, &observations);
    if mode == InteropMode::Media {
        install_media_receiver(&peer, &observations);
    }
    let media_senders = if role == PeerRole::Offerer && mode == InteropMode::Media {
        Some(add_media_senders(&peer).await?)
    } else {
        None
    };

    match role {
        PeerRole::Offerer => {
            let options = match mode {
                InteropMode::Reliable | InteropMode::Media => None,
                InteropMode::Partial => Some(RTCDataChannelInit {
                    ordered: Some(false),
                    max_retransmits: Some(2),
                    ..Default::default()
                }),
            };
            let channel = peer.create_data_channel("interop", options).await?;
            install_channel_handlers(
                channel,
                ChannelBehavior::Initiate,
                mode,
                media_senders,
                Arc::clone(&observations),
            );
        }
        PeerRole::Answerer => {
            let channel_observations = Arc::clone(&observations);
            peer.on_data_channel(Box::new(move |channel: Arc<RTCDataChannel>| {
                install_channel_handlers(
                    channel,
                    ChannelBehavior::Echo,
                    mode,
                    None,
                    Arc::clone(&channel_observations),
                );
                Box::pin(async {})
            }));
        }
    }

    exchange_descriptions(&peer, role, offer_path, answer_path).await?;

    let started = Instant::now();
    loop {
        let (opened, text, binary, audio, video, failure) = {
            let current = observations.lock().expect("observations mutex");
            (
                current.channel_opened,
                current.saw_text,
                current.saw_binary,
                current.saw_audio,
                current.saw_video,
                current.failure.clone(),
            )
        };
        if let Some(failure) = failure {
            bail!("{failure}");
        }
        let moon_finished = tokio::fs::try_exists(moon_result_path).await?;
        let media_complete =
            mode != InteropMode::Media || role == PeerRole::Offerer || (audio && video);
        if opened && text && binary && media_complete && moon_finished {
            break;
        }
        if started.elapsed() >= RUN_TIMEOUT {
            bail!(
                "interop timed out (role={role:?}, open={opened}, text={text}, binary={binary}, audio={audio}, video={video}, result={moon_finished})"
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    publish_file(rust_result_path, "ok\n").await?;
    // Let the MoonBit side observe the completion marker and initiate the
    // orderly close before this process tears down its DTLS transport.
    tokio::time::sleep(Duration::from_millis(250)).await;
    peer.close().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    log::set_logger(&DTLS_LOGGER).map_err(|_| anyhow::anyhow!("install DTLS logger"))?;
    log::set_max_level(LevelFilter::Trace);
    let arguments: Vec<String> = std::env::args().collect();
    let [
        _,
        role,
        mode,
        offer_path,
        answer_path,
        moon_result_path,
        rust_result_path,
    ] = arguments.as_slice()
    else {
        bail!("usage: rust-peer ROLE MODE OFFER_SDP ANSWER_SDP MOON_RESULT RUST_RESULT");
    };
    let role = match role.as_str() {
        "offer" => PeerRole::Offerer,
        "answer" => PeerRole::Answerer,
        _ => bail!("ROLE must be offer or answer"),
    };
    let mode = match mode.as_str() {
        "reliable" => InteropMode::Reliable,
        "partial" => InteropMode::Partial,
        "media" => InteropMode::Media,
        _ => bail!("MODE must be reliable, partial, or media"),
    };
    run_peer(
        role,
        mode,
        Path::new(offer_path),
        Path::new(answer_path),
        Path::new(moon_result_path),
        Path::new(rust_result_path),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::validate_loopback_candidates;

    #[test]
    fn accepts_udp4_loopback_host_candidates() {
        let sdp = concat!(
            "v=0\r\n",
            "a=candidate:1 1 udp 2130706431 127.0.0.1 50000 typ host\r\n",
            "a=candidate:2 1 UDP 2130706431 127.0.0.1 50001 typ host\r\n",
        );
        validate_loopback_candidates(sdp).unwrap();
    }

    #[test]
    fn rejects_candidates_outside_the_fixture_topology() {
        for candidate in [
            "a=candidate:1 1 udp 2130706431 10.1.0.112 50000 typ host\r\n",
            "a=candidate:1 1 udp 2130706431 ::1 50000 typ host\r\n",
            "a=candidate:1 1 tcp 2130706431 127.0.0.1 50000 typ host\r\n",
            "a=candidate:1 1 udp 2130706431 127.0.0.1 50000 typ srflx\r\n",
        ] {
            let error = validate_loopback_candidates(candidate).unwrap_err();
            assert!(
                error.to_string().contains(candidate.trim_end()),
                "error did not identify the rejected candidate: {error:#}"
            );
        }
    }

    #[test]
    fn rejects_missing_or_malformed_candidates() {
        let missing = validate_loopback_candidates("v=0\r\n").unwrap_err();
        assert!(missing.to_string().contains("no ICE candidates"));

        let malformed =
            validate_loopback_candidates("a=candidate:1 1 udp 2130706431\r\n").unwrap_err();
        assert!(malformed.to_string().contains("malformed"));
    }
}
