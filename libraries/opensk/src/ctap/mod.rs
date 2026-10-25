// Copyright 2019-2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod apdu;
mod client_pin;
pub mod command;
#[cfg(feature = "config_command")]
mod config_command;
mod credential_management;
pub mod crypto_wrapper;
#[cfg(feature = "ctap1")]
mod ctap1;
pub mod data_formats;
#[cfg(feature = "fingerprint")]
pub mod fingerprint;
pub mod hid;
mod large_blobs;
pub mod main_hid;
pub mod mtc;
mod pin_protocol;
pub mod response;
pub mod secret;
pub mod status_code;
mod storage;
mod token_state;
#[cfg(feature = "ctap1")]
mod u2f_up;
#[cfg(feature = "vendor_hid")]
pub mod vendor_hid;

pub use self::client_pin::PIN_AUTH_LENGTH;
use self::client_pin::{ClientPin, PinPermission};
use self::command::{
    AuthenticatorGetAssertionParameters, AuthenticatorMakeCredentialParameters, Command,
};
#[cfg(feature = "config_command")]
use self::config_command::process_config;
use self::credential_management::process_credential_management;
use self::data_formats::{
    AuthenticatorTransport, CredentialProtectionPolicy, EnterpriseAttestationMode,
    GetAssertionExtensions, PackedAttestationStatement, PinUvAuthProtocol,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameter, PublicKeyCredentialSource,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, SignatureAlgorithm,
};
#[cfg(feature = "fingerprint")]
use self::fingerprint::{EnrollmentStatus, perform_built_in_uv, process_bio_enrollment};
use self::hid::{
    ChannelID, CtapHid, CtapHidCommand, HidPacketIterator, KeepaliveStatus, ProcessedPacket,
};
use self::large_blobs::LargeBlobState;
use self::response::{
    AuthenticatorGetAssertionResponse, AuthenticatorGetInfoResponse,
    AuthenticatorMakeCredentialResponse, ResponseData,
};
use self::secret::Secret;
use self::status_code::{Ctap2StatusCode, CtapResult};
#[cfg(feature = "ctap1")]
use self::u2f_up::U2fUserPresenceState;
use crate::api::clock::Clock;
use crate::api::connection::{HidConnection, RecvStatus, UsbEndpoint};
use crate::api::crypto::HASH_SIZE;
#[cfg(test)]
use crate::api::crypto::ec_signing::{EcSecretKey, EcSignature};
use crate::api::crypto::hkdf256::Hkdf256;
use crate::api::crypto::sha256::Sha256;
use crate::api::customization::Customization;
#[cfg(feature = "fingerprint")]
use crate::api::fingerprint::Fingerprint;
use crate::api::key_store::{CredentialSource, KeyStore, MAX_CREDENTIAL_ID_SIZE};
use crate::api::persist::{Attestation, AttestationId, Persist};
use crate::api::private_key::PrivateKey;
use crate::api::rng::Rng;
use crate::api::user_presence::{UserPresence, UserPresenceError};
#[cfg(test)]
use crate::env::EcdsaSk;
use crate::env::{Env, Hkdf, Sha};
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use core::convert::TryFrom;
use rand_core::RngCore;
use sk_cbor as cbor;
use sk_cbor::cbor_map_options;

// Set this bit when checking user presence.
const UP_FLAG: u8 = 0x01;
// Set this bit when checking user verification.
const UV_FLAG: u8 = 0x04;
// Set this bit when performing attestation.
const AT_FLAG: u8 = 0x40;
// Set this bit when an extension is used.
const ED_FLAG: u8 = 0x80;

// CTAP2 specification section 6 requires that the depth of nested CBOR structures be limited to at most four levels.
const MAX_CBOR_NESTING_DEPTH: i8 = 4;

pub const KEEPALIVE_DELAY_MS: usize = 100;
pub const TOUCH_TIMEOUT_MS: usize = 30000;
const RESET_TIMEOUT_DURATION_MS: usize = 10000;
const STATEFUL_COMMAND_TIMEOUT_DURATION_MS: usize = 30000;

pub const FIDO2_VERSION_STRING: &str = "FIDO_2_0";
#[cfg(feature = "ctap1")]
pub const U2F_VERSION_STRING: &str = "U2F_V2";
pub const FIDO2_1_VERSION_STRING: &str = "FIDO_2_1";
pub const FIDO2_3_VERSION_STRING: &str = "FIDO_2_3";

// We currently only support one algorithm for signatures: ES256.
// This algorithm is requested in MakeCredential and advertized in GetInfo.
pub const ES256_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::Es256,
};

#[cfg(feature = "es384")]
pub const ES384_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::Es384,
};

#[cfg(feature = "es512")]
pub const ES512_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::Es512,
};

#[cfg(feature = "es256k")]
pub const ES256K_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::Es256k,
};

#[cfg(feature = "ed25519")]
pub const EDDSA_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::Eddsa,
};

#[cfg(feature = "ed448")]
pub const ED448_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::Ed448,
};

#[cfg(feature = "mldsa")]
pub const ML_DSA_44_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::MlDsa44,
};

#[cfg(feature = "mldsa")]
pub const ML_DSA_65_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::MlDsa65,
};

#[cfg(feature = "mldsa")]
pub const ML_DSA_87_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::MlDsa87,
};

#[cfg(feature = "pq_composite")]
pub const ML_DSA_44_ES256_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::MlDsa44Es256,
};

#[cfg(feature = "pq_composite")]
pub const ML_DSA_65_ES256_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::MlDsa65Es256,
};

#[cfg(feature = "pq_composite")]
pub const ML_DSA_87_ES384_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::MlDsa87Es384,
};

#[cfg(feature = "pq_composite")]
pub const ML_DSA_44_ED25519_CRED_PARAM: PublicKeyCredentialParameter =
    PublicKeyCredentialParameter {
        cred_type: PublicKeyCredentialType::PublicKey,
        alg: SignatureAlgorithm::MlDsa44Ed25519,
    };

#[cfg(feature = "pq_composite")]
pub const ML_DSA_65_ED25519_CRED_PARAM: PublicKeyCredentialParameter =
    PublicKeyCredentialParameter {
        cred_type: PublicKeyCredentialType::PublicKey,
        alg: SignatureAlgorithm::MlDsa65Ed25519,
    };

#[cfg(feature = "pq_composite")]
pub const ML_DSA_87_ED448_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::MlDsa87Ed448,
};

#[cfg(feature = "rs256")]
pub const RS256_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::Rs256,
};

#[cfg(feature = "fndsa")]
pub const FN_DSA_512_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::FnDsa512,
};

#[cfg(feature = "fndsa")]
pub const FN_DSA_1024_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::FnDsa1024,
};

const SUPPORTED_CRED_PARAMS: &[PublicKeyCredentialParameter] = &[
    ES256_CRED_PARAM,
    #[cfg(feature = "es384")]
    ES384_CRED_PARAM,
    #[cfg(feature = "es512")]
    ES512_CRED_PARAM,
    #[cfg(feature = "es256k")]
    ES256K_CRED_PARAM,
    #[cfg(feature = "ed25519")]
    EDDSA_CRED_PARAM,
    #[cfg(feature = "ed448")]
    ED448_CRED_PARAM,
    #[cfg(feature = "mldsa")]
    ML_DSA_44_CRED_PARAM,
    #[cfg(feature = "mldsa")]
    ML_DSA_65_CRED_PARAM,
    #[cfg(feature = "mldsa")]
    ML_DSA_87_CRED_PARAM,
    #[cfg(feature = "pq_composite")]
    ML_DSA_44_ES256_CRED_PARAM,
    #[cfg(feature = "pq_composite")]
    ML_DSA_65_ES256_CRED_PARAM,
    #[cfg(feature = "pq_composite")]
    ML_DSA_87_ES384_CRED_PARAM,
    #[cfg(feature = "pq_composite")]
    ML_DSA_44_ED25519_CRED_PARAM,
    #[cfg(feature = "pq_composite")]
    ML_DSA_65_ED25519_CRED_PARAM,
    #[cfg(feature = "pq_composite")]
    ML_DSA_87_ED448_CRED_PARAM,
    #[cfg(feature = "fndsa")]
    FN_DSA_512_CRED_PARAM,
    #[cfg(feature = "fndsa")]
    FN_DSA_1024_CRED_PARAM,
    #[cfg(feature = "rs256")]
    RS256_CRED_PARAM,
];

fn get_preferred_cred_param(
    params: &[PublicKeyCredentialParameter],
) -> Option<&PublicKeyCredentialParameter> {
    params
        .iter()
        .find(|&param| SUPPORTED_CRED_PARAMS.contains(param))
}

/// Transports supported by OpenSK.
///
/// An OpenSK library user annotates incoming data with this data type.
///
/// The difference between this data type and `AuthenticatorTransport` is that the latter
/// corresponds to the communication defined in the CTAP specification. This data type describes
/// the hardware path a packet took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Corresponds to CTAP's USB transport.
    MainHid,
    /// No equivalent in CTAP, used for communication outside the specification.
    #[cfg(feature = "vendor_hid")]
    VendorHid,
}

impl Transport {
    pub fn usb_endpoint(self) -> UsbEndpoint {
        match self {
            Transport::MainHid => UsbEndpoint::MainHid,
            #[cfg(feature = "vendor_hid")]
            Transport::VendorHid => UsbEndpoint::VendorHid,
        }
    }
}

/// Communication channels between authenticator and client.
///
/// From OpenSK's perspective, a channel represents a client. When we receive data from a new
/// channel, we have to assume it's a new client.
///
/// For HID, communication channels coincide with the channel ID. NFC and HID transports are unique
/// channels themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// Corresponds to CTAP's USB transport.
    MainHid(ChannelID),
    /// No equivalent in CTAP, used for communication outside the specification.
    #[cfg(feature = "vendor_hid")]
    VendorHid(ChannelID),
}

// Helpers to perform CBOR read/write while respecting CTAP2 nesting limits.
pub fn cbor_read(encoded_cbor: &[u8]) -> CtapResult<cbor::Value> {
    cbor::reader::read_nested(encoded_cbor, Some(MAX_CBOR_NESTING_DEPTH))
        .map_err(|_e| Ctap2StatusCode::CTAP2_ERR_INVALID_CBOR)
}

pub fn cbor_write(value: cbor::Value, encoded_cbor: &mut Vec<u8>) -> CtapResult<()> {
    cbor::writer::write_nested(value, encoded_cbor, Some(MAX_CBOR_NESTING_DEPTH))
        .map_err(|_e| Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
}

/// Resets the all state for a CTAP Reset command.
pub fn reset(env: &mut impl Env) -> CtapResult<()> {
    #[cfg(feature = "fingerprint")]
    {
        let template_infos = env.persist().template_infos()?;
        for template_info in template_infos {
            env.fingerprint()
                .remove_enrollment(&template_info.template_id)?;
            env.persist()
                .remove_template_id(&template_info.template_id)?;
        }
    }
    env.persist().reset()?;
    env.key_store().reset()?;
    storage::init(env)
}

/// Filters the credential from the option if credProtect criteria are not met.
pub fn filter_listed_credential(
    credential: Option<CredentialSource>,
    has_uv: bool,
) -> Option<CredentialSource> {
    credential.filter(|c| {
        has_uv
            || !matches!(
                c.cred_protect_policy,
                Some(CredentialProtectionPolicy::UserVerificationRequired)
            )
    })
}

/// Filters the resident key from the option if credProtect criteria are not met.
fn filter_listed_resident_credential(
    credential: Option<PublicKeyCredentialSource>,
    has_uv: bool,
) -> Option<PublicKeyCredentialSource> {
    credential.filter(|c| {
        has_uv
            || !matches!(
                c.cred_protect_policy,
                Some(CredentialProtectionPolicy::UserVerificationRequired)
            )
    })
}

/// Populates all matching fields in a `PublicKeyCredentialSource`.
fn to_public_source(
    credential_id: Vec<u8>,
    credential_source: CredentialSource,
) -> PublicKeyCredentialSource {
    PublicKeyCredentialSource {
        key_type: PublicKeyCredentialType::PublicKey,
        credential_id,
        wrapped_private_key: credential_source.wrapped_private_key,
        rp_id: String::new(),
        user_handle: Vec::new(),
        user_display_name: None,
        cred_protect_policy: credential_source.cred_protect_policy,
        creation_order: 0,
        user_name: None,
        user_icon: None,
        cred_blob: credential_source.cred_blob,
        large_blob_key: None,
        third_party_payment: credential_source.third_party_payment,
    }
}

// This function is adapted from https://doc.rust-lang.org/nightly/src/core/str/mod.rs.html#2110
// (as of 2020-01-20) and truncates to "max" bytes, not breaking the encoding.
// We change the return value, since we don't need the bool.
fn truncate_to_char_boundary(s: &str, mut max: usize) -> &str {
    if max >= s.len() {
        s
    } else {
        while !s.is_char_boundary(max) {
            max -= 1;
        }
        &s[..max]
    }
}

// For MakeCredential and GetAssertion, the specification says:
// If the uvRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED. See:
// https://github.com/fido-alliance/fido-2-specs/issues/1672 (private)
#[cfg(feature = "fingerprint")]
fn map_uv_block_error(result: CtapResult<()>) -> CtapResult<()> {
    result.map_err(|e| match e {
        Ctap2StatusCode::CTAP2_ERR_UV_BLOCKED => Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED,
        other => other,
    })
}

/// Send non-critical packets using fire-and-forget.
pub fn send_packets<E: Env>(
    env: &mut E,
    endpoint: UsbEndpoint,
    packets: HidPacketIterator,
) -> CtapResult<()> {
    for pkt in packets {
        env.hid_connection().send(&pkt, endpoint)?;
    }
    Ok(())
}

fn is_cancel(packet: &ProcessedPacket) -> bool {
    match packet {
        ProcessedPacket::InitPacket { cmd, .. } => *cmd == CtapHidCommand::Cancel as u8,
        ProcessedPacket::ContinuationPacket { .. } => false,
    }
}

fn wait_and_respond_busy<E: Env>(env: &mut E, channel: Channel) -> CtapResult<()> {
    let (cid, transport) = match channel {
        Channel::MainHid(cid) => (cid, Transport::MainHid),
        #[cfg(feature = "vendor_hid")]
        Channel::VendorHid(cid) => (cid, Transport::VendorHid),
    };
    let endpoint = transport.usb_endpoint();

    let mut packet = [0; 64];
    let (up_status, recv_status) = env
        .user_presence()
        .wait_with_timeout(&mut packet, KEEPALIVE_DELAY_MS)?;
    match recv_status {
        RecvStatus::Timeout => (),
        RecvStatus::Received(rx_endpoint) => {
            let (received_cid, processed_packet) = CtapHid::<E>::process_single_packet(&packet);
            if rx_endpoint != endpoint || received_cid != cid {
                debug_ctap!(
                    env,
                    "Received an unrelated packet on endpoint {:?} while sending a KEEPALIVE packet",
                    rx_endpoint,
                );
                let busy_error = CtapHid::<E>::busy_error(received_cid);
                // Don't send errors from other channels on the active channel.
                let _ = send_packets(env, rx_endpoint, busy_error);
            } else if is_cancel(&processed_packet) {
                // Ignored, CANCEL specification says: "the authenticator MUST NOT reply"
                debug_ctap!(env, "User presence check cancelled");
                return Err(UserPresenceError::Canceled.into());
            } else {
                // Ignored. A client shouldn't try to talk to us on this channel yet.
                debug_ctap!(env, "Discarded packet while checking user presence.");
            }
        }
    }
    if matches!(up_status, Err(UserPresenceError::Timeout)) {
        let keepalive_msg = CtapHid::<E>::keepalive(cid, KeepaliveStatus::UpNeeded);
        send_packets(env, endpoint, keepalive_msg)?;
    }
    up_status.map_err(|e| e.into())
}

/// Blocks for user presence.
///
/// Returns an error in case of timeout, user declining presence request, or keepalive error.
#[cfg_attr(
    feature = "up_always_true",
    allow(unreachable_code, unused_variables)
)]
pub fn check_user_presence<E: Env>(env: &mut E, channel: Channel) -> CtapResult<()> {
    #[cfg(feature = "up_always_true")]
    {
        let (cid, transport) = match channel {
            Channel::MainHid(cid) => (cid, Transport::MainHid),
            #[cfg(feature = "vendor_hid")]
            Channel::VendorHid(cid) => (cid, Transport::VendorHid),
        };
        let endpoint = transport.usb_endpoint();

        // Send initial KEEPALIVE (STATUS_UPNEEDED) so host knows user interaction is pending.
        // This satisfies P-9, P-10, and P-15 in the FIDO conformance test suite.
        let keepalive_msg = CtapHid::<E>::keepalive(cid, KeepaliveStatus::UpNeeded);
        let _ = send_packets(env, endpoint, keepalive_msg);

        // Poll for incoming CTAPHID_CANCEL packets for 180 ms.
        // P-15 in the FIDO conformance test suite waits 150 ms before reading KEEPALIVE
        // and sending CTAPHID_CANCEL. 180 ms provides plenty of margin while minimizing ceremony latency.
        let mut packet = [0; 64];
        let delay_timer = env.clock().make_timer(180);
        let mut keepalive_timer = env.clock().make_timer(KEEPALIVE_DELAY_MS);
        while !env.clock().is_elapsed(&delay_timer) {
            if env.clock().is_elapsed(&keepalive_timer) {
                let keepalive_msg = CtapHid::<E>::keepalive(cid, KeepaliveStatus::UpNeeded);
                let _ = send_packets(env, endpoint, keepalive_msg);
                keepalive_timer = env.clock().make_timer(KEEPALIVE_DELAY_MS);
            }
            match env.hid_connection().recv(&mut packet, 20) {
                Ok(RecvStatus::Received(rx_endpoint)) => {
                    let (received_cid, processed_packet) =
                        CtapHid::<E>::process_single_packet(&packet);
                    if rx_endpoint != endpoint || received_cid != cid {
                        let busy_error = CtapHid::<E>::busy_error(received_cid);
                        let _ = send_packets(env, rx_endpoint, busy_error);
                    } else if is_cancel(&processed_packet) {
                        debug_ctap!(env, "User presence check cancelled");
                        return Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL);
                    }
                }
                _ => (),
            }
        }

        return Ok(());
    }

    const TIMEOUT_ERROR: Ctap2StatusCode = Ctap2StatusCode::CTAP2_ERR_USER_ACTION_TIMEOUT;

    env.user_presence().check_init();
    let loop_timer = env.clock().make_timer(TOUCH_TIMEOUT_MS);

    // We don't use the '?' operator to always reach check_complete(...).
    let mut result = Err(TIMEOUT_ERROR);
    while !env.clock().is_elapsed(&loop_timer) {
        match wait_and_respond_busy(env, channel) {
            Err(TIMEOUT_ERROR) => (),
            r => {
                result = r;
                // We want to break on Ok(()) too, indicating touch.
                break;
            }
        }
    }

    env.user_presence().check_complete();
    result
}

/// Holds data necessary to sign an assertion for a credential.
#[derive(Clone)]
pub struct AssertionInput {
    client_data_hash: Vec<u8>,
    auth_data: Vec<u8>,
    extensions: GetAssertionExtensions,
    has_uv: bool,
}

/// Contains the state we need to store for GetNextAssertion.
pub struct AssertionState {
    assertion_input: AssertionInput,
    // Sorted by ascending order of creation, so the last element is the most recent one.
    next_credential_keys: Vec<usize>,
}

/// Stores which command currently holds state for subsequent calls.
pub enum StatefulCommand {
    Reset,
    GetAssertion(Box<AssertionState>),
    EnumerateRps(usize),
    EnumerateCredentials(Vec<usize>),
    LargeBlob(LargeBlobState),
}

/// Stores the current CTAP command state and when it times out.
///
/// Some commands are executed in a series of calls to the authenticator.
/// Interleaving calls to other commands interrupt the current command and
/// remove all state and permissions. Power cycling allows the Reset command,
/// and to prevent misuse or accidents, we disallow Reset after receiving
/// different commands. Therefore, Reset behaves just like all other stateful
/// commands and is included here. Please note that the allowed time for Reset
/// differs from all other stateful commands.
///
/// Additionally, state that is held over multiple commands is assigned to a channel. We discard
/// all state when we receive data on a different channel.
pub struct StatefulPermission<E: Env> {
    permission: <E::Clock as Clock>::Timer,
    command_type: Option<StatefulCommand>,
    channel: Option<Channel>,
}

impl<E: Env> Default for StatefulPermission<E> {
    /// Creates the command state at device startup without user action.
    ///
    /// Reset is not granted after a forced reboot. The user replugging the device is a required
    /// to avoid accidental data loss.
    fn default() -> StatefulPermission<E> {
        StatefulPermission {
            permission: <E::Clock as Clock>::Timer::default(),
            command_type: None,
            channel: None,
        }
    }
}

impl<E: Env> StatefulPermission<E> {
    /// Creates the command state at device startup.
    ///
    /// Resets are only possible after a power cycle. Therefore, there is no way to grant the Reset
    /// permission outside of this function. If you initialize the app without a power cycle
    /// (potentially after waking up from sleep), call `default` instead.
    pub fn new_reset(env: &mut E) -> StatefulPermission<E> {
        StatefulPermission {
            permission: env.clock().make_timer(RESET_TIMEOUT_DURATION_MS),
            command_type: Some(StatefulCommand::Reset),
            channel: None,
        }
    }

    /// Clears all permissions and state.
    pub fn clear(&mut self) {
        self.permission = <E::Clock as Clock>::Timer::default();
        self.command_type = None;
        self.channel = None;
    }

    /// Clears all state if communication is coming from a different channel.
    pub fn clear_old_channels(&mut self, channel: Channel) {
        // There are different possible choices for incoming traffic on a different channel:
        // A) Always reset state (our choice).
        // B) Only reset state if the new command is stateful.
        // C) Keep state on all channels until timeout.
        //
        // If we wanted to switch to (B) or (C), we'd have to be very careful that the state does
        // not go stale. For example, we keep credential keys that we expect to still exist.
        // However, interleaving (stateless) commands could delete credentials or change the PIN,
        // which could invalidate our access. Some read-only commands should be okay to run,
        // but (A) is the safest and easiest solution.
        if let Some(c) = self.channel
            && c != channel
        {
            self.clear();
        }
    }

    /// Clears all state if the permission timed out.
    fn clear_timer(&mut self, env: &mut E) {
        if env.clock().is_elapsed(&self.permission) {
            self.clear();
        }
    }

    /// Gets a reference to the current command state, if any exists.
    pub fn get_command(&mut self, env: &mut E) -> CtapResult<&StatefulCommand> {
        self.clear_timer(env);
        self.command_type
            .as_ref()
            .ok_or(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
    }

    /// Sets a new command state, and starts a new clock for timeouts.
    pub fn set_command(
        &mut self,
        env: &mut E,
        new_command_type: StatefulCommand,
        channel: Channel,
    ) {
        match &new_command_type {
            // Reset is only allowed after a power cycle.
            StatefulCommand::Reset => unreachable!(),
            _ => {
                self.permission = env.clock().make_timer(STATEFUL_COMMAND_TIMEOUT_DURATION_MS);
                self.command_type = Some(new_command_type);
                self.channel = Some(channel);
            }
        }
    }

    /// Returns the state for the next assertion and advances it.
    ///
    /// The state includes all information from GetAssertion and the storage key
    /// to the next credential that needs to be processed.
    pub fn next_assertion_credential(
        &mut self,
        env: &mut E,
    ) -> Result<(AssertionInput, usize), Ctap2StatusCode> {
        self.clear_timer(env);
        if let Some(StatefulCommand::GetAssertion(assertion_state)) = &mut self.command_type {
            let credential_key = assertion_state
                .next_credential_keys
                .pop()
                .ok_or(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)?;
            Ok((assertion_state.assertion_input.clone(), credential_key))
        } else {
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        }
    }

    /// Returns the index to the next RP ID for enumeration and advances it.
    pub fn next_enumerate_rp(&mut self, env: &mut E) -> CtapResult<usize> {
        self.clear_timer(env);
        if let Some(StatefulCommand::EnumerateRps(rp_id_index)) = &mut self.command_type {
            let current_index = *rp_id_index;
            *rp_id_index += 1;
            Ok(current_index)
        } else {
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        }
    }

    /// Returns the next storage credential key for enumeration and advances it.
    pub fn next_enumerate_credential(&mut self, env: &mut E) -> CtapResult<usize> {
        self.clear_timer(env);
        if let Some(StatefulCommand::EnumerateCredentials(rp_credentials)) = &mut self.command_type
        {
            rp_credentials
                .pop()
                .ok_or(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        } else {
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        }
    }

    /// Returns the large blob state. If none is hold, create and hold a new state.
    pub fn large_blob(&mut self, env: &mut E, channel: Channel) -> &mut LargeBlobState {
        self.clear_timer(env);
        if let Some(StatefulCommand::LargeBlob(_)) = &self.command_type {
        } else {
            self.set_command(
                env,
                StatefulCommand::LargeBlob(LargeBlobState::default()),
                channel,
            );
        }
        if let Some(StatefulCommand::LargeBlob(large_blob_state)) = &mut self.command_type {
            large_blob_state
        } else {
            unreachable!();
        }
    }
}

// This struct currently holds all state, not only the persistent memory. The persistent members are
// in the persistent store field.
pub struct CtapState<E: Env> {
    client_pin: ClientPin<E>,
    #[cfg(feature = "ctap1")]
    pub(crate) u2f_up_state: U2fUserPresenceState<E>,
    // The state initializes to Reset and its timeout, and never goes back to Reset.
    stateful_command_permission: StatefulPermission<E>,
    // While fingerprint enrollment is in progress, we store its progress here.
    // Despite being state of a command, by the CTAP standard, BioEnrollment is
    // not a "stateful command".
    #[cfg(feature = "fingerprint")]
    fingerprint_enrollment_status: EnrollmentStatus,
}

impl<E: Env> CtapState<E> {
    pub fn new(env: &mut E) -> Self {
        storage::init(env).ok().unwrap();
        let client_pin = ClientPin::new(env);
        let stateful_command_permission = if env.boots_after_soft_reset() {
            StatefulPermission::default()
        } else {
            StatefulPermission::new_reset(env)
        };
        CtapState {
            client_pin,
            #[cfg(feature = "ctap1")]
            u2f_up_state: U2fUserPresenceState::new(),
            stateful_command_permission,
            #[cfg(feature = "fingerprint")]
            fingerprint_enrollment_status: EnrollmentStatus::default(),
        }
    }

    pub fn increment_global_signature_counter(&mut self, env: &mut E) -> CtapResult<()> {
        if env.customization().use_signature_counter() {
            let increment = env.rng().next_u32() % 8 + 1;
            env.persist().incr_global_signature_counter(increment)?;
        }
        Ok(())
    }

    // Returns whether CTAP1 commands are currently supported.
    // If alwaysUv is enabled and the authenticator does not support internal UV,
    // CTAP1 needs to be disabled.
    #[cfg(feature = "ctap1")]
    pub fn allows_ctap1(&self, env: &mut E) -> CtapResult<bool> {
        Ok(!storage::has_always_uv(env)?)
    }

    fn clear_other_channels(&mut self, channel: Channel) {
        // Correct behavior between CTAP1 and CTAP2 isn't defined yet. Just a guess.
        #[cfg(feature = "ctap1")]
        {
            // We create a block statement to wrap this assignment expression, because attributes
            // (like #[cfg]) are not supported on expressions.
            self.u2f_up_state = U2fUserPresenceState::new();
        }
        self.stateful_command_permission.clear_old_channels(channel);
    }

    /// Checks if the application has any timers running.
    pub fn can_sleep(&mut self, env: &mut E) -> bool {
        !self.client_pin.has_token(env)
            && self.stateful_command_permission.get_command(env).is_err()
    }

    pub fn process_command(
        &mut self,
        env: &mut E,
        command_cbor: &[u8],
        channel: Channel,
    ) -> Vec<u8> {
        if let Some(response) = env.process_vendor_command(command_cbor, channel) {
            self.clear_other_channels(channel);
            self.stateful_command_permission.clear();
            return response;
        }
        let cmd = Command::deserialize(command_cbor);
        debug_ctap!(env, "Received command: {:?}", cmd);
        let response = cmd.and_then(|command| self.process_parsed_command(env, command, channel));
        debug_ctap!(env, "Sending response: {:?}", response);
        match response {
            Ok(response_data) => {
                let mut response_vec = vec![Ctap2StatusCode::CTAP2_OK as u8];
                if let Some(value) = response_data.into()
                    && cbor_write(value, &mut response_vec).is_err()
                {
                    response_vec = vec![Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR as u8];
                }
                response_vec
            }
            Err(error_code) => vec![error_code as u8],
        }
    }

    /// Processed a command after parsing from CBOR, returning its structured output.
    ///
    /// This function contains the logic of `parse_command`, minus all CBOR encoding and decoding.
    /// It should make command parsing easier to test.
    pub fn process_parsed_command(
        &mut self,
        env: &mut E,
        command: Command,
        channel: Channel,
    ) -> CtapResult<ResponseData> {
        // The auth token timeouts are checked once here, to make error codes consistent. If your
        // auth token hasn't timed out now, you can fully use it for this command.
        self.client_pin.update_timeouts(env);
        if !matches!(&command, Command::AuthenticatorGetInfo) {
            self.clear_other_channels(channel);
        }
        match (&command, self.stateful_command_permission.get_command(env)) {
            (Command::AuthenticatorGetNextAssertion, Ok(StatefulCommand::GetAssertion(_)))
            | (Command::AuthenticatorLargeBlobs(_), Ok(StatefulCommand::LargeBlob(_)))
            | (Command::AuthenticatorReset, Ok(StatefulCommand::Reset))
            // AuthenticatorGetInfo still allows Reset.
            | (Command::AuthenticatorGetInfo, Ok(StatefulCommand::Reset))
            // AuthenticatorSelection still allows Reset.
            | (Command::AuthenticatorSelection, Ok(StatefulCommand::Reset))
            // AuthenticatorMakeCredential is used like AuthenticatorSelection in 2.0.
            | (Command::AuthenticatorMakeCredential(_), Ok(StatefulCommand::Reset))
            // AuthenticatorCredentialManagement handles its subcommands later.
            | (
                Command::AuthenticatorCredentialManagement(_),
                Ok(StatefulCommand::EnumerateRps(_)),
            )
            | (
                Command::AuthenticatorCredentialManagement(_),
                Ok(StatefulCommand::EnumerateCredentials(_)),
            ) => (),
            (_, _) => self.stateful_command_permission.clear(),
        }
        match channel {
            Channel::MainHid(_) => self.process_fido_command(env, command, channel),
            #[cfg(feature = "vendor_hid")]
            Channel::VendorHid(_) => self.process_vendor_command(env, command),
        }
    }

    fn process_fido_command(
        &mut self,
        env: &mut E,
        command: Command,
        channel: Channel,
    ) -> CtapResult<ResponseData> {
        match command {
            Command::AuthenticatorMakeCredential(params) => {
                self.process_make_credential(env, params, channel)
            }
            Command::AuthenticatorGetAssertion(params) => {
                self.process_get_assertion(env, params, channel)
            }
            Command::AuthenticatorGetNextAssertion => self.process_get_next_assertion(env),
            Command::AuthenticatorGetInfo => self.process_get_info(env),
            Command::AuthenticatorClientPin(params) => {
                self.client_pin.process_command(env, params, channel)
            }
            Command::AuthenticatorReset => self.process_reset(env, channel),
            #[cfg(feature = "fingerprint")]
            Command::AuthenticatorBioEnrollment(params) => process_bio_enrollment(
                env,
                &mut self.client_pin,
                params,
                &mut self.fingerprint_enrollment_status,
            ),
            Command::AuthenticatorCredentialManagement(params) => process_credential_management(
                env,
                &mut self.stateful_command_permission,
                &mut self.client_pin,
                params,
                channel,
            ),
            Command::AuthenticatorSelection => self.process_selection(env, channel),
            Command::AuthenticatorLargeBlobs(params) => {
                let large_blob_state = self.stateful_command_permission.large_blob(env, channel);
                large_blob_state.process_command(env, &mut self.client_pin, params)
            }
            #[cfg(feature = "config_command")]
            Command::AuthenticatorConfig(params) => {
                process_config(env, &mut self.client_pin, params)
            }
        }
    }

    #[cfg(feature = "vendor_hid")]
    fn process_vendor_command(
        &mut self,
        env: &mut E,
        command: Command,
    ) -> CtapResult<ResponseData> {
        match command {
            Command::AuthenticatorGetInfo => self.process_get_info(env),
            _ => Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND),
        }
    }

    fn pin_uv_auth_precheck(
        &mut self,
        env: &mut E,
        pin_uv_auth_param: &Option<Vec<u8>>,
        pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
        channel: Channel,
    ) -> CtapResult<()> {
        if let Some(auth_param) = &pin_uv_auth_param {
            // This case was added in FIDO 2.1.
            if auth_param.is_empty() {
                check_user_presence(env, channel)?;
                if env.persist().pin_hash()?.is_none() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                } else {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
                }
            }
            pin_uv_auth_protocol.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?;
        }
        Ok(())
    }

    fn has_valid_up(&mut self, has_pin_uv_auth_param: bool, has_uv_option: bool) -> bool {
        if has_pin_uv_auth_param {
            self.client_pin.get_user_present_flag()
        } else {
            has_uv_option
        }
    }

    fn process_make_credential(
        &mut self,
        env: &mut E,
        make_credential_params: AuthenticatorMakeCredentialParameters,
        channel: Channel,
    ) -> CtapResult<ResponseData> {
        let AuthenticatorMakeCredentialParameters {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list,
            extensions,
            options,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
            enterprise_attestation,
            attestation_formats_preference,
        } = make_credential_params;

        self.pin_uv_auth_precheck(env, &pin_uv_auth_param, pin_uv_auth_protocol, channel)?;

        // When more algorithms are supported, iterate and pick the first match.
        let cred_param = get_preferred_cred_param(&pub_key_cred_params)
            .ok_or(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)?;
        let algorithm = cred_param.alg;

        let rp_id = rp.rp_id;
        let ep_att = if let Some(enterprise_attestation) = enterprise_attestation {
            let has_provisioned_ep = env
                .persist()
                .get_attestation(AttestationId::Enterprise)?
                .is_some();
            let authenticator_mode = env
                .customization()
                .enterprise_attestation_mode()
                .or(if has_provisioned_ep {
                    Some(EnterpriseAttestationMode::PlatformManaged)
                } else {
                    None
                })
                .ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
            if !storage::enterprise_attestation(env)? {
                return Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER);
            }
            match (
                EnterpriseAttestationMode::try_from(enterprise_attestation)?,
                authenticator_mode,
            ) {
                (
                    EnterpriseAttestationMode::PlatformManaged,
                    EnterpriseAttestationMode::PlatformManaged,
                ) => true,
                _ => env.customization().is_enterprise_rp_id(&rp_id),
            }
        } else {
            false
        };

        let has_pin_uv_auth_param = pin_uv_auth_param.is_some();
        let mut flags = match pin_uv_auth_param {
            Some(pin_uv_auth_param) => {
                // This case is not mentioned in CTAP2.1, so we keep 2.0 logic.
                if env.persist().pin_hash()?.is_none() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                }
                self.client_pin.verify_pin_uv_auth_token(
                    &client_data_hash,
                    &pin_uv_auth_param,
                    pin_uv_auth_protocol.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                self.client_pin
                    .has_permission(PinPermission::MakeCredential)?;
                self.client_pin.check_user_verified_flag()?;
                // Checking for the correct permissions_rp_id is specified earlier.
                // Error codes are identical though, so the implementation can be identical with
                // GetAssertion.
                self.client_pin.ensure_rp_id_permission(&rp_id)?;
                UV_FLAG
            }
            None => {
                if options.uv {
                    #[cfg(not(feature = "fingerprint"))]
                    return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
                    #[cfg(feature = "fingerprint")]
                    map_uv_block_error(perform_built_in_uv(env, channel, true))?;
                    #[cfg(feature = "fingerprint")]
                    UV_FLAG
                } else {
                    if storage::has_always_uv(env)? {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                    }
                    // Corresponds to makeCredUvNotRqd set to true.
                    if options.rk && env.persist().pin_hash()?.is_some() {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                    }
                    0x00
                }
            }
        };
        // MakeCredential always requires user presence.
        // The ED flag is added later, if applicable.
        flags |= UP_FLAG | AT_FLAG;

        let has_uv = has_pin_uv_auth_param || options.uv;
        let rp_id_hash = Sha::<E>::digest(rp_id.as_bytes());
        if let Some(exclude_list) = exclude_list {
            for cred_desc in exclude_list {
                if filter_listed_resident_credential(
                    storage::find_credential(env, &rp_id, &cred_desc.key_id)?,
                    has_uv,
                )
                .is_some()
                    || filter_listed_credential(
                        env.key_store()
                            .unwrap_credential(&cred_desc.key_id, &rp_id_hash)?,
                        has_uv,
                    )
                    .is_some()
                {
                    // Perform this check, so bad actors can't brute force exclude_list
                    // without user interaction.
                    let _ = check_user_presence(env, channel);
                    return Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED);
                }
            }
        }

        if !self.has_valid_up(has_pin_uv_auth_param, options.uv) {
            check_user_presence(env, channel)?;
        }
        self.client_pin.clear_token_flags();

        let attestation = if ep_att {
            Some(
                env.persist()
                    .get_attestation(AttestationId::Enterprise)?
                    .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?,
            )
        } else if env.customization().use_batch_attestation() {
            env.persist()
                .get_attestation(AttestationId::Batch)?
                .filter(|att| !att.certificate.is_empty())
        } else {
            None
        };
        let mtc_att = attestation
            .as_ref()
            .and_then(|att| mtc::ProvisionedMtcAttestation::from_bytes(&att.certificate));

        let default_cred_protect = env.customization().default_cred_protect();
        let mut cred_protect_policy = extensions.cred_protect;
        if cred_protect_policy.unwrap_or(CredentialProtectionPolicy::UserVerificationOptional)
            < default_cred_protect.unwrap_or(CredentialProtectionPolicy::UserVerificationOptional)
        {
            cred_protect_policy = default_cred_protect;
        }
        let min_pin_length =
            extensions.min_pin_length && storage::min_pin_length_rp_ids(env)?.contains(&rp_id);
        // None for no input, false for invalid input, true for valid input.
        let has_cred_blob_output = extensions.cred_blob.is_some();
        let cred_blob = extensions
            .cred_blob
            .filter(|c| c.len() <= env.customization().max_cred_blob_length());
        let cred_blob_output = if has_cred_blob_output {
            Some(cred_blob.is_some())
        } else {
            None
        };
        let has_extension_output = extensions.hmac_secret
            || extensions.cred_protect.is_some()
            || min_pin_length
            || has_cred_blob_output
            || extensions.mtc_debug;
        if has_extension_output {
            flags |= ED_FLAG
        };
        let large_blob_key = match (options.rk, extensions.large_blob_key) {
            (true, Some(true)) => Some(env.rng().gen_uniform_u8x32().to_vec()),
            _ => None,
        };

        // We decide on the algorithm early, but delay key creation since it takes time.
        // We rather do that later so all intermediate checks may return faster.
        let private_key = PrivateKey::new(env, algorithm);
        let hmac_secret_mc_output = if extensions.hmac_secret {
            if let Some(hmac_secret_input) = extensions.hmac_secret_mc {
                let cred_random = self.generate_cred_random(env, &private_key, has_uv)?;
                Some(
                    self.client_pin
                        .process_hmac_secret(env, hmac_secret_input, &cred_random)?,
                )
            } else {
                None
            }
        } else {
            None
        };
        let credential_id = if options.rk {
            let random_id = env.rng().gen_uniform_u8x32().to_vec();
            let credential_source = PublicKeyCredentialSource {
                key_type: PublicKeyCredentialType::PublicKey,
                credential_id: random_id.clone(),
                wrapped_private_key: private_key.to_cbor(),
                rp_id,
                user_handle: user.user_id,
                // This input is user provided, so we crop it to 64 byte for storage.
                // The UTF8 encoding is always preserved, so the string might end up shorter.
                user_display_name: user
                    .user_display_name
                    .map(|s| truncate_to_char_boundary(&s, 64).to_string()),
                cred_protect_policy,
                creation_order: storage::new_creation_order(env)?,
                user_name: user
                    .user_name
                    .map(|s| truncate_to_char_boundary(&s, 64).to_string()),
                user_icon: user
                    .user_icon
                    .map(|s| truncate_to_char_boundary(&s, 64).to_string()),
                cred_blob,
                large_blob_key: large_blob_key.clone(),
                third_party_payment: extensions.third_party_payment,
            };
            storage::store_credential(env, credential_source)?;
            random_id
        } else {
            let credential_source = CredentialSource {
                wrapped_private_key: private_key.to_cbor(),
                rp_id_hash,
                cred_protect_policy,
                cred_blob,
                third_party_payment: extensions.third_party_payment,
            };
            env.key_store()
                .wrap_credential(credential_source)
                .map_err(|_| Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?
        };

        let mut auth_data = self.generate_auth_data(env, &rp_id_hash, flags)?;
        auth_data.extend(env.persist().aaguid()?);
        // The length is fixed to 0x20 or 0x80 and fits one byte.
        if credential_id.len() > 0xFF {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        auth_data.extend(vec![0x00, credential_id.len() as u8]);
        auth_data.extend(&credential_id);
        let public_cose_key = private_key.get_pub_key()?;
        cbor_write(cbor::Value::from(public_cose_key), &mut auth_data)?;
        let explicit_mtc_pref = attestation_formats_preference.as_deref().is_some_and(|prefs| {
            prefs.iter().any(|pref| {
                mtc_att.is_some()
                    && matches!(
                        pref.as_str(),
                        mtc::MTC_FORMAT_STR
                            | mtc::MTC_KEYREF_FORMAT_STR
                            | mtc::MTC_MDS_FORMAT_STR
                    )
            })
        });

        if has_extension_output {
            let hmac_secret_output = if extensions.hmac_secret {
                Some(true)
            } else {
                None
            };
            let min_pin_length_output = if min_pin_length {
                Some(storage::min_pin_length(env)? as u64)
            } else {
                None
            };
            let cred_protect_output = extensions.cred_protect.and(cred_protect_policy);
            let mtc_debug_output = if extensions.mtc_debug {
                let primary_att_key = attestation
                    .as_ref()
                    .and_then(|att| PrivateKey::<E>::from_attestation_bytes(&att.wrapped_private_key));
                let debug_att_key = if !ep_att
                    && !algorithm.is_mldsa()
                    && !explicit_mtc_pref
                    && let Some(c_key) = mtc_att.as_ref().and_then(|m| m.classical_key.as_ref())
                {
                    PrivateKey::<E>::from_attestation_bytes(c_key)
                } else {
                    attestation
                        .as_ref()
                        .and_then(|att| PrivateKey::<E>::from_attestation_bytes(&att.wrapped_private_key))
                };
                let cose_pk = match debug_att_key.as_ref() {
                    Some(att_k) => att_k.get_pub_key()?,
                    None => private_key.get_pub_key()?,
                };
                let mut pk_bytes = Vec::new();
                cbor_write(cbor::Value::from(cose_pk), &mut pk_bytes)?;

                // Privacy Gate (WebAuthn Level 4 PR §10.2.1):
                // `deviceSerial` MUST ONLY be populated when Enterprise Attestation (`ep_att == true`)
                // was granted. For non-enterprise registrations (`ep_att == false`), `deviceSerial`
                // MUST be omitted to preserve batch anonymity.
                let device_serial_opt = if ep_att
                    && let Some(ent_mtc) = mtc_att.as_ref()
                {
                    mtc::MtcProof::from_tls_bytes(&ent_mtc.cert.mtc_proof).and_then(|p| {
                        if p.extensions.is_empty() {
                            None
                        } else {
                            String::from_utf8(p.extensions).ok()
                        }
                    })
                } else {
                    None
                };

                let (not_before_opt, not_after_opt, fw_version_opt, mtc_proof_opt, root_hash_opt) =
                    if let Some(active_mtc) = mtc_att.as_ref() {
                        let mtc_pk_bytes = if let Some(ref prim_k) = primary_att_key {
                            let mut buf = Vec::new();
                            cbor_write(cbor::Value::from(prim_k.get_pub_key()?), &mut buf)?;
                            buf
                        } else {
                            pk_bytes.clone()
                        };
                        let aaguid = env.persist().aaguid()?;
                        let root_hash = mtc::compute_mtc_root_hash::<Sha<E>>(
                            &active_mtc.cert,
                            &mtc_pk_bytes,
                            &aaguid,
                        )
                        .map(|rh| rh.to_vec());
                        let proof_opt = if active_mtc.cert.mtc_proof.is_empty() {
                            None
                        } else {
                            Some(active_mtc.cert.mtc_proof.clone())
                        };
                        let nb_opt =
                            if active_mtc.cert.not_before == 0 && active_mtc.cert.not_after == 0 {
                                None
                            } else {
                                Some(active_mtc.cert.not_before)
                            };
                        let na_opt =
                            if active_mtc.cert.not_before == 0 && active_mtc.cert.not_after == 0 {
                                None
                            } else {
                                Some(active_mtc.cert.not_after)
                            };
                        (
                            nb_opt,
                            na_opt,
                            active_mtc.cert.firmware_version,
                            proof_opt,
                            root_hash,
                        )
                    } else {
                        (None, None, env.firmware_version(), None, None)
                    };

                Some(cbor::Value::from(mtc::MtcDebugOutput {
                    pub_key: pk_bytes,
                    device_serial: device_serial_opt,
                    not_before: not_before_opt,
                    not_after: not_after_opt,
                    firmware_version: fw_version_opt,
                    mtc_proof: mtc_proof_opt,
                    root_hash: root_hash_opt,
                }))
            } else {
                None
            };
            let extensions_output = cbor_map_options! {
                "credBlob" => cred_blob_output,
                "mtc-debug" => mtc_debug_output,
                "credProtect" => cred_protect_output,
                "hmac-secret" => hmac_secret_output,
                "minPinLength" => min_pin_length_output,
                "hmac-secret-mc" => hmac_secret_mc_output,
            };
            cbor_write(extensions_output, &mut auth_data)?;
        }

        let mut signature_data = auth_data.clone();
        signature_data.extend(client_data_hash);

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum SelectedAttestationFormat {
            Mtc,
            Packed,
            NoneFormat,
        }

        let default_format = match &mtc_att {
            Some(_) => SelectedAttestationFormat::Mtc,
            None => SelectedAttestationFormat::Packed,
        };
        let selected_format = match attestation_formats_preference.as_deref() {
            Some(prefs) => prefs
                .iter()
                .find_map(|pref| match pref.as_str() {
                    mtc::MTC_FORMAT_STR
                    | mtc::MTC_KEYREF_FORMAT_STR
                    | mtc::MTC_MDS_FORMAT_STR
                        if mtc_att.is_some() =>
                    {
                        Some(SelectedAttestationFormat::Mtc)
                    }
                    "packed" => Some(SelectedAttestationFormat::Packed),
                    "none" if !ep_att => Some(SelectedAttestationFormat::NoneFormat),
                    _ => None,
                })
                .unwrap_or(default_format),
            None => default_format,
        };

        let (fmt, alg, signature, x5c, pub_key, mtc_cert) = match selected_format {
            SelectedAttestationFormat::NoneFormat => (
                String::from("none"),
                0,
                Vec::new(),
                None,
                None,
                None,
            ),
            SelectedAttestationFormat::Mtc => {
                let Attestation {
                    wrapped_private_key,
                    ..
                } = attestation.ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                let mtc_att = mtc_att.ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;

                // Second Non-Enterprise Batch X.509 Certificate (`cKey` + `cX5c`):
                // For non-Enterprise MakeCredential requests where the credential algorithm is
                // non-ML-DSA (e.g., ES256, ES384, ES512, Ed25519, Ed448, RS256) and the client did
                // not explicitly request "mtc" via 0x0B, use the provisioned classical
                // batch key and X.509 certificate when present.
                if !ep_att
                    && !algorithm.is_mldsa()
                    && !explicit_mtc_pref
                    && let (Some(c_key), Some(c_x5c)) =
                        (mtc_att.classical_key.as_ref(), mtc_att.classical_x5c.as_ref())
                {
                    let classical_att_key = PrivateKey::<E>::from_attestation_bytes(c_key)
                        .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                    let c_alg = classical_att_key.signature_algorithm() as i64;
                    let c_sig = classical_att_key.sign_and_encode(&signature_data)?;
                    (
                        String::from("packed"),
                        c_alg,
                        c_sig,
                        Some(vec![c_x5c.clone()]),
                        None,
                        None,
                    )
                } else {
                    let attestation_key =
                        PrivateKey::<E>::from_attestation_bytes(&wrapped_private_key)
                            .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                    let alg = attestation_key.signature_algorithm() as i64;
                    let sig = attestation_key.sign_and_encode(&signature_data)?;

                    // Tier 1 (Both Non-Enterprise and Enterprise): If no explicit MTC format was
                    // requested via 0x0B (e.g., 0x0B is omitted or empty) and an X.509 certificate
                    // (`x5c`) was provisioned alongside `mtcCert`, provide standard `"packed"`
                    // attestation with `x5c` whenever the total response fits in 7,609 B!
                    // If `x5c` is too large for the 7,609 B budget, cascade to Tier 2 (`"mtc"`).
                    if !explicit_mtc_pref
                        && let Some(x5c_der) = mtc_att.x5c.as_ref()
                        && auth_data.len() + sig.len() + x5c_der.len() + 60 <= 7550
                    {
                        (
                            String::from("packed"),
                            alg,
                            sig,
                            Some(vec![x5c_der.clone()]),
                            None,
                            None,
                        )
                    } else {
                        let explicit_keyref_pref = attestation_formats_preference
                            .as_ref()
                            .is_some_and(|prefs| {
                                prefs.iter().any(|p| p == mtc::MTC_KEYREF_FORMAT_STR)
                            });
                        let wire_mtc_cert = if mtc_att.key_ref || explicit_keyref_pref {
                            mtc_att.cert.to_key_ref()
                        } else {
                            mtc_att.cert
                        };
                        (
                            String::from(mtc::MTC_FORMAT_STR),
                            alg,
                            sig,
                            None,
                            None,
                            Some(wire_mtc_cert),
                        )
                    }
                }
            }
            SelectedAttestationFormat::Packed => match (attestation, mtc_att) {
                (
                    Some(Attestation {
                        wrapped_private_key,
                        certificate,
                    }),
                    None,
                ) => {
                    let attestation_key =
                        PrivateKey::<E>::from_attestation_bytes(&wrapped_private_key)
                            .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                    let alg = attestation_key.signature_algorithm() as i64;
                    let sig = attestation_key.sign_and_encode(&signature_data)?;
                    (
                        String::from("packed"),
                        alg,
                        sig,
                        Some(vec![certificate]),
                        None,
                        None,
                    )
                }
                (
                    Some(Attestation { .. }),
                    Some(mtc::ProvisionedMtcAttestation {
                        classical_key: Some(c_key),
                        classical_x5c: Some(c_x5c),
                        ..
                    }),
                ) if !ep_att && !algorithm.is_mldsa() => {
                    let classical_att_key = PrivateKey::<E>::from_attestation_bytes(&c_key)
                        .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                    let c_alg = classical_att_key.signature_algorithm() as i64;
                    let c_sig = classical_att_key.sign_and_encode(&signature_data)?;
                    (
                        String::from("packed"),
                        c_alg,
                        c_sig,
                        Some(vec![c_x5c]),
                        None,
                        None,
                    )
                }
                (
                    Some(Attestation {
                        wrapped_private_key,
                        ..
                    }),
                    Some(mtc::ProvisionedMtcAttestation {
                        x5c: Some(x5c_der), ..
                    }),
                ) => {
                    let attestation_key =
                        PrivateKey::<E>::from_attestation_bytes(&wrapped_private_key)
                            .ok_or(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?;
                    let alg = attestation_key.signature_algorithm() as i64;
                    let sig = attestation_key.sign_and_encode(&signature_data)?;
                    (
                        String::from("packed"),
                        alg,
                        sig,
                        Some(vec![x5c_der]),
                        None,
                        None,
                    )
                }
                _ => (
                    String::from("packed"),
                    algorithm as i64,
                    private_key.sign_and_encode(&signature_data)?,
                    None,
                    None,
                    None,
                ),
            },
        };
        let attestation_statement = PackedAttestationStatement {
            alg,
            sig: signature,
            x5c,
            ecdaa_key_id: None,
            pub_key,
            mtc_cert,
        };
        let ep_att = if ep_att { Some(true) } else { None };
        Ok(ResponseData::AuthenticatorMakeCredential(
            AuthenticatorMakeCredentialResponse {
                fmt,
                auth_data,
                att_stmt: attestation_statement,
                ep_att,
                large_blob_key,
            },
        ))
    }

    // Generates a different per-credential secret for each UV mode.
    // The computation is deterministic, and private_key expected to be unique.
    fn generate_cred_random(
        &mut self,
        env: &mut E,
        private_key: &PrivateKey<E>,
        has_uv: bool,
    ) -> CtapResult<Secret<[u8; HASH_SIZE]>> {
        let salt = Sha::<E>::digest(&private_key.export());
        let key = env.key_store().cred_random(has_uv)?;
        let mut output = Secret::default();
        Hkdf::<E>::hkdf_256(&*key, &salt, b"credRandom", &mut output);
        Ok(output)
    }

    // Processes the input of a get_assertion operation for a given credential
    // and returns the correct Get(Next)Assertion response.
    fn assertion_response(
        &mut self,
        env: &mut E,
        mut credential: PublicKeyCredentialSource,
        assertion_input: AssertionInput,
        number_of_credentials: Option<usize>,
        is_next: bool,
    ) -> CtapResult<ResponseData> {
        let AssertionInput {
            client_data_hash,
            mut auth_data,
            extensions,
            has_uv,
        } = assertion_input;

        let private_key = PrivateKey::from_cbor(credential.wrapped_private_key)?;
        // Process extensions.
        if extensions.hmac_secret.is_some() || extensions.cred_blob || extensions.third_party_payment {
            let encrypted_output = if let Some(hmac_secret_input) = extensions.hmac_secret {
                let cred_random = self.generate_cred_random(env, &private_key, has_uv)?;
                Some(
                    self.client_pin
                        .process_hmac_secret(env, hmac_secret_input, &cred_random)?,
                )
            } else {
                None
            };
            // This could be written more nicely with `then_some` when stable.
            let cred_blob = if extensions.cred_blob {
                Some(credential.cred_blob.unwrap_or_default())
            } else {
                None
            };
            let third_party_payment = if extensions.third_party_payment {
                Some(credential.third_party_payment)
            } else {
                None
            };
            let extensions_output = cbor_map_options! {
                "credBlob" => cred_blob,
                "hmac-secret" => encrypted_output,
                "thirdPartyPayment" => third_party_payment,
            };
            cbor_write(extensions_output, &mut auth_data)?;
        }
        let large_blob_key = match extensions.large_blob_key {
            Some(true) => credential.large_blob_key,
            _ => None,
        };

        let mut signature_data = auth_data.clone();
        signature_data.extend(client_data_hash);
        let signature = private_key.sign_and_encode(&signature_data)?;

        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential.credential_id,
            transports: None, // You can set USB as a hint here.
        };
        // Remove user identifiable information without uv.
        if !has_uv {
            credential.user_name = None;
            credential.user_display_name = None;
            credential.user_icon = None;
        }
        let user = if !credential.user_handle.is_empty() {
            Some(PublicKeyCredentialUserEntity {
                user_id: credential.user_handle,
                user_name: credential.user_name,
                user_display_name: credential.user_display_name,
                user_icon: credential.user_icon,
            })
        } else {
            None
        };
        let response_data = AuthenticatorGetAssertionResponse {
            credential: Some(cred_desc),
            auth_data,
            signature,
            user,
            number_of_credentials: number_of_credentials.map(|n| n as u64),
            large_blob_key,
        };
        // Only returned for the first GetAssertion, not for Next calls.
        if is_next {
            Ok(ResponseData::AuthenticatorGetNextAssertion(response_data))
        } else {
            Ok(ResponseData::AuthenticatorGetAssertion(response_data))
        }
    }

    // Returns the first applicable credential from the allow list.
    fn get_any_credential_from_allow_list(
        &mut self,
        env: &mut E,
        allow_list: Vec<PublicKeyCredentialDescriptor>,
        rp_id: &str,
        rp_id_hash: &[u8],
        has_uv: bool,
    ) -> CtapResult<Option<PublicKeyCredentialSource>> {
        for allowed_credential in allow_list {
            let credential = filter_listed_resident_credential(
                storage::find_credential(env, rp_id, &allowed_credential.key_id)?,
                has_uv,
            );
            if credential.is_some() {
                return Ok(credential);
            }
            let credential = filter_listed_credential(
                env.key_store()
                    .unwrap_credential(&allowed_credential.key_id, rp_id_hash)?,
                has_uv,
            );
            if credential.is_some() {
                return Ok(credential.map(|c| to_public_source(allowed_credential.key_id, c)));
            }
        }
        Ok(None)
    }

    fn process_get_assertion(
        &mut self,
        env: &mut E,
        get_assertion_params: AuthenticatorGetAssertionParameters,
        channel: Channel,
    ) -> CtapResult<ResponseData> {
        let AuthenticatorGetAssertionParameters {
            rp_id,
            client_data_hash,
            allow_list,
            extensions,
            options,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        } = get_assertion_params;

        self.pin_uv_auth_precheck(env, &pin_uv_auth_param, pin_uv_auth_protocol, channel)?;

        if extensions.hmac_secret.is_some() && !options.up {
            // The extension is actually supported, but we need user presence.
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_OPTION);
        }

        let has_pin_uv_auth_param = pin_uv_auth_param.is_some();
        let mut flags = match pin_uv_auth_param {
            Some(pin_uv_auth_param) => {
                // This case is not mentioned in CTAP2.1, so we keep 2.0 logic.
                if env.persist().pin_hash()?.is_none() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                }
                self.client_pin.verify_pin_uv_auth_token(
                    &client_data_hash,
                    &pin_uv_auth_param,
                    pin_uv_auth_protocol.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                self.client_pin
                    .has_permission(PinPermission::GetAssertion)?;
                // Checking for the UV flag is specified earlier for GetAssertion.
                // Error codes are identical though, so the implementation can be identical with
                // MakeCredential.
                self.client_pin.check_user_verified_flag()?;
                self.client_pin.ensure_rp_id_permission(&rp_id)?;
                UV_FLAG
            }
            None => {
                if options.uv {
                    #[cfg(not(feature = "fingerprint"))]
                    return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
                    #[cfg(feature = "fingerprint")]
                    map_uv_block_error(perform_built_in_uv(env, channel, true))?;
                    #[cfg(feature = "fingerprint")]
                    UV_FLAG
                } else {
                    if options.up && storage::has_always_uv(env)? {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED);
                    }
                    0x00
                }
            }
        };

        if options.up {
            flags |= UP_FLAG;
        }
        if extensions.hmac_secret.is_some() || extensions.cred_blob || extensions.third_party_payment {
            flags |= ED_FLAG;
        }

        let has_uv = has_pin_uv_auth_param || options.uv;
        let rp_id_hash = Sha::<E>::digest(rp_id.as_bytes());
        let (credential, next_credential_keys) = if let Some(allow_list) = allow_list {
            (
                self.get_any_credential_from_allow_list(
                    env,
                    allow_list,
                    &rp_id,
                    &rp_id_hash,
                    has_uv,
                )?,
                vec![],
            )
        } else {
            let mut iter_result = Ok(());
            let iter = storage::iter_credentials(env, &mut iter_result)?;
            let mut stored_credentials: Vec<(usize, u64)> = iter
                .filter_map(|(key, credential)| {
                    if credential.rp_id == rp_id && (has_uv || credential.is_discoverable()) {
                        Some((key, credential.creation_order))
                    } else {
                        None
                    }
                })
                .collect();
            iter_result?;
            stored_credentials.sort_unstable_by_key(|&(_key, order)| order);
            let mut stored_credentials: Vec<usize> = stored_credentials
                .into_iter()
                .map(|(key, _order)| key)
                .collect();
            let credential = stored_credentials
                .pop()
                .map(|key| storage::get_credential(env, key))
                .transpose()?;
            (credential, stored_credentials)
        };

        let credential = credential.ok_or(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)?;

        // This check comes before CTAP2_ERR_NO_CREDENTIALS in CTAP 2.0.
        if options.up && !self.has_valid_up(has_pin_uv_auth_param, options.uv) {
            check_user_presence(env, channel)?;
            self.client_pin.clear_token_flags();
        }

        self.increment_global_signature_counter(env)?;

        let assertion_input = AssertionInput {
            client_data_hash,
            auth_data: self.generate_auth_data(env, &rp_id_hash, flags)?,
            extensions,
            has_uv,
        };
        let number_of_credentials = if next_credential_keys.is_empty() {
            None
        } else {
            let number_of_credentials = Some(next_credential_keys.len() + 1);
            let assertion_state = StatefulCommand::GetAssertion(Box::new(AssertionState {
                assertion_input: assertion_input.clone(),
                next_credential_keys,
            }));
            self.stateful_command_permission
                .set_command(env, assertion_state, channel);
            number_of_credentials
        };
        self.assertion_response(
            env,
            credential,
            assertion_input,
            number_of_credentials,
            false,
        )
    }

    fn process_get_next_assertion(&mut self, env: &mut E) -> CtapResult<ResponseData> {
        let (assertion_input, credential_key) = self
            .stateful_command_permission
            .next_assertion_credential(env)?;
        let credential = storage::get_credential(env, credential_key)?;
        self.assertion_response(env, credential, assertion_input, None, true)
    }

    fn process_get_info(&self, env: &mut E) -> CtapResult<ResponseData> {
        let has_always_uv = storage::has_always_uv(env)?;
        #[cfg_attr(not(feature = "ctap1"), allow(unused_mut))]
        let mut versions = vec![
            String::from(FIDO2_VERSION_STRING),
            String::from(FIDO2_1_VERSION_STRING),
            String::from(FIDO2_3_VERSION_STRING),
        ];
        #[cfg(feature = "ctap1")]
        if !has_always_uv {
            versions.insert(0, String::from(U2F_VERSION_STRING))
        }
        let mut options = vec![
            (String::from("rk"), true),
            (
                String::from("clientPin"),
                env.persist().pin_hash()?.is_some(),
            ),
            (String::from("up"), true),
            (String::from("pinUvAuthToken"), true),
            (String::from("perCredMgmtRO"), true),
            (String::from("largeBlobs"), true),
            #[cfg(feature = "config_command")]
            (String::from("authnrCfg"), true),
            #[cfg(feature = "config_command")]
            (String::from("uvAcfg"), true),
            (String::from("credMgmt"), true),
            #[cfg(feature = "config_command")]
            (String::from("setMinPINLength"), true),
            (String::from("makeCredUvNotRqd"), !has_always_uv),
            (String::from("alwaysUv"), has_always_uv),
        ];
        #[cfg(feature = "fingerprint")]
        {
            let has_fingerprint = !env.persist().template_infos()?.is_empty();
            options.push((String::from("uv"), has_fingerprint));
            options.push((String::from("bioEnroll"), has_fingerprint));
        }
        let has_enterprise_attestation = env.customization().enterprise_attestation_mode().is_some()
            || env
                .persist()
                .get_attestation(AttestationId::Enterprise)?
                .is_some();
        if has_enterprise_attestation {
            options.push((String::from("ep"), storage::enterprise_attestation(env)?));
        }
        let mut pin_protocols = vec![PinUvAuthProtocol::V2 as u64];
        if env.customization().allows_pin_protocol_v1() {
            pin_protocols.push(PinUvAuthProtocol::V1 as u64);
        }
        let attestation_formats = if env.customization().use_batch_attestation() {
            match env
                .persist()
                .get_attestation(AttestationId::Batch)?
                .and_then(|att| mtc::ProvisionedMtcAttestation::from_bytes(&att.certificate))
            {
                Some(_) => vec![
                    String::from(mtc::MTC_FORMAT_STR),
                    String::from("packed"),
                ],
                None => vec![String::from("packed")],
            }
        } else {
            vec![String::from("packed")]
        };

        let ppuat = storage::persistent_pin_uv_auth_token(env)?;
        let enc_id_plain = storage::enc_identifier(env)?;
        let enc_state_plain = storage::enc_cred_store_state(env)?;
        let enc_identifier = Some(Self::encrypt_with_persistent_token(
            env,
            &ppuat,
            b"encIdentifier",
            &enc_id_plain,
        ));
        let enc_cred_store_state = Some(Self::encrypt_with_persistent_token(
            env,
            &ppuat,
            b"encCredStoreState",
            &enc_state_plain,
        ));

        Ok(ResponseData::AuthenticatorGetInfo(
            AuthenticatorGetInfoResponse {
                versions,
                extensions: Some(vec![
                    String::from("hmac-secret"),
                    String::from("hmac-secret-mc"),
                    String::from("credProtect"),
                    String::from("minPinLength"),
                    String::from("credBlob"),
                    String::from("largeBlobKey"),
                    String::from("thirdPartyPayment"),
                    String::from("mtc-debug"),
                ]),
                aaguid: env.persist().aaguid()?,
                options: Some(options),
                max_msg_size: Some(env.customization().max_msg_size() as u64),
                // The order implies preference. We favor the new V2.
                pin_protocols: Some(pin_protocols),
                max_credential_count_in_list: env
                    .customization()
                    .max_credential_count_in_list()
                    .map(|c| c as u64),
                max_credential_id_length: Some(MAX_CREDENTIAL_ID_SIZE as u64),
                transports: Some(vec![AuthenticatorTransport::Usb]),
                algorithms: Some(SUPPORTED_CRED_PARAMS.to_vec()),
                max_serialized_large_blob_array: Some(
                    env.customization().max_large_blob_array_size() as u64,
                ),
                force_pin_change: Some(env.persist().has_force_pin_change()?),
                min_pin_length: storage::min_pin_length(env)?,
                firmware_version: env.firmware_version(),
                max_cred_blob_length: Some(env.customization().max_cred_blob_length() as u64),
                max_rp_ids_for_set_min_pin_length: Some(
                    env.customization().max_rp_ids_length() as u64
                ),
                #[cfg(feature = "fingerprint")]
                preferred_platform_uv_attempts: Some(
                    env.customization().preferred_platform_uv_attempts() as u64,
                ),
                #[cfg(not(feature = "fingerprint"))]
                preferred_platform_uv_attempts: None,
                // https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#user-verification-methods
                #[cfg(feature = "fingerprint")]
                uv_modality: Some(0x02),
                #[cfg(not(feature = "fingerprint"))]
                uv_modality: None,
                certifications: None,
                remaining_discoverable_credentials: Some(
                    storage::remaining_credentials(env)? as u64
                ),
                attestation_formats: Some(attestation_formats),
                enc_identifier,
                enc_cred_store_state,
                #[cfg(feature = "config_command")]
                authenticator_config_commands: Some(if has_enterprise_attestation {
                    vec![0x01, 0x02, 0x03]
                } else {
                    vec![0x02, 0x03]
                }),
                #[cfg(not(feature = "config_command"))]
                authenticator_config_commands: None,
            },
        ))
    }

    fn encrypt_with_persistent_token(
        env: &mut E,
        ppuat: &[u8; 32],
        info: &[u8],
        plaintext: &[u8; 16],
    ) -> Vec<u8> {
        use aes::cipher::generic_array::GenericArray;
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        let mut okm = [0u8; 32];
        Hkdf::<E>::hkdf_empty_salt_256(ppuat, info, &mut okm);
        let aes_key = &okm[..16];
        let random_bytes = env.rng().gen_uniform_u8x32();
        let iv = &random_bytes[..16];
        let mut block = *plaintext;
        let mut encryptor = cbc::Encryptor::<aes::Aes128>::new_from_slices(aes_key, iv).unwrap();
        encryptor.encrypt_block_mut(GenericArray::from_mut_slice(&mut block));
        let mut result = Vec::with_capacity(32);
        result.extend_from_slice(iv);
        result.extend_from_slice(&block);
        result
    }

    fn process_reset(&mut self, env: &mut E, channel: Channel) -> CtapResult<ResponseData> {
        #[cfg(not(feature = "no_reset_restrictions"))]
        {
            if !matches!(
                self.stateful_command_permission.get_command(env)?,
                StatefulCommand::Reset
            ) {
                return Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED);
            }
            check_user_presence(env, channel)?;
        }
        #[cfg(feature = "no_reset_restrictions")]
        let _ = channel;

        reset(env)?;
        self.client_pin.reset(env);

        #[cfg(feature = "fingerprint")]
        self.fingerprint_enrollment_status.clear();

        #[cfg(feature = "ctap1")]
        {
            // We create a block statement to wrap this assignment expression, because attributes
            // (like #[cfg]) are not supported on expressions.
            self.u2f_up_state = U2fUserPresenceState::new();
        }
        Ok(ResponseData::AuthenticatorReset)
    }

    fn process_selection(&self, env: &mut E, channel: Channel) -> CtapResult<ResponseData> {
        #[cfg(feature = "up_always_true")]
        {
            let (cid, transport) = match channel {
                Channel::MainHid(cid) => (cid, Transport::MainHid),
                #[cfg(feature = "vendor_hid")]
                Channel::VendorHid(cid) => (cid, Transport::VendorHid),
            };
            let endpoint = transport.usb_endpoint();

            // Send initial KEEPALIVE (STATUS_UPNEEDED) so host knows user interaction is pending.
            let keepalive_msg = CtapHid::<E>::keepalive(cid, KeepaliveStatus::UpNeeded);
            let _ = send_packets(env, endpoint, keepalive_msg);

            // In authenticatorSelection (P-15), host waits 150ms before expecting keepalive and sending CANCEL.
            // Wait up to 5000ms sending periodic keepalives every 100ms and checking for CANCEL.
            let mut packet = [0; 64];
            let delay_timer = env.clock().make_timer(5000);
            let mut keepalive_timer = env.clock().make_timer(KEEPALIVE_DELAY_MS);
            while !env.clock().is_elapsed(&delay_timer) {
                if env.clock().is_elapsed(&keepalive_timer) {
                    let keepalive_msg = CtapHid::<E>::keepalive(cid, KeepaliveStatus::UpNeeded);
                    let _ = send_packets(env, endpoint, keepalive_msg);
                    keepalive_timer = env.clock().make_timer(KEEPALIVE_DELAY_MS);
                }
                match env.hid_connection().recv(&mut packet, 20) {
                    Ok(RecvStatus::Received(rx_endpoint)) => {
                        let (received_cid, processed_packet) =
                            CtapHid::<E>::process_single_packet(&packet);
                        if rx_endpoint != endpoint || received_cid != cid {
                            let busy_error = CtapHid::<E>::busy_error(received_cid);
                            let _ = send_packets(env, rx_endpoint, busy_error);
                        } else if is_cancel(&processed_packet) {
                            debug_ctap!(env, "Selection cancelled");
                            return Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL);
                        }
                    }
                    Ok(RecvStatus::Timeout) => {}
                    Err(_) => return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR),
                }
            }
            Ok(ResponseData::AuthenticatorSelection)
        }
        #[cfg(not(feature = "up_always_true"))]
        {
            check_user_presence(env, channel)?;
            Ok(ResponseData::AuthenticatorSelection)
        }
    }

    pub fn generate_auth_data(
        &self,
        env: &mut E,
        rp_id_hash: &[u8],
        flag_byte: u8,
    ) -> CtapResult<Vec<u8>> {
        let mut auth_data = vec![];
        auth_data.extend(rp_id_hash);
        auth_data.push(flag_byte);
        // The global counter is only increased if use_signature_counter() is true.
        // It uses a big-endian representation.
        let mut signature_counter = [0u8; 4];
        BigEndian::write_u32(
            &mut signature_counter,
            env.persist().global_signature_counter()?,
        );
        auth_data.extend(&signature_counter);
        Ok(auth_data)
    }

    #[cfg(feature = "ctap1")]
    pub fn u2f_grant_user_presence(&mut self, env: &mut E) {
        self.u2f_up_state.grant_up(env)
    }

    #[cfg(feature = "ctap1")]
    pub fn u2f_needs_user_presence(&mut self, env: &mut E) -> bool {
        self.u2f_up_state.is_up_needed(env)
    }
}

#[cfg(test)]
mod test {
    use super::client_pin::PIN_TOKEN_LENGTH;
    use super::command::{
        AuthenticatorClientPinParameters, AuthenticatorCredentialManagementParameters,
    };
    use super::data_formats::{
        ClientPinSubCommand, CoseKey, CredentialManagementSubCommand, GetAssertionHmacSecretInput,
        GetAssertionOptions, MakeCredentialExtensions, MakeCredentialOptions, PinUvAuthProtocol,
        PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    };
    use super::pin_protocol::{PinProtocol, authenticate_pin_uv_auth_token};
    use super::*;
    use crate::api::crypto::ecdh::SecretKey as _;
    use crate::api::customization;
    use crate::api::key_store::CBOR_CREDENTIAL_ID_SIZE;
    use crate::ctap::command::AuthenticatorLargeBlobsParameters;
    use crate::env::EcdhSk;
    use crate::env::test::TestEnv;
    use crate::test_helpers;
    use cbor::{cbor_array, cbor_array_vec, cbor_map, destructure_cbor_map};

    // The keep-alive logic in the processing of some commands needs a channel ID to send
    // keep-alive packets to.
    // In tests where we define a dummy user-presence check that immediately returns, the channel
    // ID is irrelevant, so we pass this (dummy but valid) value.
    const DUMMY_CHANNEL: Channel = Channel::MainHid([0x12, 0x34, 0x56, 0x78]);
    #[cfg(feature = "vendor_hid")]
    const VENDOR_CHANNEL: Channel = Channel::VendorHid([0x12, 0x34, 0x56, 0x78]);

    fn check_make_response(
        env: &mut impl Env,
        make_credential_response: &CtapResult<ResponseData>,
        flags: u8,
        expected_credential_id_size: u8,
        expected_extension_cbor: &[u8],
    ) {
        let expected_aaguid = env.persist().aaguid().unwrap();
        let signature_counter = env.persist().global_signature_counter().unwrap();
        match make_credential_response.as_ref().unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                let AuthenticatorMakeCredentialResponse {
                    fmt,
                    auth_data,
                    att_stmt,
                    ep_att,
                    large_blob_key,
                } = make_credential_response;
                // The expected response is split to only assert the non-random parts.
                assert_eq!(fmt, "packed");
                let mut expected_auth_data = vec![
                    0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80,
                    0x34, 0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2,
                    0x12, 0x55, 0x86, 0xCE, 0x19, 0x47, flags,
                ];
                expected_auth_data.extend(&signature_counter.to_be_bytes());
                expected_auth_data.extend(expected_aaguid);
                expected_auth_data.extend(&[0x00, expected_credential_id_size]);
                assert_eq!(
                    auth_data[0..expected_auth_data.len()],
                    expected_auth_data[..]
                );
                assert_eq!(
                    &auth_data[auth_data.len() - expected_extension_cbor.len()..auth_data.len()],
                    expected_extension_cbor
                );
                assert!(ep_att.is_none());
                assert_eq!(att_stmt.alg, SignatureAlgorithm::Es256 as i64);
                assert_eq!(large_blob_key, &None);
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    #[cfg(feature = "fingerprint")]
    fn test_get_info() {
        let mut env = TestEnv::default();
        let aaguid = env.persist().aaguid().unwrap();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        let info_reponse = ctap_state.process_command(&mut env, &[0x04], DUMMY_CHANNEL);
        let parsed_map = data_formats::extract_map(cbor_read(&info_reponse[1..]).unwrap()).unwrap();
        let enc_id = parsed_map
            .iter()
            .find(|(k, _)| *k == cbor::cbor_int!(0x19))
            .map(|(_, v)| data_formats::extract_byte_string(v.clone()).unwrap())
            .unwrap();
        let enc_state = parsed_map
            .iter()
            .find(|(k, _)| *k == cbor::cbor_int!(0x1E))
            .map(|(_, v)| data_formats::extract_byte_string(v.clone()).unwrap())
            .unwrap();
        assert_eq!(enc_id.len(), 32);
        assert_eq!(enc_state.len(), 32);

        // Fails when removing `to_vec` for `SUPPORTED_CRED_PARAMS` as linted.
        #[allow(clippy::unnecessary_to_owned)]
        let expected_cbor = cbor_map_options! {
             0x01 => cbor_array_vec![vec![
                    #[cfg(feature = "ctap1")]
                    String::from(U2F_VERSION_STRING),
                    String::from(FIDO2_VERSION_STRING),
                    String::from(FIDO2_1_VERSION_STRING),
                    String::from(FIDO2_3_VERSION_STRING),
                ]],
            0x02 => cbor_array![
                    String::from("hmac-secret"),
                    String::from("hmac-secret-mc"),
                    String::from("credProtect"),
                    String::from("minPinLength"),
                    String::from("credBlob"),
                    String::from("largeBlobKey"),
                    String::from("thirdPartyPayment"),
                    String::from("mtc-debug"),
                ],
            0x03 => &aaguid[..],
            0x04 => cbor_map_options! {
                "ep" => env.customization().enterprise_attestation_mode().map(|_| false),
                "rk" => true,
                "up" => true,
                "uv" => false,
                #[cfg(feature = "config_command")]
                "uvAcfg" => true,
                #[cfg(feature = "config_command")]
                "alwaysUv" => false,
                "credMgmt" => true,
                #[cfg(feature = "config_command")]
                "authnrCfg" => true,
                "bioEnroll" => false,
                "clientPin" => false,
                "largeBlobs" => true,
                "perCredMgmtRO" => true,
                "pinUvAuthToken" => true,
                #[cfg(feature = "config_command")]
                "setMinPINLength" => true,
                "makeCredUvNotRqd" => true,
            },
            0x05 => env.customization().max_msg_size() as u64,
            0x06 => cbor_array![2, 1],
            0x07 => env.customization().max_credential_count_in_list().map(|c| c as u64),
            0x08 => MAX_CREDENTIAL_ID_SIZE as u64,
            0x09 => cbor_array!["usb"],
            0x0A => cbor_array_vec!(SUPPORTED_CRED_PARAMS.to_vec()),
            0x0B => env.customization().max_large_blob_array_size() as u64,
            0x0C => false,
            0x0D => storage::min_pin_length(&mut env).unwrap() as u64,
            0x0E => 0,
            0x0F => env.customization().max_cred_blob_length() as u64,
            0x10 => env.customization().max_rp_ids_length() as u64,
            0x11 => env.customization().preferred_platform_uv_attempts() as u64,
            0x12 => 0x02,
            0x14 => storage::remaining_credentials(&mut env).unwrap() as u64,
            0x16 => cbor_array!["packed", "none"],
            0x19 => enc_id,
            0x1E => enc_state,
            #[cfg(feature = "config_command")]
            0x1F => cbor_array![2, 3],
        };

        let mut response_cbor = vec![0x00];
        assert!(cbor_write(expected_cbor, &mut response_cbor).is_ok());
        assert_eq!(info_reponse, response_cbor);
    }

    #[test]
    #[cfg(not(feature = "fingerprint"))]
    fn test_get_info() {
        let mut env = TestEnv::default();
        let aaguid = env.persist().aaguid().unwrap();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        let info_reponse = ctap_state.process_command(&mut env, &[0x04], DUMMY_CHANNEL);
        let parsed_map = data_formats::extract_map(cbor_read(&info_reponse[1..]).unwrap()).unwrap();
        let enc_id = parsed_map
            .iter()
            .find(|(k, _)| *k == cbor::cbor_int!(0x19))
            .map(|(_, v)| data_formats::extract_byte_string(v.clone()).unwrap())
            .unwrap();
        let enc_state = parsed_map
            .iter()
            .find(|(k, _)| *k == cbor::cbor_int!(0x1E))
            .map(|(_, v)| data_formats::extract_byte_string(v.clone()).unwrap())
            .unwrap();
        assert_eq!(enc_id.len(), 32);
        assert_eq!(enc_state.len(), 32);

        // Fails when removing `to_vec` for `SUPPORTED_CRED_PARAMS` as linted.
        #[allow(clippy::unnecessary_to_owned)]
        let expected_cbor = cbor_map_options! {
             0x01 => cbor_array_vec![vec![
                    #[cfg(feature = "ctap1")]
                    String::from(U2F_VERSION_STRING),
                    String::from(FIDO2_VERSION_STRING),
                    String::from(FIDO2_1_VERSION_STRING),
                    String::from(FIDO2_3_VERSION_STRING),
                ]],
            0x02 => cbor_array![
                    String::from("hmac-secret"),
                    String::from("hmac-secret-mc"),
                    String::from("credProtect"),
                    String::from("minPinLength"),
                    String::from("credBlob"),
                    String::from("largeBlobKey"),
                    String::from("thirdPartyPayment"),
                    String::from("mtc-debug"),
                ],
            0x03 => &aaguid[..],
            0x04 => cbor_map_options! {
                "ep" => env.customization().enterprise_attestation_mode().map(|_| false),
                "rk" => true,
                "up" => true,
                #[cfg(feature = "config_command")]
                "uvAcfg" => true,
                #[cfg(feature = "config_command")]
                "alwaysUv" => false,
                "credMgmt" => true,
                #[cfg(feature = "config_command")]
                "authnrCfg" => true,
                "clientPin" => false,
                "largeBlobs" => true,
                "perCredMgmtRO" => true,
                "pinUvAuthToken" => true,
                #[cfg(feature = "config_command")]
                "setMinPINLength" => true,
                "makeCredUvNotRqd" => true,
            },
            0x05 => env.customization().max_msg_size() as u64,
            0x06 => cbor_array![2, 1],
            0x07 => env.customization().max_credential_count_in_list().map(|c| c as u64),
            0x08 => MAX_CREDENTIAL_ID_SIZE as u64,
            0x09 => cbor_array!["usb"],
            0x0A => cbor_array_vec!(SUPPORTED_CRED_PARAMS.to_vec()),
            0x0B => env.customization().max_large_blob_array_size() as u64,
            0x0C => false,
            0x0D => storage::min_pin_length(&mut env).unwrap() as u64,
            0x0E => 0,
            0x0F => env.customization().max_cred_blob_length() as u64,
            0x10 => env.customization().max_rp_ids_length() as u64,
            0x14 => storage::remaining_credentials(&mut env).unwrap() as u64,
            0x16 => cbor_array!["packed"],
            0x19 => enc_id,
            0x1E => enc_state,
            #[cfg(feature = "config_command")]
            0x1F => cbor_array![2, 3],
        };

        let mut response_cbor = vec![0x00];
        assert!(cbor_write(expected_cbor, &mut response_cbor).is_ok());
        assert_eq!(info_reponse, response_cbor);
    }

    #[test]
    fn test_get_info_no_pin_protocol_v1() {
        let mut env = TestEnv::default();
        env.customization_mut().set_allows_pin_protocol_v1(false);
        let ctap_state = CtapState::new(&mut env);
        let info_response = ctap_state.process_get_info(&mut env).unwrap();
        match info_response {
            ResponseData::AuthenticatorGetInfo(response) => {
                assert_eq!(
                    response.pin_protocols,
                    Some(vec![PinUvAuthProtocol::V2 as u64])
                );
            }
            _ => panic!("Invalid response type"),
        }
    }

    fn create_minimal_make_credential_parameters() -> AuthenticatorMakeCredentialParameters {
        let client_data_hash = vec![0xCD];
        let rp = PublicKeyCredentialRpEntity {
            rp_id: String::from("example.com"),
            rp_name: None,
            rp_icon: None,
        };
        let user = PublicKeyCredentialUserEntity {
            user_id: vec![0x1D],
            user_name: None,
            user_display_name: None,
            user_icon: None,
        };
        let pub_key_cred_params = vec![ES256_CRED_PARAM];
        let options = MakeCredentialOptions {
            rk: true,
            uv: false,
        };
        AuthenticatorMakeCredentialParameters {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list: None,
            extensions: MakeCredentialExtensions::default(),
            options,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
            enterprise_attestation: None,
            attestation_formats_preference: None,
        }
    }

    fn create_make_credential_parameters_with_exclude_list(
        excluded_credential_id: &[u8],
    ) -> AuthenticatorMakeCredentialParameters {
        let excluded_credential_descriptor = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: excluded_credential_id.to_vec(),
            transports: None,
        };
        let exclude_list = Some(vec![excluded_credential_descriptor]);
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.exclude_list = exclude_list;
        make_credential_params
    }

    fn create_make_credential_parameters_with_cred_protect_policy(
        policy: CredentialProtectionPolicy,
    ) -> AuthenticatorMakeCredentialParameters {
        let extensions = MakeCredentialExtensions {
            cred_protect: Some(policy),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        make_credential_params
    }

    fn parse_credential_id_from_non_resident_make_credential_response(
        env: &mut impl Env,
        make_credential_response: ResponseData,
    ) -> Vec<u8> {
        match make_credential_response {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                let auth_data = make_credential_response.auth_data;
                let offset = 37 + env.persist().aaguid().unwrap().len();
                assert_eq!(auth_data[offset], 0x00);
                assert_eq!(auth_data[offset + 1] as usize, CBOR_CREDENTIAL_ID_SIZE);
                auth_data[offset + 2..offset + 2 + CBOR_CREDENTIAL_ID_SIZE].to_vec()
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    fn test_resident_process_make_credential() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        check_make_response(&mut env, &make_credential_response, 0x41, 0x20, &[]);
    }

    #[test]
    fn test_non_resident_process_make_credential() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        check_make_response(
            &mut env,
            &make_credential_response,
            0x41,
            CBOR_CREDENTIAL_ID_SIZE as u8,
            &[],
        );
    }

    #[test]
    fn test_process_make_credential_unsupported_algorithm() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.pub_key_cred_params = vec![];
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        );
    }

    #[test]
    fn test_process_make_credential_credential_excluded() {
        let mut env = TestEnv::default();
        let excluded_private_key = PrivateKey::new_ecdsa(&mut env);
        let wrapped_private_key = excluded_private_key.to_cbor();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let excluded_credential_id = vec![0x01, 0x23, 0x45, 0x67];
        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&excluded_credential_id);
        let excluded_credential_source = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: excluded_credential_id,
            wrapped_private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
            third_party_payment: false,
        };
        assert!(storage::store_credential(&mut env, excluded_credential_source).is_ok());

        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );
    }

    #[test]
    fn test_process_make_credential_credential_with_cred_protect() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let test_policy = CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
        let make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        let credential_id = stored_credential.credential_id;
        assert_eq!(stored_credential.cred_protect_policy, Some(test_policy));

        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );

        let test_policy = CredentialProtectionPolicy::UserVerificationRequired;
        let make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        let credential_id = stored_credential.credential_id;
        assert_eq!(stored_credential.cred_protect_policy, Some(test_policy));

        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
    }

    #[test]
    fn test_non_resident_process_make_credential_credential_with_cred_protect() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::new(&mut env);

        let test_policy = CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
        let mut make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );

        let test_policy = CredentialProtectionPolicy::UserVerificationRequired;
        let mut make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
    }

    #[test]
    fn test_process_make_credential_hmac_secret() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        let expected_extension_cbor = [
            0xA1, 0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0xF5,
        ];
        check_make_response(
            &mut env,
            &make_credential_response,
            0xC1,
            CBOR_CREDENTIAL_ID_SIZE as u8,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_make_credential_hmac_secret_resident_key() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        let expected_extension_cbor = [
            0xA1, 0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0xF5,
        ];
        check_make_response(
            &mut env,
            &make_credential_response,
            0xC1,
            0x20,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_make_credential_min_pin_length() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // First part: The extension is ignored, since the RP ID is not on the list.
        let extensions = MakeCredentialExtensions {
            min_pin_length: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_make_response(&mut env, &make_credential_response, 0x41, 0x20, &[]);

        // Second part: The extension is used.
        assert_eq!(
            storage::set_min_pin_length_rp_ids(&mut env, vec!["example.com".to_string()]),
            Ok(())
        );

        let extensions = MakeCredentialExtensions {
            min_pin_length: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let expected_extension_cbor = [
            0xA1, 0x6C, 0x6D, 0x69, 0x6E, 0x50, 0x69, 0x6E, 0x4C, 0x65, 0x6E, 0x67, 0x74, 0x68,
            0x04,
        ];
        check_make_response(
            &mut env,
            &make_credential_response,
            0xC1,
            0x20,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_make_credential_cred_blob_ok() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let extensions = MakeCredentialExtensions {
            cred_blob: Some(vec![0xCB]),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0xF5,
        ];
        check_make_response(
            &mut env,
            &make_credential_response,
            0xC1,
            0x20,
            &expected_extension_cbor,
        );

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        assert_eq!(stored_credential.cred_blob, Some(vec![0xCB]));
    }

    #[test]
    fn test_process_make_credential_cred_blob_too_big() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let extensions = MakeCredentialExtensions {
            cred_blob: Some(vec![0xCB; env.customization().max_cred_blob_length() + 1]),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0xF4,
        ];
        check_make_response(
            &mut env,
            &make_credential_response,
            0xC1,
            0x20,
            &expected_extension_cbor,
        );

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        assert_eq!(stored_credential.cred_blob, None);
    }

    #[test]
    fn test_process_make_credential_large_blob_key() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let extensions = MakeCredentialExtensions {
            large_blob_key: Some(true),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let large_blob_key = match make_credential_response.unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                make_credential_response.large_blob_key.unwrap()
            }
            _ => panic!("Invalid response type"),
        };
        assert_eq!(large_blob_key.len(), 32);

        let mut iter_result = Ok(());
        let iter = storage::iter_credentials(&mut env, &mut iter_result).unwrap();
        // There is only 1 credential, so last is good enough.
        let (_, stored_credential) = iter.last().unwrap();
        iter_result.unwrap();
        assert_eq!(stored_credential.large_blob_key.unwrap(), large_blob_key);
    }

    fn test_helper_process_make_credential_with_pin_and_uv(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x91; PIN_TOKEN_LENGTH];
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            pin_uv_auth_protocol,
        );

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        ctap_state.client_pin = client_pin;
        env.persist().set_pin(&[0x88; 16], 4).unwrap();

        let client_data_hash = [0xCD];
        let pin_uv_auth_param = authenticate_pin_uv_auth_token(
            &pin_uv_auth_token,
            &client_data_hash,
            pin_uv_auth_protocol,
        );
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.uv = true;
        make_credential_params.pin_uv_auth_param = Some(pin_uv_auth_param);
        make_credential_params.pin_uv_auth_protocol = Some(pin_uv_auth_protocol);
        let make_credential_response = ctap_state.process_make_credential(
            &mut env,
            make_credential_params.clone(),
            DUMMY_CHANNEL,
        );

        check_make_response(&mut env, &make_credential_response, 0x45, 0x20, &[]);

        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        )
    }

    #[test]
    fn test_process_make_credential_with_pin_and_uv_v1() {
        test_helper_process_make_credential_with_pin_and_uv(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_make_credential_with_pin_and_uv_v2() {
        test_helper_process_make_credential_with_pin_and_uv(PinUvAuthProtocol::V2);
    }

    #[test]
    fn test_non_resident_process_make_credential_with_pin() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        env.persist().set_pin(&[0x88; 16], 4).unwrap();

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        check_make_response(
            &mut env,
            &make_credential_response,
            0x41,
            CBOR_CREDENTIAL_ID_SIZE as u8,
            &[],
        );
    }

    #[test]
    fn test_resident_process_make_credential_with_pin() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        env.persist().set_pin(&[0x88; 16], 4).unwrap();

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)
        );
    }

    #[test]
    fn test_process_make_credential_with_pin_always_uv() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        storage::toggle_always_uv(&mut env).unwrap();
        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PUAT_REQUIRED)
        );

        env.persist().set_pin(&[0x88; 16], 4).unwrap();
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.pin_uv_auth_param = Some(vec![0xA4; 16]);
        make_credential_params.pin_uv_auth_protocol = Some(PinUvAuthProtocol::V1);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }

    fn check_ep(make_credential_response: CtapResult<ResponseData>, has_ep: bool) {
        let ep_att = if has_ep { Some(true) } else { None };
        match make_credential_response.unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                assert_eq!(make_credential_response.ep_att, ep_att);
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    fn test_process_make_credential_with_enterprise_attestation_vendor_facilitated() {
        let mut env = TestEnv::default();
        env.customization_mut().setup_enterprise_attestation(
            Some(EnterpriseAttestationMode::VendorFacilitated),
            Some(vec!["example.com".to_string()]),
        );

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        test_helpers::enable_enterprise_attestation(&mut ctap_state, &mut env).unwrap();

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(1);
        make_credential_params.rp = PublicKeyCredentialRpEntity {
            rp_id: "counter-example.com".to_string(),
            rp_name: None,
            rp_icon: None,
        };
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, false);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(2);
        make_credential_params.rp = PublicKeyCredentialRpEntity {
            rp_id: "counter-example.com".to_string(),
            rp_name: None,
            rp_icon: None,
        };
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, false);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(1);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, true);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(2);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, true);
    }

    #[test]
    fn test_process_make_credential_with_enterprise_attestation_platform_managed() {
        let mut env = TestEnv::default();
        env.customization_mut().setup_enterprise_attestation(
            Some(EnterpriseAttestationMode::PlatformManaged),
            Some(vec!["example.com".to_string()]),
        );
        assert!(customization::is_valid(env.customization()));

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        test_helpers::enable_enterprise_attestation(&mut ctap_state, &mut env).unwrap();

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(1);
        make_credential_params.rp = PublicKeyCredentialRpEntity {
            rp_id: "counter-example.com".to_string(),
            rp_name: None,
            rp_icon: None,
        };
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, false);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(1);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, true);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(2);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        check_ep(make_credential_response, true);
    }

    #[test]
    fn test_process_make_credential_with_enterprise_attestation_invalid() {
        let mut env = TestEnv::default();
        env.customization_mut()
            .setup_enterprise_attestation(Some(EnterpriseAttestationMode::PlatformManaged), None);

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(2);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        test_helpers::enable_enterprise_attestation(&mut ctap_state, &mut env).unwrap();

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.enterprise_attestation = Some(3);
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION)
        );
    }

    #[test]
    fn test_process_make_credential_cancelled() {
        let mut env = TestEnv::default();
        env.user_presence().set(|| Err(UserPresenceError::Canceled));
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);

        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    #[test]
    #[cfg(feature = "fingerprint")]
    fn test_process_make_credential_cached_up() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x88; 32];
        let pin_uv_auth_protocol = PinUvAuthProtocol::V2;
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            pin_uv_auth_protocol,
        );
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        env.create_fingerprint().unwrap();
        ctap_state.client_pin = client_pin;

        env.persist().set_pin(&[0u8; 16], 4).unwrap();
        env.user_presence().set(|| Err(UserPresenceError::Canceled));
        let client_data_hash = [0xCD];
        let pin_uv_auth_param = authenticate_pin_uv_auth_token(
            &pin_uv_auth_token,
            &client_data_hash,
            pin_uv_auth_protocol,
        );
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.pin_uv_auth_param = Some(pin_uv_auth_param);
        make_credential_params.pin_uv_auth_protocol = Some(pin_uv_auth_protocol);
        assert!(
            ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok()
        );
    }

    fn check_assertion_response_with_user(
        response: CtapResult<ResponseData>,
        expected_user: Option<PublicKeyCredentialUserEntity>,
        flags: u8,
        signature_counter: u32,
        expected_number_of_credentials: Option<u64>,
        expected_extension_cbor: &[u8],
    ) {
        let assertion_response = match response.unwrap() {
            ResponseData::AuthenticatorGetAssertion(r) => r,
            ResponseData::AuthenticatorGetNextAssertion(r) => r,
            _ => panic!("Invalid response type"),
        };
        let AuthenticatorGetAssertionResponse {
            auth_data,
            user,
            number_of_credentials,
            ..
        } = assertion_response;
        let mut expected_auth_data = vec![
            0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80, 0x34,
            0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2, 0x12, 0x55,
            0x86, 0xCE, 0x19, 0x47, flags, 0x00, 0x00, 0x00, 0x00,
        ];
        let signature_counter_position = expected_auth_data.len() - 4;
        BigEndian::write_u32(
            &mut expected_auth_data[signature_counter_position..],
            signature_counter,
        );
        expected_auth_data.extend(expected_extension_cbor);
        assert_eq!(auth_data, expected_auth_data);
        assert_eq!(user, expected_user);
        assert_eq!(number_of_credentials, expected_number_of_credentials);
    }

    fn check_assertion_response_with_extension(
        response: CtapResult<ResponseData>,
        expected_user_id: Option<Vec<u8>>,
        signature_counter: u32,
        expected_number_of_credentials: Option<u64>,
        expected_extension_cbor: &[u8],
    ) {
        let expected_user = expected_user_id.map(|user_id| PublicKeyCredentialUserEntity {
            user_id,
            user_name: None,
            user_display_name: None,
            user_icon: None,
        });
        check_assertion_response_with_user(
            response,
            expected_user,
            0x80,
            signature_counter,
            expected_number_of_credentials,
            expected_extension_cbor,
        );
    }

    fn check_assertion_response(
        response: CtapResult<ResponseData>,
        expected_user_id: Vec<u8>,
        signature_counter: u32,
        expected_number_of_credentials: Option<u64>,
    ) {
        let expected_user = PublicKeyCredentialUserEntity {
            user_id: expected_user_id,
            user_name: None,
            user_display_name: None,
            user_icon: None,
        };
        check_assertion_response_with_user(
            response,
            Some(expected_user),
            0x00,
            signature_counter,
            expected_number_of_credentials,
            &[],
        );
    }

    #[test]
    fn test_resident_process_get_assertion() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let make_credential_params = create_minimal_make_credential_parameters();
        assert!(
            ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok()
        );

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let signature_counter = env.persist().global_signature_counter().unwrap();
        check_assertion_response(get_assertion_response, vec![0x1D], signature_counter, None);
    }

    #[test]
    fn test_process_get_assertion_cancelled() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let make_credential_params = create_minimal_make_credential_parameters();
        assert!(
            ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok()
        );

        env.user_presence().set(|| Err(UserPresenceError::Canceled));
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: true,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    #[test]
    #[cfg(feature = "fingerprint")]
    fn test_process_get_assertion_up_through_fingerprint() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let make_credential_params = create_minimal_make_credential_parameters();
        assert!(
            ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok()
        );

        env.user_presence().set(|| Err(UserPresenceError::Canceled));
        env.create_fingerprint().unwrap();
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions { up: true, uv: true },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let expected_user = PublicKeyCredentialUserEntity {
            user_id: vec![0x1D],
            user_name: None,
            user_display_name: None,
            user_icon: None,
        };
        let signature_counter = env.persist().global_signature_counter().unwrap();
        check_assertion_response_with_user(
            get_assertion_response,
            Some(expected_user),
            0x05,
            signature_counter,
            None,
            &[],
        );
    }

    #[test]
    #[cfg(not(feature = "fingerprint"))]
    fn test_process_get_assertion_no_uv_from_fingerprint() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let make_credential_params = create_minimal_make_credential_parameters();
        assert!(
            ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok()
        );

        env.user_presence().set(|| Err(UserPresenceError::Canceled));
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions { up: true, uv: true },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION)
        );
    }

    fn get_assertion_hmac_secret_params(
        key_agreement_key: EcdhSk<TestEnv>,
        key_agreement_response: ResponseData,
        credential_id: Option<Vec<u8>>,
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) -> AuthenticatorGetAssertionParameters {
        let mut env = TestEnv::default();
        let platform_public_key = key_agreement_key.public_key();
        let public_key = match key_agreement_response {
            ResponseData::AuthenticatorClientPin(Some(client_pin_response)) => {
                client_pin_response.key_agreement.unwrap()
            }
            _ => panic!("Invalid response type"),
        };
        let pin_protocol = PinProtocol::<TestEnv>::new_test(key_agreement_key, [0x91; 32]);
        let shared_secret = pin_protocol
            .decapsulate(public_key, pin_uv_auth_protocol)
            .unwrap();

        let salt = vec![0x01; 32];
        let salt_enc = shared_secret.encrypt(&mut env, &salt).unwrap();
        let salt_auth = shared_secret.authenticate(&salt_enc);
        let hmac_secret_input = GetAssertionHmacSecretInput {
            key_agreement: CoseKey::from_ecdh_public_key::<TestEnv>(platform_public_key),
            salt_enc,
            salt_auth,
            pin_uv_auth_protocol,
        };
        let get_extensions = GetAssertionExtensions {
            hmac_secret: Some(hmac_secret_input),
            ..Default::default()
        };

        let credential_descriptor = credential_id.map(|key_id| PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id,
            transports: None,
        });
        let allow_list = credential_descriptor.map(|c| vec![c]);
        AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list,
            extensions: get_extensions,
            options: GetAssertionOptions {
                up: true,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        }
    }

    fn test_helper_process_get_assertion_hmac_secret(pin_uv_auth_protocol: PinUvAuthProtocol) {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let make_extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        make_credential_params.extensions = make_extensions;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );

        let client_pin_params = AuthenticatorClientPinParameters {
            pin_uv_auth_protocol,
            sub_command: ClientPinSubCommand::GetKeyAgreement,
            key_agreement: None,
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            permissions_rp_id: None,
        };
        let key_agreement_response =
            ctap_state
                .client_pin
                .process_command(&mut env, client_pin_params, DUMMY_CHANNEL);
        let get_assertion_params = get_assertion_hmac_secret_params(
            key_agreement_key,
            key_agreement_response.unwrap(),
            Some(credential_id),
            pin_uv_auth_protocol,
        );
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert!(get_assertion_response.is_ok());
    }

    #[test]
    fn test_process_get_assertion_hmac_secret_v1() {
        test_helper_process_get_assertion_hmac_secret(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_get_assertion_hmac_secret_v2() {
        test_helper_process_get_assertion_hmac_secret(PinUvAuthProtocol::V2);
    }

    fn test_helper_resident_process_get_assertion_hmac_secret(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let make_extensions = MakeCredentialExtensions {
            hmac_secret: true,
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = make_extensions;
        assert!(
            ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok()
        );

        let client_pin_params = AuthenticatorClientPinParameters {
            pin_uv_auth_protocol,
            sub_command: ClientPinSubCommand::GetKeyAgreement,
            key_agreement: None,
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            permissions_rp_id: None,
        };
        let key_agreement_response =
            ctap_state
                .client_pin
                .process_command(&mut env, client_pin_params, DUMMY_CHANNEL);
        let get_assertion_params = get_assertion_hmac_secret_params(
            key_agreement_key,
            key_agreement_response.unwrap(),
            None,
            pin_uv_auth_protocol,
        );
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert!(get_assertion_response.is_ok());
    }

    #[test]
    fn test_process_resident_get_assertion_hmac_secret_v1() {
        test_helper_resident_process_get_assertion_hmac_secret(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_resident_process_get_assertion_hmac_secret_v2() {
        test_helper_resident_process_get_assertion_hmac_secret(PinUvAuthProtocol::V2);
    }

    fn test_helper_make_credential_hmac_secret_mc(
        pin_uv_auth_protocol: PinUvAuthProtocol,
        rk: bool,
        salts: Vec<u8>,
    ) {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // 1. Obtain authenticator keyAgreement public key.
        let client_pin_params = AuthenticatorClientPinParameters {
            pin_uv_auth_protocol,
            sub_command: ClientPinSubCommand::GetKeyAgreement,
            key_agreement: None,
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            permissions_rp_id: None,
        };
        let key_agreement_response = ctap_state
            .client_pin
            .process_command(&mut env, client_pin_params, DUMMY_CHANNEL)
            .unwrap();
        let authnr_public_key = match key_agreement_response {
            ResponseData::AuthenticatorClientPin(Some(client_pin_response)) => {
                client_pin_response.key_agreement.unwrap()
            }
            _ => panic!("Invalid response type"),
        };

        // 2. Platform encapsulates shared secret and builds hmac-secret-mc input.
        let platform_sk = EcdhSk::<TestEnv>::random(env.rng());
        let platform_pk = platform_sk.public_key();
        let pin_protocol = PinProtocol::<TestEnv>::new_test(platform_sk, [0x91; 32]);
        let shared_secret = pin_protocol
            .decapsulate(authnr_public_key, pin_uv_auth_protocol)
            .unwrap();

        let salt_enc = shared_secret.encrypt(&mut env, &salts).unwrap();
        let salt_auth = shared_secret.authenticate(&salt_enc);
        let hmac_secret_input = GetAssertionHmacSecretInput {
            key_agreement: CoseKey::from_ecdh_public_key::<TestEnv>(platform_pk),
            salt_enc,
            salt_auth,
            pin_uv_auth_protocol,
        };

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = rk;
        make_credential_params.extensions = MakeCredentialExtensions {
            hmac_secret: true,
            hmac_secret_mc: Some(hmac_secret_input.clone()),
            ..Default::default()
        };
        let make_credential_response = ctap_state
            .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
            .unwrap();

        // 3. Extract and decrypt hmac-secret-mc output from MakeCredential authData.
        let mc_auth_data = match &make_credential_response {
            ResponseData::AuthenticatorMakeCredential(resp) => resp.auth_data.clone(),
            _ => panic!("Invalid response type"),
        };
        let non_rk_cred_id = if !rk {
            Some(parse_credential_id_from_non_resident_make_credential_response(
                &mut env,
                make_credential_response,
            ))
        } else {
            None
        };
        // In MakeCredential authData:
        // 32 (rpIdHash) + 1 (flags) + 4 (signCount) + 16 (aaguid) + 2 (credIdLen) + credIdLen + coseKey + extensions
        let cred_id_len = ((mc_auth_data[53] as usize) << 8) | (mc_auth_data[54] as usize);
        // ES256 public COSE key is 77 bytes in canonical CBOR.
        let ext_offset = 55 + cred_id_len + 77;
        let mc_ext_cbor = cbor::read(&mc_auth_data[ext_offset..]).unwrap();
        destructure_cbor_map! {
            let {
                "hmac-secret" => mc_hmac_secret_enabled,
                "hmac-secret-mc" => mc_hmac_secret_enc,
            } = mc_ext_cbor.extract_map().unwrap();
        }
        assert_eq!(mc_hmac_secret_enabled.unwrap().extract_bool(), Some(true));
        let mc_output_enc = mc_hmac_secret_enc.unwrap().extract_byte_string().unwrap();
        let mc_decrypted_prf = shared_secret.decrypt(&mc_output_enc).unwrap();
        assert_eq!(mc_decrypted_prf.len(), salts.len());

        // 4. Perform GetAssertion with the exact same hmac-secret input and verify outputs match!
        let allow_list = non_rk_cred_id.map(|key_id| {
            vec![PublicKeyCredentialDescriptor {
                key_type: PublicKeyCredentialType::PublicKey,
                key_id,
                transports: None,
            }]
        });
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list,
            extensions: GetAssertionExtensions {
                hmac_secret: Some(hmac_secret_input),
                ..Default::default()
            },
            options: GetAssertionOptions {
                up: true,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state
            .process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL)
            .unwrap();
        let ga_auth_data = match get_assertion_response {
            ResponseData::AuthenticatorGetAssertion(resp) => resp.auth_data,
            _ => panic!("Invalid response type"),
        };
        let ga_ext_cbor = cbor::read(&ga_auth_data[37..]).unwrap();
        let ga_output_enc = {
            destructure_cbor_map! {
                let {
                    "hmac-secret" => ga_hmac_secret_enc,
                } = ga_ext_cbor.extract_map().unwrap();
            }
            ga_hmac_secret_enc.unwrap().extract_byte_string().unwrap()
        };
        let ga_decrypted_prf = shared_secret.decrypt(&ga_output_enc).unwrap();
        assert_eq!(&mc_decrypted_prf[..], &ga_decrypted_prf[..]);
    }

    #[test]
    fn test_process_make_credential_hmac_secret_mc_v1() {
        test_helper_make_credential_hmac_secret_mc(PinUvAuthProtocol::V1, false, vec![0x11; 32]);
        test_helper_make_credential_hmac_secret_mc(PinUvAuthProtocol::V1, true, vec![0x22; 64]);
    }

    #[test]
    fn test_process_make_credential_hmac_secret_mc_v2() {
        test_helper_make_credential_hmac_secret_mc(PinUvAuthProtocol::V2, false, vec![0x33; 32]);
        test_helper_make_credential_hmac_secret_mc(PinUvAuthProtocol::V2, true, vec![0x44; 64]);
    }

    #[test]
    fn test_process_make_credential_hmac_secret_mc_invalid_aborts_before_storage() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let platform_sk = EcdhSk::<TestEnv>::random(env.rng());
        let platform_pk = platform_sk.public_key();
        let bad_hmac_secret_input = GetAssertionHmacSecretInput {
            key_agreement: CoseKey::from_ecdh_public_key::<TestEnv>(platform_pk),
            salt_enc: vec![0x00; 32],
            salt_auth: vec![0xFF; 16],
            pin_uv_auth_protocol: PinUvAuthProtocol::V1,
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = true;
        make_credential_params.extensions = MakeCredentialExtensions {
            hmac_secret: true,
            hmac_secret_mc: Some(bad_hmac_secret_input),
            ..Default::default()
        };
        assert_eq!(
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL),
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
        // Verify no resident credential was written to storage on failure.
        let mut iter_result = Ok(());
        let count = storage::iter_credentials(&mut env, &mut iter_result)
            .unwrap()
            .count();
        iter_result.unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_webauthn_prf_ctap_test_vectors() {
        // Test vectors from W3C WebAuthn Level 4 §"CTAP2 `hmac-secret` extension"
        // (scratch/GitHub/webauthn/index.bs lines 10169-10273)
        let mut env = TestEnv::default();
        let cred_random: [u8; 32] = [
            0x43, 0x7e, 0x06, 0x5e, 0x72, 0x3a, 0x98, 0xb2, 0xf0, 0x8f, 0x39, 0xd8, 0xba, 0xf7,
            0xc5, 0x3e, 0xcb, 0x3c, 0x36, 0x3c, 0x5e, 0x51, 0x04, 0xbd, 0xaa, 0xf5, 0xd5, 0xca,
            0x2e, 0x02, 0x81, 0x54,
        ];
        let prf_eval_first = b"WebAuthn PRF test vectors\x02";
        let prf_eval_second = b"WebAuthn PRF test vectors\x03";

        let mut salt1_input = b"WebAuthn PRF\x00".to_vec();
        salt1_input.extend_from_slice(prf_eval_first);
        let salt1 = Sha::<TestEnv>::digest(&salt1_input);
        assert_eq!(
            salt1,
            [
                0x52, 0x74, 0x13, 0xeb, 0xb4, 0x82, 0x93, 0x77, 0x2d, 0xf3, 0x0f, 0x03, 0x1c,
                0x5a, 0xc4, 0x65, 0x0c, 0x7d, 0xe1, 0x4b, 0xf9, 0x49, 0x86, 0x71, 0xae, 0x16,
                0x34, 0x47, 0xb6, 0xa7, 0x72, 0xb3,
            ]
        );

        let mut salt2_input = b"WebAuthn PRF\x00".to_vec();
        salt2_input.extend_from_slice(prf_eval_second);
        let salt2 = Sha::<TestEnv>::digest(&salt2_input);
        assert_eq!(
            salt2,
            [
                0xd6, 0x8a, 0xc0, 0x33, 0x29, 0xa1, 0x0e, 0xe5, 0xe0, 0xec, 0x83, 0x44, 0x92,
                0xbb, 0x9a, 0x96, 0xa0, 0xe5, 0x47, 0xba, 0xf5, 0x63, 0xbf, 0x78, 0xcc, 0xbe,
                0x87, 0x89, 0xb2, 0x2e, 0x77, 0x6b,
            ]
        );

        let expected_output1: [u8; 32] = [
            0x3c, 0x33, 0xe0, 0x7d, 0x20, 0x2c, 0x3b, 0x02, 0x9c, 0xc2, 0x1f, 0x17, 0x22, 0x76,
            0x70, 0x21, 0xbf, 0x27, 0xd5, 0x95, 0x93, 0x3b, 0x3d, 0x2b, 0x6a, 0x1b, 0x9d, 0x5d,
            0xdd, 0xc7, 0x7f, 0xae,
        ];
        let expected_output2: [u8; 32] = [
            0xa6, 0x2a, 0x87, 0x73, 0xb1, 0x9c, 0xda, 0x90, 0xd7, 0xed, 0x4e, 0xf7, 0x2a, 0x80,
            0xa8, 0x04, 0x32, 0x0d, 0xbd, 0x39, 0x97, 0xe2, 0xf6, 0x63, 0x80, 0x5a, 0xd1, 0xfd,
            0x32, 0x93, 0xd5, 0x0b,
        ];

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        for protocol in [PinUvAuthProtocol::V1, PinUvAuthProtocol::V2] {
            let client_pin_params = AuthenticatorClientPinParameters {
                pin_uv_auth_protocol: protocol,
                sub_command: ClientPinSubCommand::GetKeyAgreement,
                key_agreement: None,
                pin_uv_auth_param: None,
                new_pin_enc: None,
                pin_hash_enc: None,
                permissions: None,
                permissions_rp_id: None,
            };
            let key_agreement_response = ctap_state
                .client_pin
                .process_command(&mut env, client_pin_params, DUMMY_CHANNEL)
                .unwrap();
            let authnr_cose_pk = match key_agreement_response {
                ResponseData::AuthenticatorClientPin(Some(client_pin_response)) => {
                    client_pin_response.key_agreement.unwrap()
                }
                _ => panic!("Invalid response type"),
            };
            let plat_sk = EcdhSk::<TestEnv>::random(env.rng());
            let plat_cose_pk = CoseKey::from_ecdh_public_key::<TestEnv>(plat_sk.public_key());
            let pin_protocol = PinProtocol::<TestEnv>::new_test(plat_sk, [0x91; 32]);
            let shared_secret = pin_protocol.decapsulate(authnr_cose_pk, protocol).unwrap();

            // Single-input case
            let salt_enc_1 = shared_secret.encrypt(&mut env, &salt1).unwrap();
            let salt_auth_1 = shared_secret.authenticate(&salt_enc_1);
            let input_1 = GetAssertionHmacSecretInput {
                key_agreement: plat_cose_pk.clone(),
                salt_enc: salt_enc_1,
                salt_auth: salt_auth_1,
                pin_uv_auth_protocol: protocol,
            };
            let output_enc_1 = ctap_state
                .client_pin
                .process_hmac_secret(&mut env, input_1, &cred_random)
                .unwrap();
            let decrypted_1 = shared_secret.decrypt(&output_enc_1).unwrap();
            assert_eq!(&decrypted_1[..], &expected_output1);

            // Two-input case
            let mut salts_both = salt1.to_vec();
            salts_both.extend_from_slice(&salt2);
            let salt_enc_2 = shared_secret.encrypt(&mut env, &salts_both).unwrap();
            let salt_auth_2 = shared_secret.authenticate(&salt_enc_2);
            let input_2 = GetAssertionHmacSecretInput {
                key_agreement: plat_cose_pk,
                salt_enc: salt_enc_2,
                salt_auth: salt_auth_2,
                pin_uv_auth_protocol: protocol,
            };
            let output_enc_2 = ctap_state
                .client_pin
                .process_hmac_secret(&mut env, input_2, &cred_random)
                .unwrap();
            let decrypted_2 = shared_secret.decrypt(&output_enc_2).unwrap();
            assert_eq!(&decrypted_2[..32], &expected_output1);
            assert_eq!(&decrypted_2[32..], &expected_output2);
        }
    }

    #[test]
    fn test_resident_process_get_assertion_with_cred_protect() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let wrapped_private_key = private_key.to_cbor();
        let credential_id = env.rng().gen_uniform_u8x32().to_vec();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id.clone(),
            transports: None,
        };
        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: credential_id.clone(),
            wrapped_private_key: wrapped_private_key.clone(),
            rp_id: String::from("example.com"),
            user_handle: vec![0x1D],
            user_display_name: None,
            cred_protect_policy: Some(
                CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList,
            ),
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
            third_party_payment: false,
        };
        assert!(storage::store_credential(&mut env, credential).is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS),
        );

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc.clone()]),
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let signature_counter = env.persist().global_signature_counter().unwrap();
        check_assertion_response(get_assertion_response, vec![0x1D], signature_counter, None);

        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            wrapped_private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x1D],
            user_display_name: None,
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationRequired),
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
            third_party_payment: false,
        };
        assert!(storage::store_credential(&mut env, credential).is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS),
        );
    }

    #[test]
    fn test_non_resident_process_get_assertion_with_cred_protect() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::new(&mut env);

        let test_policy = CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
        let mut make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id,
            transports: None,
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert!(get_assertion_response.is_ok());

        let test_policy = CredentialProtectionPolicy::UserVerificationRequired;
        let mut make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        assert!(make_credential_response.is_ok());
        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id,
            transports: None,
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS),
        );
    }

    #[test]
    fn test_process_get_assertion_with_cred_blob() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let wrapped_private_key = private_key.to_cbor();
        let credential_id = env.rng().gen_uniform_u8x32().to_vec();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            wrapped_private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x1D],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: Some(vec![0xCB]),
            large_blob_key: None,
            third_party_payment: false,
        };
        assert!(storage::store_credential(&mut env, credential).is_ok());

        let extensions = GetAssertionExtensions {
            cred_blob: true,
            ..Default::default()
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let signature_counter = env.persist().global_signature_counter().unwrap();
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0x41, 0xCB,
        ];
        check_assertion_response_with_extension(
            get_assertion_response,
            Some(vec![0x1D]),
            signature_counter,
            None,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_non_resident_process_get_assertion_with_cred_blob() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::new(&mut env);

        let extensions = MakeCredentialExtensions {
            cred_blob: Some(vec![0xCB]),
            ..Default::default()
        };
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL);
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0xF5,
        ];
        check_make_response(
            &mut env,
            &make_credential_response,
            0xC1,
            CBOR_CREDENTIAL_ID_SIZE as u8,
            &expected_extension_cbor,
        );

        let credential_id = parse_credential_id_from_non_resident_make_credential_response(
            &mut env,
            make_credential_response.unwrap(),
        );
        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id,
            transports: None,
        };
        let extensions = GetAssertionExtensions {
            cred_blob: true,
            ..Default::default()
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let signature_counter = env.persist().global_signature_counter().unwrap();
        let expected_extension_cbor = [
            0xA1, 0x68, 0x63, 0x72, 0x65, 0x64, 0x42, 0x6C, 0x6F, 0x62, 0x41, 0xCB,
        ];
        check_assertion_response_with_extension(
            get_assertion_response,
            None,
            signature_counter,
            None,
            &expected_extension_cbor,
        );
    }

    #[test]
    fn test_process_get_assertion_with_large_blob_key() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let wrapped_private_key = private_key.to_cbor();
        let credential_id = env.rng().gen_uniform_u8x32().to_vec();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            wrapped_private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x1D],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: Some(vec![0x1C; 32]),
            third_party_payment: false,
        };
        assert!(storage::store_credential(&mut env, credential).is_ok());

        let extensions = GetAssertionExtensions {
            large_blob_key: Some(true),
            ..Default::default()
        };
        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let large_blob_key = match get_assertion_response.unwrap() {
            ResponseData::AuthenticatorGetAssertion(get_assertion_response) => {
                get_assertion_response.large_blob_key.unwrap()
            }
            _ => panic!("Invalid response type"),
        };
        assert_eq!(large_blob_key, vec![0x1C; 32]);
    }

    fn test_helper_process_get_next_assertion_two_credentials_with_uv(
        pin_uv_auth_protocol: PinUvAuthProtocol,
    ) {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x88; 32];
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            pin_uv_auth_protocol,
        );

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        let user1 = PublicKeyCredentialUserEntity {
            user_id: vec![0x01],
            user_name: Some("user1".to_string()),
            user_display_name: Some("User One".to_string()),
            user_icon: Some("icon1".to_string()),
        };
        make_credential_params.user = user1.clone();
        assert!(
            ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok()
        );
        let mut make_credential_params = create_minimal_make_credential_parameters();
        let user2 = PublicKeyCredentialUserEntity {
            user_id: vec![0x02],
            user_name: Some("user2".to_string()),
            user_display_name: Some("User Two".to_string()),
            user_icon: Some("icon2".to_string()),
        };
        make_credential_params.user = user2.clone();
        assert!(
            ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok()
        );

        ctap_state.client_pin = client_pin;
        // The PIN length is outside of the test scope and most likely incorrect.
        env.persist().set_pin(&[0u8; 16], 4).unwrap();
        let client_data_hash = vec![0xCD];
        let pin_uv_auth_param = authenticate_pin_uv_auth_token(
            &pin_uv_auth_token,
            &client_data_hash,
            pin_uv_auth_protocol,
        );

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash,
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: true,
            },
            pin_uv_auth_param: Some(pin_uv_auth_param),
            pin_uv_auth_protocol: Some(pin_uv_auth_protocol),
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let signature_counter = env.persist().global_signature_counter().unwrap();
        check_assertion_response_with_user(
            get_assertion_response,
            Some(user2),
            0x04,
            signature_counter,
            Some(2),
            &[],
        );

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        check_assertion_response_with_user(
            get_assertion_response,
            Some(user1),
            0x04,
            signature_counter,
            None,
            &[],
        );

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_get_next_assertion_two_credentials_with_uv_v1() {
        test_helper_process_get_next_assertion_two_credentials_with_uv(PinUvAuthProtocol::V1);
    }

    #[test]
    fn test_process_get_next_assertion_two_credentials_with_uv_v2() {
        test_helper_process_get_next_assertion_two_credentials_with_uv(PinUvAuthProtocol::V2);
    }

    #[test]
    fn test_process_get_next_assertion_three_credentials_no_uv() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x01];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(
            ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok()
        );
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x02];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(
            ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok()
        );
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x03];
        make_credential_params.user.user_name = Some("removed".to_string());
        make_credential_params.user.user_display_name = Some("removed".to_string());
        make_credential_params.user.user_icon = Some("removed".to_string());
        assert!(
            ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok()
        );

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        let signature_counter = env.persist().global_signature_counter().unwrap();
        check_assertion_response(
            get_assertion_response,
            vec![0x03],
            signature_counter,
            Some(3),
        );

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        check_assertion_response(get_assertion_response, vec![0x02], signature_counter, None);

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        check_assertion_response(get_assertion_response, vec![0x01], signature_counter, None);

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_get_next_assertion_not_allowed() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x01];
        assert!(
            ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok()
        );
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.user.user_id = vec![0x02];
        assert!(
            ctap_state
                .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                .is_ok()
        );

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(&mut env, get_assertion_params, DUMMY_CHANNEL);
        assert!(get_assertion_response.is_ok());

        // This is a MakeCredential command.
        let mut command_cbor = vec![0x01];
        let cbor_value = cbor_map! {
            1 => vec![0xCD; 16],
            2 => cbor_map! {
                "id" => "example.com",
            },
            3 => cbor_map! {
                "id" => vec![0x1D, 0x1D, 0x1D, 0x1D],
            },
            4 => cbor_array![ES256_CRED_PARAM],
        };
        assert!(cbor_write(cbor_value, &mut command_cbor).is_ok());
        ctap_state.process_command(&mut env, &command_cbor, DUMMY_CHANNEL);

        let get_assertion_response = ctap_state.process_get_next_assertion(&mut env);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_process_reset() {
        let mut env = TestEnv::default();
        let private_key = PrivateKey::new_ecdsa(&mut env);
        let wrapped_private_key = private_key.to_cbor();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let credential_id = vec![0x01, 0x23, 0x45, 0x67];
        let credential_source = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            wrapped_private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![],
            user_display_name: None,
            cred_protect_policy: None,
            creation_order: 0,
            user_name: None,
            user_icon: None,
            cred_blob: None,
            large_blob_key: None,
            third_party_payment: false,
        };
        assert!(storage::store_credential(&mut env, credential_source).is_ok());
        assert!(storage::count_credentials(&mut env).unwrap() > 0);

        let reset_reponse = ctap_state.process_command(&mut env, &[0x07], DUMMY_CHANNEL);
        let expected_response = vec![0x00];
        assert_eq!(reset_reponse, expected_response);
        assert!(storage::count_credentials(&mut env).unwrap() == 0);
    }

    #[test]
    #[cfg(not(feature = "no_reset_restrictions"))]
    fn test_process_reset_cancelled() {
        let mut env = TestEnv::default();
        env.user_presence().set(|| Err(UserPresenceError::Canceled));
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let reset_reponse = ctap_state.process_reset(&mut env, DUMMY_CHANNEL);

        assert_eq!(
            reset_reponse,
            Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    #[test]
    #[cfg(not(feature = "no_reset_restrictions"))]
    fn test_process_reset_not_first() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // This is a GetNextAssertion command.
        ctap_state.process_command(&mut env, &[0x08], DUMMY_CHANNEL);

        let reset_reponse = ctap_state.process_reset(&mut env, DUMMY_CHANNEL);
        assert_eq!(reset_reponse, Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED));
    }

    #[test]
    #[cfg(feature = "no_reset_restrictions")]
    fn test_process_reset_unrestricted() {
        let mut env = TestEnv::default();
        env.user_presence().set(|| Err(UserPresenceError::Canceled));
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // Execute another command and advance clock past reset timeout.
        ctap_state.process_command(&mut env, &[0x08], DUMMY_CHANNEL);
        env.clock().advance(RESET_TIMEOUT_DURATION_MS);

        let reset_response =
            ctap_state.process_parsed_command(&mut env, Command::AuthenticatorReset, DUMMY_CHANNEL);
        assert_eq!(reset_response, Ok(ResponseData::AuthenticatorReset));
    }

    #[test]
    fn test_process_credential_management_unknown_subcommand() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // The subcommand 0xEE does not exist.
        let reponse =
            ctap_state.process_command(&mut env, &[0x0A, 0xA1, 0x01, 0x18, 0xEE], DUMMY_CHANNEL);
        let expected_response = vec![Ctap2StatusCode::CTAP2_ERR_INVALID_SUBCOMMAND as u8];
        assert_eq!(reponse, expected_response);
    }

    #[test]
    fn test_process_unknown_command() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // This command does not exist.
        let reponse = ctap_state.process_command(&mut env, &[0xDF], DUMMY_CHANNEL);
        let expected_response = vec![Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND as u8];
        assert_eq!(reponse, expected_response);
    }

    #[test]
    fn test_signature_counter() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let mut last_counter = env.persist().global_signature_counter().unwrap();
        assert!(last_counter > 0);
        for _ in 0..100 {
            assert!(
                ctap_state
                    .increment_global_signature_counter(&mut env)
                    .is_ok()
            );
            let next_counter = env.persist().global_signature_counter().unwrap();
            assert!(next_counter > last_counter);
            last_counter = next_counter;
        }
    }

    #[test]
    fn test_permission_timeout() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // Write 2 credentials for later assertions.
        for i in 0..3 {
            let mut make_credential_params = create_minimal_make_credential_parameters();
            make_credential_params.user.user_id = vec![i as u8];
            assert!(
                ctap_state
                    .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                    .is_ok()
            );
        }

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetAssertion(get_assertion_params),
            DUMMY_CHANNEL,
        );
        env.clock()
            .advance(STATEFUL_COMMAND_TIMEOUT_DURATION_MS - 1);
        assert!(get_assertion_response.is_ok());
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            DUMMY_CHANNEL,
        );
        assert!(get_next_assertion_response.is_ok());
        env.clock().advance(1);
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            DUMMY_CHANNEL,
        );
        assert_eq!(
            get_next_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    #[cfg(not(feature = "no_reset_restrictions"))]
    fn test_reset_timeout() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        env.clock().advance(RESET_TIMEOUT_DURATION_MS);
        let response =
            ctap_state.process_parsed_command(&mut env, Command::AuthenticatorReset, DUMMY_CHANNEL);
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED));
    }

    #[test]
    #[cfg(feature = "fingerprint")]
    fn test_reset_removes_fingerprints() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        env.create_fingerprint().unwrap();
        assert_eq!(perform_built_in_uv(&mut env, DUMMY_CHANNEL, false), Ok(()));

        let response =
            ctap_state.process_parsed_command(&mut env, Command::AuthenticatorReset, DUMMY_CHANNEL);
        assert_eq!(response, Ok(ResponseData::AuthenticatorReset));
        assert_eq!(env.persist().template_infos(), Ok(vec![]));
        assert_eq!(
            perform_built_in_uv(&mut env, DUMMY_CHANNEL, false),
            Err(Ctap2StatusCode::CTAP2_ERR_UV_INVALID)
        );
    }

    #[test]
    fn test_credential_management_timeout() {
        let mut env = TestEnv::default();
        let key_agreement_key = EcdhSk::<TestEnv>::random(env.rng());
        let pin_uv_auth_token = [0x55; 32];
        let client_pin = ClientPin::<TestEnv>::new_test(
            &mut env,
            key_agreement_key,
            pin_uv_auth_token,
            PinUvAuthProtocol::V1,
        );

        let private_key = PrivateKey::new_ecdsa(&mut env);
        let wrapped_private_key = private_key.to_cbor();
        let credential_source = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: env.rng().gen_uniform_u8x32().to_vec(),
            wrapped_private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x01],
            user_display_name: Some("display_name".to_string()),
            cred_protect_policy: None,
            creation_order: 0,
            user_name: Some("name".to_string()),
            user_icon: Some("icon".to_string()),
            cred_blob: None,
            large_blob_key: None,
            third_party_payment: false,
        };

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        ctap_state.client_pin = client_pin;

        for i in 0..3 {
            let mut credential = credential_source.clone();
            credential.rp_id = i.to_string();
            storage::store_credential(&mut env, credential).unwrap();
        }

        env.persist().set_pin(&[0u8; 16], 4).unwrap();
        let pin_uv_auth_param = Some(vec![
            0x1A, 0xA4, 0x96, 0xDA, 0x62, 0x80, 0x28, 0x13, 0xEB, 0x32, 0xB9, 0xF1, 0xD2, 0xA9,
            0xD0, 0xD1,
        ]);

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsBegin,
            sub_command_params: None,
            pin_uv_auth_protocol: Some(PinUvAuthProtocol::V1),
            pin_uv_auth_param,
        };
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorCredentialManagement(cred_management_params),
            DUMMY_CHANNEL,
        );
        assert!(matches!(
            response,
            Ok(ResponseData::AuthenticatorCredentialManagement(_))
        ));

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsGetNextRp,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        env.clock()
            .advance(STATEFUL_COMMAND_TIMEOUT_DURATION_MS - 1);
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorCredentialManagement(cred_management_params),
            DUMMY_CHANNEL,
        );
        assert!(matches!(
            response,
            Ok(ResponseData::AuthenticatorCredentialManagement(_))
        ));

        let cred_management_params = AuthenticatorCredentialManagementParameters {
            sub_command: CredentialManagementSubCommand::EnumerateRpsGetNextRp,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        env.clock().advance(1);
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorCredentialManagement(cred_management_params),
            DUMMY_CHANNEL,
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED));
    }

    #[test]
    fn test_check_user_presence() {
        // This TestEnv always returns successful user_presence checks.
        let mut env = TestEnv::default();
        let response = check_user_presence(&mut env, DUMMY_CHANNEL);
        assert!(response.is_ok());
    }

    #[test]
    fn test_check_user_presence_timeout() {
        let mut env = TestEnv::default();
        let clock = env.clock().clone();
        env.user_presence().set(move || {
            clock.advance(100);
            Err(UserPresenceError::Timeout)
        });
        let response = check_user_presence(&mut env, DUMMY_CHANNEL);
        assert!(matches!(
            response,
            Err(Ctap2StatusCode::CTAP2_ERR_USER_ACTION_TIMEOUT)
        ));
    }

    #[test]
    fn test_channel_interleaving() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        const NEW_CHANNEL: Channel = Channel::MainHid([0xAA, 0xAA, 0xAA, 0xAA]);

        // Write 3 credentials for later assertions.
        for i in 0..3 {
            let mut make_credential_params = create_minimal_make_credential_parameters();
            make_credential_params.user.user_id = vec![i as u8];
            assert!(
                ctap_state
                    .process_make_credential(&mut env, make_credential_params, DUMMY_CHANNEL)
                    .is_ok()
            );
        }

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: GetAssertionExtensions::default(),
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetAssertion(get_assertion_params),
            DUMMY_CHANNEL,
        );
        assert!(matches!(
            get_assertion_response,
            Ok(ResponseData::AuthenticatorGetAssertion(_))
        ));
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            DUMMY_CHANNEL,
        );
        assert!(get_next_assertion_response.is_ok());
        assert!(matches!(
            get_next_assertion_response,
            Ok(ResponseData::AuthenticatorGetNextAssertion(_))
        ));
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            NEW_CHANNEL,
        );
        assert_eq!(
            get_next_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
        let get_next_assertion_response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            DUMMY_CHANNEL,
        );
        assert_eq!(
            get_next_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED)
        );
    }

    #[test]
    fn test_get_info_command() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetInfo,
            DUMMY_CHANNEL,
        );
        assert!(matches!(
            response,
            Ok(ResponseData::AuthenticatorGetInfo(_))
        ));
        #[cfg(feature = "vendor_hid")]
        {
            let response = ctap_state.process_parsed_command(
                &mut env,
                Command::AuthenticatorGetInfo,
                VENDOR_CHANNEL,
            );
            assert!(matches!(
                response,
                Ok(ResponseData::AuthenticatorGetInfo(_))
            ));
        }
    }

    #[test]
    #[cfg(feature = "vendor_hid")]
    fn test_vendor_hid_does_not_support_fido_command() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::new(&mut env);
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetNextAssertion,
            VENDOR_CHANNEL,
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_COMMAND));
    }

    #[test]
    #[cfg(feature = "vendor_hid")]
    fn test_vendor_hid() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorGetInfo,
            VENDOR_CHANNEL,
        );
        assert!(matches!(
            response,
            Ok(ResponseData::AuthenticatorGetInfo(_))
        ));
    }

    #[test]
    fn test_large_blob_stateful() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        const EMPTY_BLOB_ARRAY: [u8; 17] = [
            0x80, 0x76, 0xBE, 0x8B, 0x52, 0x8D, 0x00, 0x75, 0xF7, 0xAA, 0xE9, 0x8D, 0x6F, 0xA5,
            0x7A, 0x6D, 0x3C,
        ];

        let params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(EMPTY_BLOB_ARRAY[..1].to_vec()),
            offset: 0,
            length: Some(EMPTY_BLOB_ARRAY.len()),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorLargeBlobs(params),
            DUMMY_CHANNEL,
        );
        assert_eq!(response, Ok(ResponseData::AuthenticatorLargeBlobs(None)));

        let params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(EMPTY_BLOB_ARRAY[1..].to_vec()),
            offset: 1,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorLargeBlobs(params),
            DUMMY_CHANNEL,
        );
        assert_eq!(response, Ok(ResponseData::AuthenticatorLargeBlobs(None)));
    }

    #[test]
    fn test_large_blob_stateful_interleaved() {
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        const EMPTY_BLOB_ARRAY: [u8; 17] = [
            0x80, 0x76, 0xBE, 0x8B, 0x52, 0x8D, 0x00, 0x75, 0xF7, 0xAA, 0xE9, 0x8D, 0x6F, 0xA5,
            0x7A, 0x6D, 0x3C,
        ];

        let params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(EMPTY_BLOB_ARRAY[..1].to_vec()),
            offset: 0,
            length: Some(EMPTY_BLOB_ARRAY.len()),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorLargeBlobs(params),
            DUMMY_CHANNEL,
        );
        assert_eq!(response, Ok(ResponseData::AuthenticatorLargeBlobs(None)));

        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorSelection,
            DUMMY_CHANNEL,
        );
        assert_eq!(response, Ok(ResponseData::AuthenticatorSelection));

        let params = AuthenticatorLargeBlobsParameters {
            get: None,
            set: Some(EMPTY_BLOB_ARRAY[1..].to_vec()),
            offset: 1,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let response = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorLargeBlobs(params),
            DUMMY_CHANNEL,
        );
        assert_eq!(response, Err(Ctap2StatusCode::CTAP1_ERR_INVALID_SEQ));
    }

    #[test]
    #[cfg(feature = "mldsa")]
    fn test_mldsa_make_credential_and_get_assertion() {
        use crate::api::crypto::mldsa::{
            ML_DSA_44_SIG_SIZE, ML_DSA_65_SIG_SIZE, ML_DSA_87_SIG_SIZE, MlDsaVariant,
        };
        use crate::ctap::command::AuthenticatorGetAssertionParameters;
        use ml_dsa::{
            EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, Signature, Verifier, VerifyingKey,
        };

        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        for (cred_param, variant, expected_sig_size) in [
            (
                ML_DSA_44_CRED_PARAM,
                MlDsaVariant::MlDsa44,
                ML_DSA_44_SIG_SIZE,
            ),
            (
                ML_DSA_65_CRED_PARAM,
                MlDsaVariant::MlDsa65,
                ML_DSA_65_SIG_SIZE,
            ),
            (
                ML_DSA_87_CRED_PARAM,
                MlDsaVariant::MlDsa87,
                ML_DSA_87_SIG_SIZE,
            ),
        ] {
            for rk in [false, true] {
                let mut make_params = create_minimal_make_credential_parameters();
                make_params.pub_key_cred_params = vec![cred_param.clone()];
                make_params.options.rk = rk;
                let make_resp = ctap_state
                    .process_make_credential(&mut env, make_params, DUMMY_CHANNEL)
                    .unwrap();
                let (cred_id, cose_key_bytes) = match make_resp {
                    ResponseData::AuthenticatorMakeCredential(r) => {
                        assert_eq!(r.att_stmt.alg, cred_param.alg as i64);
                        assert_eq!(r.att_stmt.sig.len(), expected_sig_size);
                        assert!(r.att_stmt.x5c.is_none());
                        let offset = 37 + env.persist().aaguid().unwrap().len();
                        let cred_id_len =
                            u16::from_be_bytes([r.auth_data[offset], r.auth_data[offset + 1]])
                                as usize;
                        let cred_id = r.auth_data[offset + 2..offset + 2 + cred_id_len].to_vec();
                        let cose_key_bytes = r.auth_data[offset + 2 + cred_id_len..].to_vec();
                        (cred_id, cose_key_bytes)
                    }
                    _ => panic!("Expected AuthenticatorMakeCredential"),
                };

                let cose_val = cbor_read(&cose_key_bytes).unwrap();
                let cose_key = CoseKey::try_from(cose_val.clone()).unwrap();
                assert_eq!(cbor::Value::from(cose_key), cose_val);

                let get_params = AuthenticatorGetAssertionParameters {
                    rp_id: String::from("example.com"),
                    client_data_hash: vec![0xCD; 32],
                    allow_list: if rk {
                        None
                    } else {
                        Some(vec![PublicKeyCredentialDescriptor {
                            key_type: PublicKeyCredentialType::PublicKey,
                            key_id: cred_id.clone(),
                            transports: None,
                        }])
                    },
                    extensions: Default::default(),
                    options: GetAssertionOptions {
                        up: true,
                        uv: false,
                    },
                    pin_uv_auth_param: None,
                    pin_uv_auth_protocol: None,
                };
                let get_resp = ctap_state
                    .process_get_assertion(&mut env, get_params, DUMMY_CHANNEL)
                    .unwrap();
                match get_resp {
                    ResponseData::AuthenticatorGetAssertion(r) => {
                        assert_eq!(r.signature.len(), expected_sig_size);
                        // Extract raw public key from COSE_Key map (-1 => pub_bytes)
                        let pub_bytes = cose_val
                            .extract_map()
                            .unwrap()
                            .into_iter()
                            .find(|(k, _)| *k == cbor::Value::from(-1i64))
                            .unwrap()
                            .1
                            .extract_byte_string()
                            .unwrap();
                        let mut signed_data = r.auth_data.clone();
                        signed_data.extend_from_slice(&[0xCD; 32]);
                        match variant {
                            MlDsaVariant::MlDsa44 => {
                                let pk_enc =
                                    EncodedVerifyingKey::<MlDsa44>::try_from(pub_bytes.as_slice())
                                        .unwrap();
                                let vk = VerifyingKey::<MlDsa44>::decode(&pk_enc);
                                let sig =
                                    Signature::<MlDsa44>::try_from(r.signature.as_slice()).unwrap();
                                assert!(vk.verify(&signed_data, &sig).is_ok());
                            }
                            MlDsaVariant::MlDsa65 => {
                                let pk_enc =
                                    EncodedVerifyingKey::<MlDsa65>::try_from(pub_bytes.as_slice())
                                        .unwrap();
                                let vk = VerifyingKey::<MlDsa65>::decode(&pk_enc);
                                let sig =
                                    Signature::<MlDsa65>::try_from(r.signature.as_slice()).unwrap();
                                assert!(vk.verify(&signed_data, &sig).is_ok());
                            }
                            MlDsaVariant::MlDsa87 => {
                                let pk_enc =
                                    EncodedVerifyingKey::<MlDsa87>::try_from(pub_bytes.as_slice())
                                        .unwrap();
                                let vk = VerifyingKey::<MlDsa87>::decode(&pk_enc);
                                let sig =
                                    Signature::<MlDsa87>::try_from(r.signature.as_slice()).unwrap();
                                assert!(vk.verify(&signed_data, &sig).is_ok());
                            }
                        }
                    }
                    _ => panic!("Expected AuthenticatorGetAssertion"),
                }
            }
        }
    }

    #[test]
    #[cfg(all(feature = "es384", feature = "es512", feature = "ed448"))]
    fn test_es384_es512_and_ed448_make_credential_and_get_assertion() {
        use crate::api::crypto::ed448::{ED448_SIG_SIZE, verify_with_context};
        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        for cred_param in [ES384_CRED_PARAM, ES512_CRED_PARAM, ED448_CRED_PARAM] {
            for rk in [false, true] {
                let mut make_params = create_minimal_make_credential_parameters();
                make_params.pub_key_cred_params = vec![cred_param.clone()];
                make_params.options.rk = rk;
                let make_resp = ctap_state
                    .process_make_credential(&mut env, make_params, DUMMY_CHANNEL)
                    .unwrap();
                let (cred_id, cose_key_bytes) = match make_resp {
                    ResponseData::AuthenticatorMakeCredential(r) => {
                        let offset = 37 + env.persist().aaguid().unwrap().len();
                        let cred_id_len =
                            u16::from_be_bytes([r.auth_data[offset], r.auth_data[offset + 1]])
                                as usize;
                        let cred_id = r.auth_data[offset + 2..offset + 2 + cred_id_len].to_vec();
                        let cose_key_bytes = r.auth_data[offset + 2 + cred_id_len..].to_vec();
                        (cred_id, cose_key_bytes)
                    }
                    _ => panic!("Expected AuthenticatorMakeCredential"),
                };

                let cose_val = cbor_read(&cose_key_bytes).unwrap();
                let cose_key = CoseKey::try_from(cose_val.clone()).unwrap();
                assert_eq!(cbor::Value::from(cose_key.clone()), cose_val);

                let get_params = AuthenticatorGetAssertionParameters {
                    rp_id: String::from("example.com"),
                    client_data_hash: vec![0xCD; 32],
                    allow_list: if rk {
                        None
                    } else {
                        Some(vec![PublicKeyCredentialDescriptor {
                            key_type: PublicKeyCredentialType::PublicKey,
                            key_id: cred_id.clone(),
                            transports: None,
                        }])
                    },
                    extensions: Default::default(),
                    options: GetAssertionOptions {
                        up: true,
                        uv: false,
                    },
                    pin_uv_auth_param: None,
                    pin_uv_auth_protocol: None,
                };
                let get_resp = ctap_state
                    .process_get_assertion(&mut env, get_params, DUMMY_CHANNEL)
                    .unwrap();
                match get_resp {
                    ResponseData::AuthenticatorGetAssertion(r) => {
                        let mut signed_data = r.auth_data.clone();
                        signed_data.extend_from_slice(&[0xCD; 32]);
                        let cose_map = cose_val.extract_map().unwrap();
                        let x_bytes = cose_map
                            .iter()
                            .find(|(k, _)| *k == cbor::Value::from(-2i64))
                            .unwrap()
                            .1
                            .clone()
                            .extract_byte_string()
                            .unwrap();
                        match cred_param.alg {
                            SignatureAlgorithm::Es384 => {
                                use p384::ecdsa::signature::Verifier as _;
                                let y_bytes = cose_map
                                    .iter()
                                    .find(|(k, _)| *k == cbor::Value::from(-3i64))
                                    .unwrap()
                                    .1
                                    .clone()
                                    .extract_byte_string()
                                    .unwrap();
                                let mut sec1 = vec![0x04];
                                sec1.extend_from_slice(&x_bytes);
                                sec1.extend_from_slice(&y_bytes);
                                let vk =
                                    p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
                                let sig =
                                    p384::ecdsa::Signature::from_der(&r.signature).unwrap();
                                assert!(vk.verify(&signed_data, &sig).is_ok());
                            }
                            SignatureAlgorithm::Es512 => {
                                use p521::ecdsa::signature::Verifier as _;
                                let y_bytes = cose_map
                                    .iter()
                                    .find(|(k, _)| *k == cbor::Value::from(-3i64))
                                    .unwrap()
                                    .1
                                    .clone()
                                    .extract_byte_string()
                                    .unwrap();
                                let mut sec1 = vec![0x04];
                                sec1.extend_from_slice(&x_bytes);
                                sec1.extend_from_slice(&y_bytes);
                                let vk =
                                    p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
                                let sig =
                                    p521::ecdsa::Signature::from_der(&r.signature).unwrap();
                                assert!(vk.verify(&signed_data, &sig).is_ok());
                            }
                            SignatureAlgorithm::Ed448 => {
                                assert_eq!(r.signature.len(), ED448_SIG_SIZE);
                                let pk_arr = <[u8; 57]>::try_from(x_bytes.as_slice()).unwrap();
                                let sig_arr =
                                    <[u8; ED448_SIG_SIZE]>::try_from(r.signature.as_slice())
                                        .unwrap();
                                assert!(verify_with_context(&pk_arr, &signed_data, &sig_arr, b""));
                            }
                            _ => unreachable!(),
                        }
                    }
                    _ => panic!("Expected AuthenticatorGetAssertion"),
                }
            }
        }
    }

    #[test]
    #[cfg(feature = "mldsa")]
    fn test_mldsa44_enterprise_attestation_with_large_cert() {
        use crate::api::crypto::mldsa::{MlDsaSecretKey, MlDsaVariant};
        use ml_dsa::{
            EncodedVerifyingKey, MlDsa44, Signature, VerifyingKey, signature::Verifier as _,
        };

        let mut env = TestEnv::default();
        env.customization_mut().setup_enterprise_attestation(
            Some(EnterpriseAttestationMode::VendorFacilitated),
            Some(vec!["example.com".to_string()]),
        );

        let seed = [0x37u8; 32];
        let mldsa_sk = MlDsaSecretKey::import(MlDsaVariant::MlDsa44, &seed).unwrap();
        let mldsa_pk_bytes = mldsa_sk.public_key_bytes();
        let large_cert: Vec<u8> = (0..4000).map(|i| (i % 253) as u8).collect();

        let attestation = Attestation::try_from(cbor_map! {
            0x01 => large_cert.clone(),
            0x02 => seed.to_vec(),
            0x03 => SignatureAlgorithm::MlDsa44 as i64,
        })
        .unwrap();
        env.persist()
            .set_attestation(AttestationId::Enterprise, Some(&attestation))
            .unwrap();
        env.persist().enable_enterprise_attestation().unwrap();

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
        let mut make_params = create_minimal_make_credential_parameters();
        make_params.enterprise_attestation = Some(1);
        let make_resp = ctap_state
            .process_make_credential(&mut env, make_params, DUMMY_CHANNEL)
            .unwrap();

        match make_resp {
            ResponseData::AuthenticatorMakeCredential(r) => {
                assert_eq!(r.ep_att, Some(true));
                assert_eq!(r.att_stmt.alg, SignatureAlgorithm::MlDsa44 as i64);
                assert_eq!(r.att_stmt.x5c, Some(vec![large_cert]));

                let mut signed_data = r.auth_data.clone();
                signed_data.extend_from_slice(&[0xCD]);
                let pk_enc =
                    EncodedVerifyingKey::<MlDsa44>::try_from(mldsa_pk_bytes.as_slice()).unwrap();
                let vk = VerifyingKey::<MlDsa44>::decode(&pk_enc);
                let sig = Signature::<MlDsa44>::try_from(r.att_stmt.sig.as_slice()).unwrap();
                assert!(vk.verify(&signed_data, &sig).is_ok());
            }
            _ => panic!("Expected AuthenticatorMakeCredential"),
        }
    }

    #[test]
    #[cfg(all(feature = "mldsa", feature = "pq_composite"))]
    fn test_pq_mtc_and_mtc_mds_attestation_formats() {
        use crate::api::crypto::mldsa::{MlDsaSecretKey, MlDsaVariant};
        use crate::ctap::mtc::{
            FidoMtcLogEntry, MtcAttestationFormat, MtcCertDescriptor, MtcProof,
            MtcRevokedSerialRange, MtcSubtree, MtcTrustAnchor, MtcVerificationError,
            ProvisionedMtcAttestation, compute_inclusion_proof, compute_subtree_hash,
            verify_mtc_cert_and_resolve_pubkey,
        };
        use ml_dsa::{
            EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, Signature, VerifyingKey,
            signature::Verifier as _,
        };

        let ca_id = vec![0x83, 0x99, 0x3F, 0x01, 0x01]; // PEN OID relative TrustAnchorID
        let log_number: u16 = 7;
        let not_before: u64 = 1_760_000_000;
        let not_after: u64 = 1_893_456_000;
        let current_time: u64 = 1_790_000_000;
        let fw_version = Some(42u64);

        let pq_algorithms = [
            SignatureAlgorithm::MlDsa44,
            SignatureAlgorithm::MlDsa65,
            SignatureAlgorithm::MlDsa87,
        ];

        for &att_alg in &pq_algorithms {
            for &mtc_format in &[MtcAttestationFormat::Mtc, MtcAttestationFormat::MtcMds] {
                let mut env = TestEnv::default();
                let aaguid = [0xA5u8; 16];
                env.persist().set_aaguid(&aaguid).unwrap();

                let seed = [0x42u8; 32];
                let variant = match att_alg {
                    SignatureAlgorithm::MlDsa44 => MlDsaVariant::MlDsa44,
                    SignatureAlgorithm::MlDsa65 => MlDsaVariant::MlDsa65,
                    SignatureAlgorithm::MlDsa87 => MlDsaVariant::MlDsa87,
                    _ => unreachable!(),
                };
                let mldsa_sk = MlDsaSecretKey::import(variant, &seed).unwrap();
                let cose_pk = CoseKey::from_mldsa_public_key(
                    att_alg as i64,
                    mldsa_sk.public_key_bytes(),
                );
                let mut canonical_cose_pk_bytes = Vec::new();
                cbor_write(cbor::Value::from(cose_pk), &mut canonical_cose_pk_bytes).unwrap();
                let pub_key_hash = Sha::<TestEnv>::digest(&canonical_cose_pk_bytes);

                // Build an 8-entry vendor batch issuance log where our authenticator is at index 5.
                let our_index: usize = 5;
                let our_serial: u64 = ((log_number as u64) << 48) | (our_index as u64);
                let mut leaf_hashes = Vec::new();
                for idx in 0..8usize {
                    let serial = ((log_number as u64) << 48) | (idx as u64);
                    let pk_hash = if idx == our_index {
                        pub_key_hash
                    } else {
                        [idx as u8; 32]
                    };
                    let entry = FidoMtcLogEntry {
                        ca_id: ca_id.clone(),
                        serial,
                        not_before,
                        not_after,
                        aaguid,
                        fw_version,
                        pub_key_hash: pk_hash,
                        extensions: Vec::new(),
                    };
                    leaf_hashes.push(entry.leaf_hash::<Sha<TestEnv>>());
                }

                // Compute the Landmark SubtreeHash [0, 8) and the 3-node RFC 9162 inclusion path for index 5.
                let landmark_root = compute_subtree_hash::<Sha<TestEnv>>(&leaf_hashes);
                let inclusion_path =
                    compute_inclusion_proof::<Sha<TestEnv>>(our_index, &leaf_hashes);
                assert_eq!(inclusion_path.len(), 3); // log2(8) = 3 sibling hashes (96 bytes)

                let mtc_proof = MtcProof::new_landmark(0, 8, inclusion_path);
                let mtc_proof_bytes = mtc_proof.to_tls_bytes().unwrap();
                assert_eq!(mtc_proof_bytes.len(), 2 + 6 + 6 + 2 + 96 + 3); // 115 bytes total!

                let mtc_cert_desc = MtcCertDescriptor {
                    ca_id: ca_id.clone(),
                    serial: our_serial,
                    not_before,
                    not_after,
                    firmware_version: fw_version,
                    mtc_proof: mtc_proof_bytes.clone(),
                };
                let x509_der_len = match att_alg {
                    SignatureAlgorithm::MlDsa44 => 4127,
                    SignatureAlgorithm::MlDsa65 => 5656,
                    SignatureAlgorithm::MlDsa87 => 7614,
                    _ => unreachable!(),
                };
                let mock_x509_der = vec![0x30u8; x509_der_len];
                let provisioned = ProvisionedMtcAttestation {
                    format: mtc_format,
                    cert: mtc_cert_desc.clone(),
                    x5c: Some(mock_x509_der.clone()),
                    classical_key: None,
                    classical_x5c: None,
                    key_ref: false,
                };
                let provisioned_bytes = provisioned.to_bytes().unwrap();

                let attestation = Attestation::try_from(cbor_map! {
                    0x01 => provisioned_bytes,
                    0x02 => seed.to_vec(),
                    0x03 => att_alg as i64,
                })
                .unwrap();
                env.persist()
                    .set_attestation(AttestationId::Batch, Some(&attestation))
                    .unwrap();

                // Execute MakeCredential with a matching post-quantum credential algorithm.
                let mut ctap_state = CtapState::<TestEnv>::new(&mut env);
                let get_info_resp = ctap_state.process_get_info(&mut env).unwrap();
                match get_info_resp {
                    ResponseData::AuthenticatorGetInfo(info) => {
                        let formats = info.attestation_formats.unwrap();
                        assert_eq!(
                            formats,
                            vec![String::from("mtc"), String::from("packed")]
                        );
                        assert!(
                            info.extensions
                                .unwrap()
                                .contains(&String::from("mtc-debug"))
                        );
                    }
                    _ => panic!("Expected AuthenticatorGetInfo"),
                }

                let make_params = AuthenticatorMakeCredentialParameters {
                    client_data_hash: vec![0xCD; 32],
                    rp: PublicKeyCredentialRpEntity {
                        rp_id: String::from("example.com"),
                        rp_name: None,
                        rp_icon: None,
                    },
                    user: PublicKeyCredentialUserEntity {
                        user_id: vec![0x11; 16],
                        user_name: Some(String::from("alice")),
                        user_display_name: None,
                        user_icon: None,
                    },
                    pub_key_cred_params: vec![PublicKeyCredentialParameter {
                        cred_type: PublicKeyCredentialType::PublicKey,
                        alg: att_alg,
                    }],
                    exclude_list: None,
                    extensions: MakeCredentialExtensions::default(),
                    options: MakeCredentialOptions {
                        rk: true,
                        uv: false,
                    },
                    pin_uv_auth_param: None,
                    pin_uv_auth_protocol: None,
                    enterprise_attestation: None,
                    attestation_formats_preference: Some(vec![String::from(mtc_format.as_str())]),
                };

                let make_resp = ctap_state
                    .process_make_credential(&mut env, make_params.clone(), DUMMY_CHANNEL)
                    .unwrap();

                // Verify un-hinted cascade (attestation_formats_preference: None):
                // Tier 1 ("packed" with batch x5c when <= 7,550 B) -> Tier 2 ("mtc" omitting pubKey on wire).
                // - When cred alg == batch alg: MlDsa44 (-48), MlDsa65 (-49), and MlDsa87 (-50) all exceed
                //   7,550 B for "packed", so they all emit "mtc" (with pubKey omitted on the wire).
                // - When batch alg is MlDsa44 (-48) and cred alg is classical (ES256), "packed" with
                //   the 4,127-byte batch X.509 certificate fits in 7,609 B (~6,730 B <= 7,550 B),
                //   so it returns "packed" with `x5c`!
                let mut default_params = make_params.clone();
                default_params.user.user_id = vec![0x12; 16];
                default_params.attestation_formats_preference = None;
                let default_resp = ctap_state
                    .process_make_credential(&mut env, default_params, DUMMY_CHANNEL)
                    .unwrap();
                match default_resp {
                    ResponseData::AuthenticatorMakeCredential(dr) => {
                        assert_eq!(dr.fmt, "mtc");
                        assert!(dr.att_stmt.pub_key.is_none());
                    }
                    _ => panic!("Expected AuthenticatorMakeCredential"),
                }

                if matches!(att_alg, SignatureAlgorithm::MlDsa44) {
                    let mut es256_params = make_params.clone();
                    es256_params.user.user_id = vec![0x44; 16];
                    es256_params.pub_key_cred_params = vec![PublicKeyCredentialParameter {
                        cred_type: PublicKeyCredentialType::PublicKey,
                        alg: SignatureAlgorithm::Es256,
                    }];
                    es256_params.attestation_formats_preference = None;
                    let es256_resp = ctap_state
                        .process_make_credential(&mut env, es256_params, DUMMY_CHANNEL)
                        .unwrap();
                    match es256_resp {
                        ResponseData::AuthenticatorMakeCredential(er) => {
                            assert_eq!(er.fmt, "packed");
                            assert_eq!(er.att_stmt.alg, SignatureAlgorithm::MlDsa44 as i64);
                            assert_eq!(
                                er.att_stmt.x5c.as_ref(),
                                Some(&vec![mock_x509_der.clone()])
                            );
                            assert!(er.att_stmt.pub_key.is_none());
                            assert!(er.att_stmt.mtc_cert.is_none());
                        }
                        _ => panic!("Expected AuthenticatorMakeCredential"),
                    }
                }

                if matches!(att_alg, SignatureAlgorithm::MlDsa65)
                    && mtc_format == MtcAttestationFormat::Mtc
                {
                    for smaller_cred_alg in [SignatureAlgorithm::Es256, SignatureAlgorithm::MlDsa44]
                    {
                        let mut small_cred_params = make_params.clone();
                        small_cred_params.user.user_id = vec![smaller_cred_alg as i64 as u8; 16];
                        small_cred_params.pub_key_cred_params = vec![PublicKeyCredentialParameter {
                            cred_type: PublicKeyCredentialType::PublicKey,
                            alg: smaller_cred_alg,
                        }];
                        small_cred_params.attestation_formats_preference = None;
                        let small_resp = ctap_state
                            .process_make_credential(&mut env, small_cred_params, DUMMY_CHANNEL)
                            .unwrap();
                        match small_resp {
                            ResponseData::AuthenticatorMakeCredential(sr) => {
                                assert_eq!(sr.fmt, "mtc");
                                assert!(sr.att_stmt.pub_key.is_none());
                            }
                            _ => panic!("Expected AuthenticatorMakeCredential"),
                        }
                    }
                }

                // Verify "packed" attestation format preference in 0x0B ALWAYS returns fmt: "packed"
                // with the batch X.509 certificate (`x5c`) and batch key signature!
                let mut packed_params = make_params.clone();
                packed_params.user.user_id = vec![0x14; 16];
                packed_params.attestation_formats_preference = Some(vec![String::from("packed")]);
                let packed_resp = ctap_state
                    .process_make_credential(&mut env, packed_params, DUMMY_CHANNEL)
                    .unwrap();
                match packed_resp {
                    ResponseData::AuthenticatorMakeCredential(pr) => {
                        assert_eq!(pr.fmt, "packed");
                        assert_eq!(pr.att_stmt.alg, att_alg as i64);
                        assert_eq!(
                            pr.att_stmt.x5c.as_ref(),
                            Some(&vec![mock_x509_der.clone()])
                        );
                        assert!(pr.att_stmt.pub_key.is_none());
                        assert!(pr.att_stmt.mtc_cert.is_none());
                    }
                    _ => panic!("Expected AuthenticatorMakeCredential"),
                }

                // Verify "none" attestation format preference returns fmt: "none" with empty attStmt.
                let mut none_params = make_params.clone();
                none_params.user.user_id = vec![0x13; 16];
                none_params.attestation_formats_preference = Some(vec![String::from("none")]);
                let none_resp = ctap_state
                    .process_make_credential(&mut env, none_params, DUMMY_CHANNEL)
                    .unwrap();
                match none_resp {
                    ResponseData::AuthenticatorMakeCredential(nr) => {
                        assert_eq!(nr.fmt, "none");
                        assert!(nr.att_stmt.sig.is_empty());
                        assert!(nr.att_stmt.pub_key.is_none());
                        assert!(nr.att_stmt.mtc_cert.is_none());
                    }
                    _ => panic!("Expected AuthenticatorMakeCredential"),
                }

                // Verify that requesting `"mtc-debug": true` on non-Enterprise MakeCredential
                // populates `authData.extensions["mtc-debug"]` with the 6 non-enterprise fields
                // (`pubKey`, `mtcProof`, `notAfter`, `rootHash`, `notBefore`, `firmwareVersion`) and
                // strictly OMITS `"deviceSerial"` (Privacy Gate).
                let mut debug_params = make_params.clone();
                debug_params.user.user_id = vec![0x22; 16];
                debug_params.extensions.mtc_debug = true;
                let debug_resp = ctap_state
                    .process_make_credential(&mut env, debug_params, DUMMY_CHANNEL)
                    .unwrap();
                match debug_resp {
                    ResponseData::AuthenticatorMakeCredential(dr) => {
                        assert_eq!(dr.fmt, "mtc");
                        assert!(dr.att_stmt.pub_key.is_none());
                        assert_eq!(dr.att_stmt.mtc_cert.as_ref(), Some(&mtc_cert_desc));
                        assert_ne!(dr.auth_data[32] & ED_FLAG, 0);
                        let mut expected_debug_ext = Vec::new();
                        cbor_write(
                            cbor_map_options! {
                                "mtc-debug" => cbor_map_options! {
                                    "pubKey" => canonical_cose_pk_bytes.clone(),
                                    "mtcProof" => mtc_proof_bytes.clone(),
                                    "notAfter" => not_after,
                                    "rootHash" => landmark_root.to_vec(),
                                    "notBefore" => not_before,
                                    "firmwareVersion" => fw_version,
                                },
                            },
                            &mut expected_debug_ext,
                        )
                        .unwrap();
                        assert!(
                            dr.auth_data.ends_with(&expected_debug_ext),
                            "Non-enterprise mtc-debug extension output must include 6 fields and omit deviceSerial"
                        );
                    }
                    _ => panic!("Expected AuthenticatorMakeCredential"),
                }

                // Check full CBOR wire size of the MakeCredential response.
                let mut wire_cbor = Vec::new();
                let cbor_val: Option<cbor::Value> = match &make_resp {
                    ResponseData::AuthenticatorMakeCredential(r) => Some(
                        AuthenticatorMakeCredentialResponse {
                            fmt: r.fmt.clone(),
                            auth_data: r.auth_data.clone(),
                            att_stmt: PackedAttestationStatement {
                                alg: r.att_stmt.alg,
                                sig: r.att_stmt.sig.clone(),
                                x5c: r.att_stmt.x5c.clone(),
                                ecdaa_key_id: r.att_stmt.ecdaa_key_id.clone(),
                                pub_key: r.att_stmt.pub_key.clone(),
                                mtc_cert: r.att_stmt.mtc_cert.clone(),
                            },
                            ep_att: r.ep_att,
                            large_blob_key: r.large_blob_key.clone(),
                        }
                        .into(),
                    ),
                    _ => unreachable!(),
                };
                cbor_write(cbor_val.unwrap(), &mut wire_cbor).unwrap();

                match make_resp {
                    ResponseData::AuthenticatorMakeCredential(r) => {
                        assert_eq!(r.fmt, "mtc");
                        assert_eq!(r.att_stmt.alg, att_alg as i64);
                        assert!(r.att_stmt.x5c.is_none());
                        assert!(r.att_stmt.pub_key.is_none());
                        assert_eq!(r.att_stmt.mtc_cert.as_ref(), Some(&mtc_cert_desc));
                        // With "mtc" omitting pubKey on the wire, ALL three (ML-DSA-44, ML-DSA-65, and ML-DSA-87!)
                        // fit inside a single 7,609-byte USB HID message!
                        assert!(
                            wire_cbor.len() < 7609,
                            "mtc wire size {} exceeded 7609 bytes for {:?}",
                            wire_cbor.len(),
                            att_alg
                        );
                        #[cfg(feature = "pq_composite")]
                        if matches!(att_alg, SignatureAlgorithm::MlDsa87) {
                            for nr_alg in [
                                SignatureAlgorithm::MlDsa87,
                                SignatureAlgorithm::MlDsa87Ed448,
                                SignatureAlgorithm::MlDsa87Es384,
                            ] {
                                let nr_params = AuthenticatorMakeCredentialParameters {
                                    client_data_hash: vec![0xCD; 32],
                                    rp: PublicKeyCredentialRpEntity {
                                        rp_id: String::from("example.com"),
                                        rp_name: None,
                                        rp_icon: None,
                                    },
                                    user: PublicKeyCredentialUserEntity {
                                        user_id: vec![0x99; 16],
                                        user_name: Some(String::from("bob")),
                                        user_display_name: None,
                                        user_icon: None,
                                    },
                                    pub_key_cred_params: vec![
                                        PublicKeyCredentialParameter {
                                            cred_type: PublicKeyCredentialType::PublicKey,
                                            alg: nr_alg,
                                        },
                                    ],
                                    exclude_list: None,
                                    extensions: MakeCredentialExtensions::default(),
                                    options: MakeCredentialOptions {
                                        rk: false,
                                        uv: false,
                                    },
                                    pin_uv_auth_param: None,
                                    pin_uv_auth_protocol: None,
                                    enterprise_attestation: None,
                                    attestation_formats_preference: None,
                                };
                                let nr_resp = ctap_state
                                    .process_make_credential(
                                        &mut env,
                                        nr_params,
                                        DUMMY_CHANNEL,
                                    )
                                    .unwrap();
                                let (nr_cbor_val, cred_id) = match nr_resp {
                                    ResponseData::AuthenticatorMakeCredential(nr_r) => {
                                        assert_eq!(nr_r.fmt, "mtc");
                                        let cred_len = ((nr_r.auth_data[53] as usize) << 8)
                                            | (nr_r.auth_data[54] as usize);
                                        let cid =
                                            nr_r.auth_data[55..55 + cred_len].to_vec();
                                        (cbor::Value::from(nr_r), cid)
                                    }
                                    _ => unreachable!(),
                                };
                                let mut nr_wire = Vec::new();
                                cbor_write(nr_cbor_val, &mut nr_wire).unwrap();
                                let fw_ver_overhead = if fw_version.is_some() { 21 } else { 0 };
                                assert!(
                                    nr_wire.len() + 1 - fw_ver_overhead <= 7609,
                                    "non-resident {:?} + ML-DSA-87 batch sig total USB HID frame size {} > 7609",
                                    nr_alg,
                                    nr_wire.len() + 1 - fw_ver_overhead
                                );
                                let ga_params = AuthenticatorGetAssertionParameters {
                                    rp_id: String::from("example.com"),
                                    client_data_hash: vec![0xEE; 32],
                                    allow_list: Some(vec![PublicKeyCredentialDescriptor {
                                        key_type: PublicKeyCredentialType::PublicKey,
                                        key_id: cred_id,
                                        transports: None,
                                    }]),
                                    extensions: GetAssertionExtensions::default(),
                                    options: GetAssertionOptions {
                                        up: true,
                                        uv: false,
                                    },
                                    pin_uv_auth_param: None,
                                    pin_uv_auth_protocol: None,
                                };
                                let ga_resp = ctap_state
                                    .process_get_assertion(
                                        &mut env,
                                        ga_params,
                                        DUMMY_CHANNEL,
                                    )
                                    .unwrap();
                                match ga_resp {
                                    ResponseData::AuthenticatorGetAssertion(ga_r) => {
                                        assert!(!ga_r.signature.is_empty());
                                    }
                                    _ => panic!("Expected AuthenticatorGetAssertion"),
                                }
                            }
                        }

                        // Construct the Relying Party's FIDO MDS MtcTrustAnchor.
                        let trust_anchor = MtcTrustAnchor {
                            ca_id: ca_id.clone(),
                            log_number,
                            trusted_subtrees: vec![MtcSubtree {
                                start: 0,
                                end: 8,
                                subtree_hash: landmark_root,
                            }],
                            revoked_serial_ranges: vec![MtcRevokedSerialRange {
                                min_serial: ((log_number as u64) << 48) | 2,
                                max_serial: ((log_number as u64) << 48) | 3,
                            }],
                            batch_keys: vec![(our_serial, canonical_cose_pk_bytes.clone())],
                        };

                        // RP Step 1: Verify MTC certificate & resolve attestation public key.
                        let resolved_pk_bytes = verify_mtc_cert_and_resolve_pubkey::<Sha<TestEnv>>(
                            &r.fmt,
                            r.att_stmt.pub_key.as_deref(),
                            r.att_stmt.mtc_cert.as_ref().unwrap(),
                            &r.auth_data,
                            &trust_anchor,
                            current_time,
                        )
                        .unwrap();
                        assert_eq!(resolved_pk_bytes, canonical_cose_pk_bytes);

                        // RP Step 2: Decode COSE_Key and verify attestation signature over (authData || clientDataHash).
                        let mut signed_data = r.auth_data.clone();
                        signed_data.extend_from_slice(&[0xCD; 32]);
                        let pk_raw = mldsa_sk.public_key_bytes();
                        match att_alg {
                            SignatureAlgorithm::MlDsa44 => {
                                let pk_enc =
                                    EncodedVerifyingKey::<MlDsa44>::try_from(pk_raw.as_slice())
                                        .unwrap();
                                let vk = VerifyingKey::<MlDsa44>::decode(&pk_enc);
                                let sig =
                                    Signature::<MlDsa44>::try_from(r.att_stmt.sig.as_slice())
                                        .unwrap();
                                assert!(vk.verify(&signed_data, &sig).is_ok());
                            }
                            SignatureAlgorithm::MlDsa65 => {
                                let pk_enc =
                                    EncodedVerifyingKey::<MlDsa65>::try_from(pk_raw.as_slice())
                                        .unwrap();
                                let vk = VerifyingKey::<MlDsa65>::decode(&pk_enc);
                                let sig =
                                    Signature::<MlDsa65>::try_from(r.att_stmt.sig.as_slice())
                                        .unwrap();
                                assert!(vk.verify(&signed_data, &sig).is_ok());
                            }
                            SignatureAlgorithm::MlDsa87 => {
                                let pk_enc =
                                    EncodedVerifyingKey::<MlDsa87>::try_from(pk_raw.as_slice())
                                        .unwrap();
                                let vk = VerifyingKey::<MlDsa87>::decode(&pk_enc);
                                let sig =
                                    Signature::<MlDsa87>::try_from(r.att_stmt.sig.as_slice())
                                        .unwrap();
                                assert!(vk.verify(&signed_data, &sig).is_ok());
                            }
                            _ => unreachable!(),
                        }

                        // Negative Test 1: Revoked serial range rejects the attestation.
                        let mut revoked_anchor = trust_anchor.clone();
                        revoked_anchor
                            .revoked_serial_ranges
                            .push(MtcRevokedSerialRange {
                                min_serial: our_serial,
                                max_serial: our_serial,
                            });
                        assert_eq!(
                            verify_mtc_cert_and_resolve_pubkey::<Sha<TestEnv>>(
                                &r.fmt,
                                r.att_stmt.pub_key.as_deref(),
                                r.att_stmt.mtc_cert.as_ref().unwrap(),
                                &r.auth_data,
                                &revoked_anchor,
                                current_time,
                            ),
                            Err(MtcVerificationError::CertificateRevoked)
                        );

                        // Negative Test 2: Tampered AAGUID in authData causes Merkle root mismatch.
                        let mut bad_auth_data = r.auth_data.clone();
                        bad_auth_data[37] ^= 0xFF;
                        assert_eq!(
                            verify_mtc_cert_and_resolve_pubkey::<Sha<TestEnv>>(
                                &r.fmt,
                                r.att_stmt.pub_key.as_deref(),
                                r.att_stmt.mtc_cert.as_ref().unwrap(),
                                &bad_auth_data,
                                &trust_anchor,
                                current_time,
                            ),
                            Err(MtcVerificationError::SubtreeNotTrusted)
                        );

                        // Negative Test 3: Missing batch key in MDS for "mtc" fails with BatchPublicKeyNotFoundInMds.
                        let mut empty_mds_anchor = trust_anchor.clone();
                        empty_mds_anchor.batch_keys.clear();
                        assert_eq!(
                            verify_mtc_cert_and_resolve_pubkey::<Sha<TestEnv>>(
                                &r.fmt,
                                r.att_stmt.pub_key.as_deref(),
                                r.att_stmt.mtc_cert.as_ref().unwrap(),
                                &r.auth_data,
                                &empty_mds_anchor,
                                current_time,
                            ),
                            Err(MtcVerificationError::BatchPublicKeyNotFoundInMds)
                        );
                    }
                    _ => panic!("Expected AuthenticatorMakeCredential"),
                }

                // Verify authenticatorGetInfo (0x04) advertises ["mtc", "packed"].
                match ctap_state.process_get_info(&mut env).unwrap() {
                    ResponseData::AuthenticatorGetInfo(info_resp) => {
                        let expected_formats = vec![
                            String::from("mtc"),
                            String::from("packed"),
                        ];
                        assert_eq!(info_resp.attestation_formats, Some(expected_formats));
                    }
                    _ => panic!("Expected AuthenticatorGetInfo"),
                }

                // Verify requesting "none" via attestationFormatsPreference (0x0B) produces fmt="none" and attStmt={}.
                let none_params = AuthenticatorMakeCredentialParameters {
                    client_data_hash: vec![0xCD; 32],
                    rp: PublicKeyCredentialRpEntity {
                        rp_id: String::from("example.com"),
                        rp_name: None,
                        rp_icon: None,
                    },
                    user: PublicKeyCredentialUserEntity {
                        user_id: vec![0x22; 16],
                        user_name: Some(String::from("bob")),
                        user_display_name: None,
                        user_icon: None,
                    },
                    pub_key_cred_params: vec![PublicKeyCredentialParameter {
                        cred_type: PublicKeyCredentialType::PublicKey,
                        alg: att_alg,
                    }],
                    exclude_list: None,
                    extensions: MakeCredentialExtensions::default(),
                    options: MakeCredentialOptions {
                        rk: false,
                        uv: false,
                    },
                    pin_uv_auth_param: None,
                    pin_uv_auth_protocol: None,
                    enterprise_attestation: None,
                    attestation_formats_preference: Some(vec![String::from("none")]),
                };
                match ctap_state
                    .process_make_credential(&mut env, none_params, DUMMY_CHANNEL)
                    .unwrap()
                {
                    ResponseData::AuthenticatorMakeCredential(r_none) => {
                        assert_eq!(r_none.fmt, "none");
                        assert!(r_none.att_stmt.sig.is_empty());
                        assert_eq!(cbor::Value::from(r_none.att_stmt), cbor_map_options! {});
                    }
                    _ => panic!("Expected AuthenticatorMakeCredential"),
                }
            }
        }
    }

    #[test]
    fn test_dual_key_enterprise_mtc_and_x5c_attestation() {
        use crate::ctap::mtc::{
            MTC_NON_EXPIRING_NOT_AFTER, MtcAttestationFormat, MtcCertDescriptor, MtcProof,
            MtcSubtree, MtcTrustAnchor, ProvisionedMtcAttestation, compute_mtc_root_hash,
            verify_mtc_cert_and_resolve_pubkey,
        };

        let mut env = TestEnv::default();
        let aaguid = [0xAA; 16];
        env.persist().set_aaguid(&aaguid).unwrap();

        // 1. Provision Key 1: Non-Enterprise 100k-Device Batch Key (AttestationId::Batch)
        //    configured with `key_ref: true` (proof-less `mtcKeyRef = { caId, serial }` on the wire)
        //    and non-expiring `not_after = MTC_NON_EXPIRING_NOT_AFTER` (253402300799).
        let batch_att_key = PrivateKey::<TestEnv>::new(&mut env, SignatureAlgorithm::MlDsa44);
        let mut batch_sk_bytes = Vec::new();
        cbor_write(batch_att_key.to_cbor(), &mut batch_sk_bytes).unwrap();
        let mut batch_pk_bytes = Vec::new();
        cbor_write(
            cbor::Value::from(batch_att_key.get_pub_key().unwrap()),
            &mut batch_pk_bytes,
        )
        .unwrap();
        let batch_proof_tls = MtcProof::new_landmark(0, 1, Vec::new())
            .to_tls_bytes()
            .unwrap();
        let batch_serial = 7u64 << 48;
        let batch_mtc = ProvisionedMtcAttestation {
            format: MtcAttestationFormat::Mtc,
            x5c: None,
            classical_key: None,
            classical_x5c: None,
            key_ref: true,
            cert: MtcCertDescriptor {
                ca_id: vec![0x83, 0x99, 0x3f, 0x01, 0x01],
                serial: batch_serial,
                mtc_proof: batch_proof_tls.clone(),
                not_before: 1_700_000_000,
                not_after: MTC_NON_EXPIRING_NOT_AFTER,
                firmware_version: Some(0),
            },
        };
        assert!(batch_mtc.cert.is_non_expiring());
        let expected_batch_root_hash =
            compute_mtc_root_hash::<Sha<TestEnv>>(&batch_mtc.cert, &batch_pk_bytes, &aaguid)
                .unwrap();
        env.persist()
            .set_attestation(
                AttestationId::Batch,
                Some(&Attestation {
                    wrapped_private_key: batch_sk_bytes,
                    certificate: batch_mtc.to_bytes().unwrap(),
                }),
            )
            .unwrap();

        // 2. Provision Key 2: Enterprise Single-Device Key (AttestationId::Enterprise)
        //    with BOTH Enterprise mtcCert (`key_ref: true` -> proof-less `mtcKeyRef` on wire, full MtcProof in flash)
        //    AND Per-Enterprise-Batch-Key X.509 DER certificate (x5c).
        let ent_att_key = PrivateKey::<TestEnv>::new(&mut env, SignatureAlgorithm::MlDsa44);
        let mut ent_sk_bytes = Vec::new();
        cbor_write(ent_att_key.to_cbor(), &mut ent_sk_bytes).unwrap();
        let mut ent_pk_bytes = Vec::new();
        cbor_write(
            cbor::Value::from(ent_att_key.get_pub_key().unwrap()),
            &mut ent_pk_bytes,
        )
        .unwrap();
        let ent_x509_der = vec![0x30, 0x82, 0x01, 0x00, 0xEE, 0xFF];
        let ent_serial = (7u64 << 48) | 42948;
        let ent_proof_tls = MtcProof {
            extensions: b"123456".to_vec(),
            start: 0,
            end: 131_072,
            inclusion_proof: vec![[0x22; 32]; 17],
            signatures: Vec::new(),
        }
        .to_tls_bytes()
        .unwrap();
        let ent_mtc = ProvisionedMtcAttestation {
            format: MtcAttestationFormat::Mtc,
            x5c: Some(ent_x509_der.clone()),
            classical_key: None,
            classical_x5c: None,
            key_ref: true,
            cert: MtcCertDescriptor {
                ca_id: vec![0x83, 0x99, 0x3f, 0x01, 0x02],
                serial: ent_serial,
                mtc_proof: ent_proof_tls.clone(),
                not_before: 1_700_000_000,
                not_after: MTC_NON_EXPIRING_NOT_AFTER,
                firmware_version: Some(0),
            },
        };
        let expected_ent_root_hash =
            compute_mtc_root_hash::<Sha<TestEnv>>(&ent_mtc.cert, &ent_pk_bytes, &aaguid).unwrap();
        env.persist()
            .set_attestation(
                AttestationId::Enterprise,
                Some(&Attestation {
                    wrapped_private_key: ent_sk_bytes,
                    certificate: ent_mtc.to_bytes().unwrap(),
                }),
            )
            .unwrap();
        storage::enable_enterprise_attestation(&mut env).unwrap();

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // Verify both Batch and Enterprise keys coexist and "ep": true is advertised in GetInfo.
        match ctap_state.process_get_info(&mut env).unwrap() {
            ResponseData::AuthenticatorGetInfo(info) => {
                assert!(
                    info.options
                        .unwrap()
                        .contains(&(String::from("ep"), true))
                );
            }
            _ => panic!("Expected AuthenticatorGetInfo"),
        }

        // Case A: Non-Enterprise MakeCredential (0x0A omitted) -> uses AttestationId::Batch ("mtc")
        //         and emits compact 2-field `mtcKeyRef` (`{ caId, serial }`) on the wire!
        let non_ent_params = create_minimal_make_credential_parameters();
        match ctap_state
            .process_make_credential(&mut env, non_ent_params, DUMMY_CHANNEL)
            .unwrap()
        {
            ResponseData::AuthenticatorMakeCredential(r) => {
                assert_eq!(r.fmt, "mtc");
                assert_eq!(r.ep_att, None);
                assert!(r.att_stmt.x5c.is_none());
                assert!(r.att_stmt.pub_key.is_none());
                let wire_cert = r.att_stmt.mtc_cert.unwrap();
                assert!(wire_cert.is_key_ref());
                assert_eq!(wire_cert.serial, batch_serial);
                assert_eq!(
                    cbor::Value::from(wire_cert),
                    cbor_map_options! {
                        "caId" => vec![0x83u8, 0x99, 0x3f, 0x01, 0x01],
                        "serial" => batch_serial,
                    }
                );
                assert_eq!(r.auth_data[32] & ED_FLAG, 0);
            }
            _ => panic!("Expected AuthenticatorMakeCredential"),
        }

        // Case B: Enterprise MakeCredential (0x0A = 1) with 0x0B omitted (None) or empty (Some(vec![]))
        //         when certificate fits in 7,609 B -> uses Tier 1 logic to return fmt="packed" with x5c!
        //         Unsolicited extension data is NOT emitted when mtc-debug is not requested.
        for pref in [None, Some(Vec::new())] {
            let mut ent_default_params = create_minimal_make_credential_parameters();
            ent_default_params.enterprise_attestation = Some(1);
            ent_default_params.attestation_formats_preference = pref;
            match ctap_state
                .process_make_credential(&mut env, ent_default_params, DUMMY_CHANNEL)
                .unwrap()
            {
                ResponseData::AuthenticatorMakeCredential(r) => {
                    assert_eq!(r.fmt, "packed");
                    assert_eq!(r.ep_att, Some(true));
                    assert_eq!(r.att_stmt.x5c, Some(vec![ent_x509_der.clone()]));
                    assert!(r.att_stmt.pub_key.is_none());
                    assert!(r.att_stmt.mtc_cert.is_none());
                    assert_eq!(r.auth_data[32] & ED_FLAG, 0);
                }
                _ => panic!("Expected AuthenticatorMakeCredential"),
            }
        }

        // Case C: Enterprise MakeCredential (0x0A = 1) with "mtc" first in 0x0B and "mtc-debug": true ->
        //         returns fmt="mtc" (with attStmt.pubKey omitted), compact 2-field `mtcKeyRef` (`{ caId, serial }`),
        //         and signed 7-field "mtc-debug" extension (including `deviceSerial: "123456"` and `rootHash`).
        let mut ent_mtc_params = create_minimal_make_credential_parameters();
        ent_mtc_params.enterprise_attestation = Some(1);
        ent_mtc_params.extensions.mtc_debug = true;
        ent_mtc_params.attestation_formats_preference =
            Some(vec![String::from("mtc"), String::from("packed")]);
        match ctap_state
            .process_make_credential(&mut env, ent_mtc_params, DUMMY_CHANNEL)
            .unwrap()
        {
            ResponseData::AuthenticatorMakeCredential(r) => {
                assert_eq!(r.fmt, "mtc");
                assert_eq!(r.ep_att, Some(true));
                assert!(r.att_stmt.x5c.is_none());
                assert!(r.att_stmt.pub_key.is_none());
                let cert = r.att_stmt.mtc_cert.clone().unwrap();
                assert!(cert.is_key_ref());
                assert_eq!(cert.serial, ent_serial);
                assert_eq!(
                    cbor::Value::from(cert.clone()),
                    cbor_map_options! {
                        "caId" => vec![0x83u8, 0x99, 0x3f, 0x01, 0x02],
                        "serial" => ent_serial,
                    }
                );
                // ED_FLAG (0x80) must be set on authData flags because "mtc-debug" was requested!
                assert_ne!(r.auth_data[32] & ED_FLAG, 0);
                let mut expected_ext_bytes = Vec::new();
                cbor_write(
                    cbor_map_options! {
                        "mtc-debug" => cbor_map_options! {
                            "pubKey" => ent_pk_bytes.clone(),
                            "mtcProof" => ent_proof_tls.clone(),
                            "notAfter" => MTC_NON_EXPIRING_NOT_AFTER,
                            "rootHash" => expected_ent_root_hash.to_vec(),
                            "notBefore" => 1_700_000_000u64,
                            "deviceSerial" => "123456",
                            "firmwareVersion" => 0u64,
                        },
                    },
                    &mut expected_ext_bytes,
                )
                .unwrap();
                assert!(
                    r.auth_data.ends_with(&expected_ext_bytes),
                    "authData extensions did not match expected 7-field mtc-debug map"
                );

                // Verify offline Enterprise MTC verification using "mtc-debug" when `batch_keys` is empty!
                let ent_trust_anchor = MtcTrustAnchor {
                    ca_id: vec![0x83, 0x99, 0x3f, 0x01, 0x02],
                    log_number: (ent_serial >> 48) as u16,
                    trusted_subtrees: vec![MtcSubtree {
                        start: 0,
                        end: 131_072,
                        subtree_hash: expected_ent_root_hash,
                    }],
                    revoked_serial_ranges: Vec::new(),
                    batch_keys: Vec::new(),
                };
                let resolved_ent_pk = verify_mtc_cert_and_resolve_pubkey::<Sha<TestEnv>>(
                    &r.fmt,
                    r.att_stmt.pub_key.as_deref(),
                    &cert,
                    &r.auth_data,
                    &ent_trust_anchor,
                    1_750_000_000,
                )
                .unwrap();
                assert_eq!(resolved_ent_pk, ent_pk_bytes);
            }
            _ => panic!("Expected AuthenticatorMakeCredential"),
        }

        // Case D: Enterprise MakeCredential (0x0A = 1) with "packed" FIRST in 0x0B -> returns fmt="packed"
        //         with the per-enterprise-batch-key X.509 certificate (x5c)!
        let mut ent_packed_params = create_minimal_make_credential_parameters();
        ent_packed_params.enterprise_attestation = Some(1);
        ent_packed_params.attestation_formats_preference =
            Some(vec![String::from("packed"), String::from("mtc")]);
        match ctap_state
            .process_make_credential(&mut env, ent_packed_params, DUMMY_CHANNEL)
            .unwrap()
        {
            ResponseData::AuthenticatorMakeCredential(r) => {
                assert_eq!(r.fmt, "packed");
                assert_eq!(r.ep_att, Some(true));
                assert_eq!(r.att_stmt.x5c, Some(vec![ent_x509_der]));
                assert!(r.att_stmt.pub_key.is_none());
                assert!(r.att_stmt.mtc_cert.is_none());
                assert_eq!(r.auth_data[32] & ED_FLAG, 0);
            }
            _ => panic!("Expected AuthenticatorMakeCredential"),
        }

        // Case E: Enterprise MakeCredential (0x0A = 1) with 0x0B omitted/empty when x5c is too large
        //         for the 7,609 B response budget -> automatically cascades from Tier 1 ("packed") to
        //         Tier 2 ("mtc") with mtcCert (and pubKey omitted on wire)!
        let large_ent_mtc = ProvisionedMtcAttestation {
            format: MtcAttestationFormat::Mtc,
            x5c: Some(vec![0x30; 5500]),
            classical_key: None,
            classical_x5c: None,
            key_ref: false,
            cert: MtcCertDescriptor {
                ca_id: vec![0x83, 0x99, 0x3f, 0x01, 0x02],
                serial: ent_serial,
                mtc_proof: vec![0x22; 17 * 32],
                not_before: 1_700_000_000,
                not_after: 1_800_000_000,
                firmware_version: None,
            },
        };
        let mut ent_sk_bytes_2 = Vec::new();
        cbor_write(ent_att_key.to_cbor(), &mut ent_sk_bytes_2).unwrap();
        env.persist()
            .set_attestation(AttestationId::Enterprise, None)
            .unwrap();
        env.persist()
            .set_attestation(
                AttestationId::Enterprise,
                Some(&Attestation {
                    wrapped_private_key: ent_sk_bytes_2,
                    certificate: large_ent_mtc.to_bytes().unwrap(),
                }),
            )
            .unwrap();
        for pref in [None, Some(Vec::new())] {
            let mut ent_cascade_params = create_minimal_make_credential_parameters();
            ent_cascade_params.enterprise_attestation = Some(1);
            ent_cascade_params.attestation_formats_preference = pref;
            match ctap_state
                .process_make_credential(&mut env, ent_cascade_params, DUMMY_CHANNEL)
                .unwrap()
            {
                ResponseData::AuthenticatorMakeCredential(r) => {
                    assert_eq!(r.fmt, "mtc");
                    assert_eq!(r.ep_att, Some(true));
                    assert!(r.att_stmt.x5c.is_none());
                    assert!(r.att_stmt.pub_key.is_none());
                    assert_eq!(r.att_stmt.mtc_cert.unwrap().serial, ent_serial);
                }
                _ => panic!("Expected AuthenticatorMakeCredential"),
            }
        }

        // Case F: VendorFacilitated (0x0A = 1) with non-allowlisted RP ID falls back to non-Enterprise
        // batch attestation (ep_att = None), while PlatformManaged (0x0A = 2) succeeds for any RP ID.
        // Also verify that if mtc-debug is requested when ep_att = None, `deviceSerial` is OMITTED while
        // the remaining 6 fields (`pubKey`, `mtcProof`, `notAfter`, `rootHash`, `notBefore`, `firmwareVersion`)
        // are still populated in `"mtc-debug"` even though `attStmt.mtcCert` on the wire is a 2-field `mtcKeyRef`!
        let mut wrong_rp_params = create_minimal_make_credential_parameters();
        wrong_rp_params.rp.rp_id = String::from("wrong-rp.example.org");
        wrong_rp_params.enterprise_attestation = Some(1);
        wrong_rp_params.extensions.mtc_debug = true;
        match ctap_state
            .process_make_credential(&mut env, wrong_rp_params, DUMMY_CHANNEL)
            .unwrap()
        {
            ResponseData::AuthenticatorMakeCredential(r) => {
                assert_eq!(r.fmt, "mtc");
                assert_eq!(r.ep_att, None);
                assert!(r.att_stmt.mtc_cert.as_ref().unwrap().is_key_ref());
                let mut expected_non_ent_debug = Vec::new();
                cbor_write(
                    cbor_map_options! {
                        "mtc-debug" => cbor_map_options! {
                            "pubKey" => batch_pk_bytes.clone(),
                            "mtcProof" => batch_proof_tls,
                            "notAfter" => MTC_NON_EXPIRING_NOT_AFTER,
                            "rootHash" => expected_batch_root_hash.to_vec(),
                            "notBefore" => 1_700_000_000u64,
                            "firmwareVersion" => 0u64,
                        },
                    },
                    &mut expected_non_ent_debug,
                )
                .unwrap();
                assert!(
                    r.auth_data.ends_with(&expected_non_ent_debug),
                    "Fallback non-enterprise registration with mtc-debug must include 6 fields and omit deviceSerial"
                );
            }
            _ => panic!("Expected AuthenticatorMakeCredential"),
        }

        let mut fido_ep_params = create_minimal_make_credential_parameters();
        fido_ep_params.rp.rp_id = String::from("enterprisetest.certinfra.fidoalliance.org");
        fido_ep_params.enterprise_attestation = Some(1);
        match ctap_state
            .process_make_credential(&mut env, fido_ep_params, DUMMY_CHANNEL)
            .unwrap()
        {
            ResponseData::AuthenticatorMakeCredential(r) => {
                assert_eq!(r.ep_att, Some(true));
            }
            _ => panic!("Expected AuthenticatorMakeCredential"),
        }
    }

    #[test]
    #[cfg(feature = "mldsa")]
    fn test_second_non_enterprise_batch_x509_on_non_mldsa_make_credential() {
        use crate::ctap::mtc::{
            MtcAttestationFormat, MtcCertDescriptor, ProvisionedMtcAttestation,
        };

        let mut env = TestEnv::default();
        let aaguid = [0xBB; 16];
        env.persist().set_aaguid(&aaguid).unwrap();

        // 1. Primary Non-Enterprise PQ Batch Key (ML-DSA-44) + PQ X.509 cert + MTC descriptor
        let pq_batch_key = PrivateKey::<TestEnv>::new(&mut env, SignatureAlgorithm::MlDsa44);
        let mut pq_sk_bytes = Vec::new();
        cbor_write(pq_batch_key.to_cbor(), &mut pq_sk_bytes).unwrap();
        let pq_x509_der = vec![0x30, 0x82, 0x04, 0x00, 0xAA, 0xBB];

        // 2. Second Non-Enterprise Classical Batch Key (ES256) + ES256 X.509 cert (signed by ES384 root)
        let classical_batch_key = PrivateKey::<TestEnv>::new_ecdsa(&mut env);
        let classical_sk_bytes = classical_batch_key.export(); // 32-byte P-256 scalar
        let classical_x509_der = vec![0x30, 0x82, 0x02, 0x00, 0xCC, 0xDD];

        let batch_mtc = ProvisionedMtcAttestation {
            format: MtcAttestationFormat::Mtc,
            x5c: Some(pq_x509_der.clone()),
            classical_key: Some(classical_sk_bytes),
            classical_x5c: Some(classical_x509_der.clone()),
            key_ref: true,
            cert: MtcCertDescriptor {
                ca_id: vec![0x83, 0x99, 0x3f, 0x01, 0x01],
                serial: 0x0007_0000_0000_0000,
                mtc_proof: vec![0x11; 96],
                not_before: 1_700_000_000,
                not_after: 1_800_000_000,
                firmware_version: None,
            },
        };
        env.persist()
            .set_attestation(
                AttestationId::Batch,
                Some(&Attestation {
                    wrapped_private_key: pq_sk_bytes,
                    certificate: batch_mtc.to_bytes().unwrap(),
                }),
            )
            .unwrap();

        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // Case 1: Non-ML-DSA MakeCredential (ES256, EdDSA, ES384) -> uses second non-enterprise
        //         classical batch key (alg = -7 / ES256) and classical X.509 certificate!
        for cred_alg in [
            SignatureAlgorithm::Es256,
            #[cfg(feature = "ed25519")]
            SignatureAlgorithm::Eddsa,
            #[cfg(feature = "es384")]
            SignatureAlgorithm::Es384,
        ] {
            let mut params = create_minimal_make_credential_parameters();
            params.user.user_id = vec![cred_alg as i64 as u8; 16];
            params.pub_key_cred_params = vec![PublicKeyCredentialParameter {
                cred_type: PublicKeyCredentialType::PublicKey,
                alg: cred_alg,
            }];
            match ctap_state
                .process_make_credential(&mut env, params, DUMMY_CHANNEL)
                .unwrap()
            {
                ResponseData::AuthenticatorMakeCredential(r) => {
                    assert_eq!(r.fmt, "packed");
                    assert_eq!(r.att_stmt.alg, SignatureAlgorithm::Es256 as i64);
                    assert_eq!(r.att_stmt.x5c, Some(vec![classical_x509_der.clone()]));
                    assert!(r.att_stmt.pub_key.is_none());
                    assert!(r.att_stmt.mtc_cert.is_none());
                }
                _ => panic!("Expected AuthenticatorMakeCredential"),
            }
        }

        // Case 2: ML-DSA MakeCredential (ML-DSA-44) -> uses primary PQ batch key (alg = -48) and PQ X.509 cert!
        let mut pq_params = create_minimal_make_credential_parameters();
        pq_params.user.user_id = vec![0x99; 16];
        pq_params.pub_key_cred_params = vec![PublicKeyCredentialParameter {
            cred_type: PublicKeyCredentialType::PublicKey,
            alg: SignatureAlgorithm::MlDsa44,
        }];
        match ctap_state
            .process_make_credential(&mut env, pq_params, DUMMY_CHANNEL)
            .unwrap()
        {
            ResponseData::AuthenticatorMakeCredential(r) => {
                assert_eq!(r.fmt, "packed");
                assert_eq!(r.att_stmt.alg, SignatureAlgorithm::MlDsa44 as i64);
                assert_eq!(r.att_stmt.x5c, Some(vec![pq_x509_der]));
                assert!(r.att_stmt.pub_key.is_none());
                assert!(r.att_stmt.mtc_cert.is_none());
            }
            _ => panic!("Expected AuthenticatorMakeCredential"),
        }
    }

    #[test]
    fn test_persistent_pin_uv_auth_token_and_encrypted_get_info() {
        use aes::cipher::generic_array::GenericArray;
        use aes::cipher::{BlockDecryptMut, KeyIvInit};
        use crate::ctap::data_formats::CredentialManagementSubCommandParameters;

        fn decrypt_with_ppuat(ppuat: &[u8], info: &[u8], iv_and_ct: &[u8]) -> [u8; 16] {
            assert_eq!(iv_and_ct.len(), 32);
            let mut okm = [0u8; 32];
            Hkdf::<TestEnv>::hkdf_empty_salt_256(ppuat, info, &mut okm);
            let aes_key = &okm[..16];
            let iv = &iv_and_ct[..16];
            let mut block = [0u8; 16];
            block.copy_from_slice(&iv_and_ct[16..32]);
            let mut decryptor = cbc::Decryptor::<aes::Aes128>::new_from_slices(aes_key, iv).unwrap();
            decryptor.decrypt_block_mut(GenericArray::from_mut_slice(&mut block));
            block
        }

        let mut env = TestEnv::default();
        let mut ctap_state = CtapState::<TestEnv>::new(&mut env);

        // 1. Set initial PIN ("1234").
        let mut pin = [0u8; 64];
        pin[..4].copy_from_slice(b"1234");
        let mut pin_hash = [0u8; 16];
        pin_hash.copy_from_slice(&Sha::<TestEnv>::digest(&pin[..])[..16]);
        env.persist().set_pin(&pin_hash, 4).unwrap();

        // 2. Request persistentPinUvAuthToken with pcmr (0x40) and permissions_rp_id.
        let platform_pin_protocol = PinProtocol::<TestEnv>::new(&mut env);
        let platform_cose_key = platform_pin_protocol.get_public_key();
        let ka_resp = ctap_state
            .client_pin
            .process_command(
                &mut env,
                AuthenticatorClientPinParameters {
                    pin_uv_auth_protocol: PinUvAuthProtocol::V2,
                    sub_command: ClientPinSubCommand::GetKeyAgreement,
                    key_agreement: None,
                    pin_uv_auth_param: None,
                    new_pin_enc: None,
                    pin_hash_enc: None,
                    permissions: None,
                    permissions_rp_id: None,
                },
                DUMMY_CHANNEL,
            )
            .unwrap();
        let authr_cose_key = match ka_resp {
            ResponseData::AuthenticatorClientPin(Some(r)) => r.key_agreement.unwrap(),
            _ => panic!("Expected AuthenticatorClientPin"),
        };
        let shared_secret = platform_pin_protocol
            .decapsulate(authr_cose_key, PinUvAuthProtocol::V2)
            .unwrap();
        let pin_hash_enc = shared_secret.encrypt(&mut env, &pin_hash).unwrap();
        let pcmr_resp = ctap_state
            .client_pin
            .process_command(
                &mut env,
                AuthenticatorClientPinParameters {
                    pin_uv_auth_protocol: PinUvAuthProtocol::V2,
                    sub_command: ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
                    key_agreement: Some(platform_cose_key.clone()),
                    pin_uv_auth_param: None,
                    new_pin_enc: None,
                    pin_hash_enc: Some(pin_hash_enc),
                    permissions: Some(0x40),
                    permissions_rp_id: Some(String::from("example.com")),
                },
                DUMMY_CHANNEL,
            )
            .unwrap();
        let encrypted_ppuat = match pcmr_resp {
            ResponseData::AuthenticatorClientPin(Some(r)) => r.pin_uv_auth_token.unwrap(),
            _ => panic!("Expected AuthenticatorClientPin"),
        };
        let ppuat_vec = shared_secret
            .decrypt(&encrypted_ppuat)
            .unwrap()
            .expose_secret_to_vec();
        assert_eq!(ppuat_vec.len(), 32);
        let ppuat = *arrayref::array_ref![ppuat_vec, 0, 32];

        // 3. Call GetInfo twice: verify IVs change while decrypted encIdentifier & encCredStoreState stay identical.
        let info1 = match ctap_state.process_get_info(&mut env).unwrap() {
            ResponseData::AuthenticatorGetInfo(r) => r,
            _ => panic!("Expected AuthenticatorGetInfo"),
        };
        let info2 = match ctap_state.process_get_info(&mut env).unwrap() {
            ResponseData::AuthenticatorGetInfo(r) => r,
            _ => panic!("Expected AuthenticatorGetInfo"),
        };
        let enc_id_1 = info1.enc_identifier.unwrap();
        let enc_id_2 = info2.enc_identifier.unwrap();
        assert_ne!(&enc_id_1[..16], &enc_id_2[..16]);
        let dec_id_1 = decrypt_with_ppuat(&ppuat, b"encIdentifier", &enc_id_1);
        let dec_id_2 = decrypt_with_ppuat(&ppuat, b"encIdentifier", &enc_id_2);
        assert_eq!(dec_id_1, dec_id_2);

        let enc_state_1 = info1.enc_cred_store_state.unwrap();
        let enc_state_2 = info2.enc_cred_store_state.unwrap();
        assert_ne!(&enc_state_1[..16], &enc_state_2[..16]);
        let dec_state_1 = decrypt_with_ppuat(&ppuat, b"encCredStoreState", &enc_state_1);
        let dec_state_2 = decrypt_with_ppuat(&ppuat, b"encCredStoreState", &enc_state_2);
        assert_eq!(dec_state_1, dec_state_2);

        // 4. Create a discoverable credential and verify encCredStoreState rotates.
        let pin_hash_enc_mc = shared_secret.encrypt(&mut env, &pin_hash).unwrap();
        let mc_token_resp = ctap_state
            .client_pin
            .process_command(
                &mut env,
                AuthenticatorClientPinParameters {
                    pin_uv_auth_protocol: PinUvAuthProtocol::V2,
                    sub_command: ClientPinSubCommand::GetPinToken,
                    key_agreement: Some(platform_cose_key.clone()),
                    pin_uv_auth_param: None,
                    new_pin_enc: None,
                    pin_hash_enc: Some(pin_hash_enc_mc),
                    permissions: None,
                    permissions_rp_id: None,
                },
                DUMMY_CHANNEL,
            )
            .unwrap();
        let enc_session_token = match mc_token_resp {
            ResponseData::AuthenticatorClientPin(Some(r)) => r.pin_uv_auth_token.unwrap(),
            _ => panic!("Expected AuthenticatorClientPin"),
        };
        let session_token_vec = shared_secret
            .decrypt(&enc_session_token)
            .unwrap()
            .expose_secret_to_vec();
        let session_token = *arrayref::array_ref![session_token_vec, 0, 32];
        let mut rk_params = create_minimal_make_credential_parameters();
        rk_params.pin_uv_auth_protocol = Some(PinUvAuthProtocol::V2);
        rk_params.pin_uv_auth_param = Some(authenticate_pin_uv_auth_token(
            &session_token,
            &rk_params.client_data_hash,
            PinUvAuthProtocol::V2,
        ));
        assert!(
            ctap_state
                .process_make_credential(&mut env, rk_params, DUMMY_CHANNEL)
                .is_ok()
        );
        let info3 = match ctap_state.process_get_info(&mut env).unwrap() {
            ResponseData::AuthenticatorGetInfo(r) => r,
            _ => panic!("Expected AuthenticatorGetInfo"),
        };
        let enc_state_3 = info3.enc_cred_store_state.unwrap();
        assert_ne!(&enc_state_2[16..], &enc_state_3[16..]);
        let dec_state_3 = decrypt_with_ppuat(&ppuat, b"encCredStoreState", &enc_state_3);
        assert_ne!(dec_state_2, dec_state_3);

        // 5. Authenticate read-only CredentialManagement subcommands using persistentPinUvAuthToken.
        for sub_command in [
            CredentialManagementSubCommand::GetCredsMetadata,
            CredentialManagementSubCommand::EnumerateRpsBegin,
        ] {
            let msg = [sub_command as u8];
            let auth_param =
                authenticate_pin_uv_auth_token(&ppuat, &msg, PinUvAuthProtocol::V2);
            let cm_resp = ctap_state.process_parsed_command(
                &mut env,
                Command::AuthenticatorCredentialManagement(
                    AuthenticatorCredentialManagementParameters {
                        sub_command,
                        sub_command_params: None,
                        pin_uv_auth_protocol: Some(PinUvAuthProtocol::V2),
                        pin_uv_auth_param: Some(auth_param),
                    },
                ),
                DUMMY_CHANNEL,
            );
            assert!(cm_resp.is_ok());
        }

        let rp_id_hash = Sha::<TestEnv>::digest(b"example.com").to_vec();
        let sub_params = CredentialManagementSubCommandParameters {
            rp_id_hash: Some(rp_id_hash),
            credential_id: None,
            user: None,
        };
        let mut enum_cred_msg = vec![CredentialManagementSubCommand::EnumerateCredentialsBegin as u8];
        cbor_write(sub_params.clone().into(), &mut enum_cred_msg).unwrap();
        let enum_cred_auth =
            authenticate_pin_uv_auth_token(&ppuat, &enum_cred_msg, PinUvAuthProtocol::V2);
        let enum_cred_resp = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorCredentialManagement(
                AuthenticatorCredentialManagementParameters {
                    sub_command: CredentialManagementSubCommand::EnumerateCredentialsBegin,
                    sub_command_params: Some(sub_params),
                    pin_uv_auth_protocol: Some(PinUvAuthProtocol::V2),
                    pin_uv_auth_param: Some(enum_cred_auth),
                },
            ),
            DUMMY_CHANNEL,
        );
        assert!(enum_cred_resp.is_ok());

        // 6. Change PIN and verify old persistentPinUvAuthToken is invalidated (CTAP2_ERR_PIN_AUTH_INVALID).
        let mut new_padded_pin = [0u8; 64];
        new_padded_pin[..4].copy_from_slice(b"5678");
        let new_pin_enc = shared_secret.encrypt(&mut env, &new_padded_pin).unwrap();
        let curr_pin_hash_enc = shared_secret.encrypt(&mut env, &pin_hash).unwrap();
        let mut change_pin_auth_data = new_pin_enc.clone();
        change_pin_auth_data.extend_from_slice(&curr_pin_hash_enc);
        let change_pin_auth_param = shared_secret.authenticate(&change_pin_auth_data);
        assert!(
            ctap_state
                .client_pin
                .process_command(
                    &mut env,
                    AuthenticatorClientPinParameters {
                        pin_uv_auth_protocol: PinUvAuthProtocol::V2,
                        sub_command: ClientPinSubCommand::ChangePin,
                        key_agreement: Some(platform_cose_key),
                        pin_uv_auth_param: Some(change_pin_auth_param),
                        new_pin_enc: Some(new_pin_enc),
                        pin_hash_enc: Some(curr_pin_hash_enc),
                        permissions: None,
                        permissions_rp_id: None,
                    },
                    DUMMY_CHANNEL,
                )
                .is_ok()
        );

        let old_auth_param = authenticate_pin_uv_auth_token(
            &ppuat,
            &[CredentialManagementSubCommand::EnumerateRpsBegin as u8],
            PinUvAuthProtocol::V2,
        );
        let post_change_resp = ctap_state.process_parsed_command(
            &mut env,
            Command::AuthenticatorCredentialManagement(
                AuthenticatorCredentialManagementParameters {
                    sub_command: CredentialManagementSubCommand::EnumerateRpsBegin,
                    sub_command_params: None,
                    pin_uv_auth_protocol: Some(PinUvAuthProtocol::V2),
                    pin_uv_auth_param: Some(old_auth_param),
                },
            ),
            DUMMY_CHANNEL,
        );
        assert_eq!(
            post_change_resp,
            Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }
}

