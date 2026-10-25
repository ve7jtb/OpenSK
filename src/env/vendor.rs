// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::env::WasefireEnv;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use opensk::api::persist::{AAGUID_LENGTH, Attestation, AttestationId, Persist};
use opensk::ctap::data_formats::{extract_byte_string, extract_map, extract_unsigned};
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};
use opensk::ctap::{Channel, cbor_read, cbor_write};
use opensk::env::Env;
use sk_cbor::{Value, cbor_map_options, destructure_cbor_map};

const VENDOR_COMMAND_CONFIGURE: u8 = 0x40;

pub fn process_vendor_command(
    env: &mut WasefireEnv,
    bytes: &[u8],
    channel: Channel,
) -> Option<Vec<u8>> {
    if bytes.is_empty() || bytes[0] != VENDOR_COMMAND_CONFIGURE {
        return None;
    }
    process_cbor(env, &bytes[1..], channel).unwrap_or_else(|e| Some(vec![e as u8]))
}

fn process_cbor(
    env: &mut WasefireEnv,
    cbor_bytes: &[u8],
    channel: Channel,
) -> CtapResult<Option<Vec<u8>>> {
    let decoded_cbor = cbor_read(cbor_bytes)?;
    let params = VendorConfigureParameters::try_from(decoded_cbor)?;
    let response = process_vendor_configure(env, params, channel)?;
    Ok(Some(encode_cbor(response.into())))
}

fn encode_cbor(value: Value) -> Vec<u8> {
    let mut response_vec = vec![Ctap2StatusCode::CTAP2_OK as u8];
    if cbor_write(value, &mut response_vec).is_err() {
        vec![Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR as u8]
    } else {
        response_vec
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct VendorConfigureParameters {
    pub aaguid: Option<[u8; AAGUID_LENGTH]>,
    pub attestation_material: Option<Attestation>,
    pub cert_append: Option<Vec<u8>>,
    pub attestation_id: Option<AttestationId>,
}

impl TryFrom<Value> for VendorConfigureParameters {
    type Error = Ctap2StatusCode;

    fn try_from(cbor_value: Value) -> CtapResult<Self> {
        destructure_cbor_map! {
            let {
                0x01 => aaguid,
                0x02 => attestation_material,
                0x03 => cert_append,
                0x04 => attestation_id,
            } = extract_map(cbor_value)?;
        }
        let aaguid = aaguid.map(extract_byte_string).transpose()?;
        let aaguid = aaguid
            .map(<[u8; AAGUID_LENGTH]>::try_from)
            .transpose()
            .map_err(|_| Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
        let attestation_material = attestation_material
            .map(Attestation::try_from)
            .transpose()?;
        let cert_append = cert_append.map(extract_byte_string).transpose()?;
        let attestation_id = match attestation_id {
            Some(val) => {
                let id_u64 = extract_unsigned(val)?;
                let id_u8 = u8::try_from(id_u64)
                    .map_err(|_| Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
                Some(
                    AttestationId::try_from(id_u8)
                        .map_err(|_| Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?,
                )
            }
            None => None,
        };
        Ok(VendorConfigureParameters {
            aaguid,
            attestation_material,
            cert_append,
            attestation_id,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct VendorConfigureResponse {
    pub cert_programmed: bool,
    pub pkey_programmed: bool,
    pub aaguid_programmed: bool,
}

impl From<VendorConfigureResponse> for Value {
    fn from(vendor_response: VendorConfigureResponse) -> Self {
        let VendorConfigureResponse {
            cert_programmed,
            pkey_programmed,
            aaguid_programmed,
        } = vendor_response;

        cbor_map_options! {
            0x01 => cert_programmed,
            0x02 => pkey_programmed,
            0x03 => aaguid_programmed,
        }
    }
}

fn process_vendor_configure(
    env: &mut WasefireEnv,
    params: VendorConfigureParameters,
    channel: Channel,
) -> CtapResult<VendorConfigureResponse> {
    opensk::ctap::check_user_presence(env, channel)?;

    let attestation_id = params.attestation_id.unwrap_or(AttestationId::Batch);
    let existing_attestation = env.persist().get_attestation(attestation_id)?;
    let has_existing_attestation = existing_attestation.is_some();
    let has_existing_aaguid = env
        .persist()
        .find(opensk::api::persist::keys::AAGUID)?
        .is_some();

    let mut response = VendorConfigureResponse {
        cert_programmed: has_existing_attestation,
        pkey_programmed: has_existing_attestation,
        aaguid_programmed: has_existing_aaguid,
    };

    if let Some(data) = params.attestation_material {
        if has_existing_attestation {
            env.persist().set_attestation(attestation_id, None)?;
        }
        env.persist().set_attestation(attestation_id, Some(&data))?;
        if attestation_id == AttestationId::Enterprise {
            env.persist().enable_enterprise_attestation()?;
        }
        response.cert_programmed = true;
        response.pkey_programmed = true;
    }

    if let Some(extra_cert_bytes) = params.cert_append {
        let mut current = env
            .persist()
            .read_attestation_certificate_for_id(attestation_id)?
            .ok_or(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)?;
        current.extend_from_slice(&extra_cert_bytes);
        env.persist()
            .write_attestation_certificate_for_id(attestation_id, Some(&current))?;
        response.cert_programmed = true;
    }

    if let Some(aaguid_bytes) = params.aaguid {
        env.persist().set_aaguid(&aaguid_bytes)?;
        response.aaguid_programmed = true;
    }

    Ok(response)
}

#[cfg(test)]
mod test {
    use super::*;
    use sk_cbor::cbor_map;

    #[test]
    fn test_vendor_configure_parameters() {
        let dummy_aaguid = [0x77u8; 16];
        let dummy_cert = [0xddu8; 20];
        let dummy_pkey = [0x41u8; 32];

        // Invalid aaguid length
        let cbor_value = cbor_map! {
            0x01 => vec![0; 15],
        };
        assert_eq!(
            VendorConfigureParameters::try_from(cbor_value),
            Err(Ctap2StatusCode::CTAP1_ERR_INVALID_PARAMETER)
        );

        // Valid with attestation and aaguid
        let cbor_value = cbor_map! {
            0x01 => dummy_aaguid,
            0x02 => cbor_map! {
                0x01 => dummy_cert,
                0x02 => dummy_pkey,
            },
        };
        assert_eq!(
            VendorConfigureParameters::try_from(cbor_value),
            Ok(VendorConfigureParameters {
                aaguid: Some(dummy_aaguid),
                attestation_material: Some(Attestation {
                    wrapped_private_key: dummy_pkey.to_vec(),
                    certificate: dummy_cert.to_vec(),
                }),
                cert_append: None,
                attestation_id: None,
            })
        );
    }

    #[test]
    fn test_vendor_response_into_cbor() {
        let response_cbor: Value = VendorConfigureResponse {
            cert_programmed: true,
            pkey_programmed: false,
            aaguid_programmed: true,
        }
        .into();
        assert_eq!(
            response_cbor,
            cbor_map_options! {
                0x01 => true,
                0x02 => false,
                0x03 => true,
            }
        );
    }
}
