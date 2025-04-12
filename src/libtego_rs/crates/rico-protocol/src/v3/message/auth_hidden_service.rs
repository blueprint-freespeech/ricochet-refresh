// std
use std::io::Write;

//extern
use sha2::Sha256;
use hmac::{Hmac, Mac};
use tor_interface::tor_crypto::{V3OnionServiceId, V3_ONION_SERVICE_ID_STRING_LENGTH};

pub(crate) const CHANNEL_TYPE: &'static str = "im.ricochet.auth.hidden-service";
pub(crate) const CLIENT_COOKIE_SIZE: usize = 16;
pub(crate) const SERVER_COOKIE_SIZE: usize = 16;
pub(crate) const PROOF_SIZE: usize = 32;
pub(crate) const PROOF_SIGNATURE_SIZE: usize = 64;

#[derive(Debug, PartialEq)]
pub enum Packet {
    Proof(Proof),
    Result(Result),
}

impl Packet {
    pub fn write_to_vec(&self, v:& mut Vec<u8>) -> std::result::Result<(), crate::Error> {
        use protobuf::Message;
        use crate::v3::protos;

        let mut pb: protos::AuthHiddenService::Packet = Default::default();

        match self {
            Packet::Proof(proof) => {
                let signature = proof.signature();
                let service_id = proof.service_id();

                let mut proof = protos::AuthHiddenService::Proof::default();
                proof.signature = Some(signature.into());
                proof.service_id = Some(service_id.to_string());

                pb.proof = Some(proof).into();
            },
            Packet::Result(result) => {
                let accepted = result.accepted();
                let is_known_contact = result.is_known_contact().clone();

                let mut result = protos::AuthHiddenService::Result::default();
                result.accepted = Some(accepted);
                result.is_known_contact = is_known_contact;

                pb.result = Some(result).into();
            }
        }

        // serialise
        pb.write_to_vec(v).map_err(crate::Error::ProtobufError)?;
        Ok(())
    }
}

impl TryFrom<&[u8]> for Packet {
    type Error = crate::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        use protobuf::Message;
        use crate::v3::protos;

        // parse bytes into protobuf message
        let pb = protos::AuthHiddenService::Packet::parse_from_bytes(value).map_err(Self::Error::ProtobufError)?;

        let proof = pb.proof.into_option();
        let result = pb.result.into_option();

        match (proof, result) {
            (Some(proof), None) => {
                let signature = proof.signature.ok_or(Self::Error::InvalidProtobufMessage)?;
                use crate::auth_hidden_service::PROOF_SIGNATURE_SIZE;
                let signature: [u8; PROOF_SIGNATURE_SIZE] = match signature.try_into() {
                    Ok(signature) => signature,
                    Err(_) => return Err(Self::Error::InvalidProtobufMessage),
                };

                let service_id = proof.service_id.ok_or(Self::Error::InvalidProtobufMessage)?;
                use tor_interface::tor_crypto::V3OnionServiceId;
                let service_id = match V3OnionServiceId::from_string(service_id.as_str()) {
                    Ok(service_id) => service_id,
                    Err(_) => return Err(Self::Error::InvalidProtobufMessage),
                };

                let proof = Proof::new(signature, service_id)?;
                Ok(Packet::Proof(proof))
            },
            (None, Some(result)) => {
                let accepted = result.accepted.ok_or(Self::Error::InvalidProtobufMessage)?;

                let is_known_contact = result.is_known_contact;

                let result = Result::new(accepted, is_known_contact)?;
                Ok(Packet::Result(result))
            },
            _ => Err(Self::Error::InvalidProtobufMessage),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct OpenChannel {
    pub client_cookie: [u8; CLIENT_COOKIE_SIZE],
}

impl OpenChannel {
    pub(crate) const CLIENT_COOKIE_FIELD_NUMBER: u32 = 7200;
}

#[derive(Debug, PartialEq)]
pub struct ChannelResult {
    pub server_cookie: [u8; SERVER_COOKIE_SIZE],
}

impl ChannelResult {
    pub(crate) const SERVER_COOKIE_FIELD_NUMBER: u32 = 7200;
}

#[derive(Debug, PartialEq)]
pub struct Proof {
    // TODO: spec doesn't explicitly say how many bytes the proof's signature is
    signature: [u8; PROOF_SIGNATURE_SIZE],
    service_id: tor_interface::tor_crypto::V3OnionServiceId,
}

impl Proof {
    pub fn new(signature: [u8; PROOF_SIGNATURE_SIZE], service_id: V3OnionServiceId) -> std::result::Result<Self, crate::Error> {
        Ok(Self{signature, service_id})
    }

    pub fn signature(&self) -> &[u8; PROOF_SIGNATURE_SIZE] {
        &self.signature
    }

    pub fn service_id(&self) -> &V3OnionServiceId {
        &self.service_id
    }

    pub fn message(
        client_cookie: &[u8; CLIENT_COOKIE_SIZE],
        server_cookie: &[u8; SERVER_COOKIE_SIZE],
        client_service_id: &V3OnionServiceId,
        server_service_id: &V3OnionServiceId) -> [u8; PROOF_SIZE] {

        let mut key: Vec<u8> = Vec::with_capacity(
            CLIENT_COOKIE_SIZE +
            SERVER_COOKIE_SIZE
        );
        key.write(client_cookie).expect("key write failed");
        key.write(server_cookie).expect("key write failed");

        let mut message: Vec<u8> = Vec::with_capacity(
            V3_ONION_SERVICE_ID_STRING_LENGTH +
            V3_ONION_SERVICE_ID_STRING_LENGTH
        );
        message.write(client_service_id.as_bytes()).expect("message write failed");
        message.write(server_service_id.as_bytes()).expect("message write failed");

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(key.as_slice()).expect("HMAC-SHA256 creation failed");
        mac.update(message.as_slice());

        let result = mac.finalize().into_bytes();
        result.try_into().expect("message wrong size")
    }

}

#[derive(Debug, PartialEq)]
pub struct Result {
    accepted: bool,
    // TODO: is_known_contact must be present if accepted is true
    is_known_contact: Option<bool>,
}

impl Result {
    pub fn new(accepted: bool, is_known_contact: Option<bool>) -> std::result::Result<Self, crate::Error> {
        if accepted && is_known_contact.is_none() {
            return Err(crate::Error::PacketConstructionFailed("is_known_contact must be present if accepted is true".to_string()));
        }
        Ok(Self{accepted, is_known_contact})
    }

    pub fn accepted(&self) -> bool {
        self.accepted
    }

    pub fn is_known_contact(&self) -> &Option<bool> {
        &self.is_known_contact
    }
}
