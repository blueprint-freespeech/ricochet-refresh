use crate::v3::Error;

pub(crate) const CHANNEL_TYPE: &str = "im.ricochet.contact.request";

#[derive(Debug, PartialEq)]
pub enum Packet {
    Response(Response),
}

impl Packet {
    pub fn write_to_vec(&self, v: &mut Vec<u8>) -> Result<(), Error> {
        use crate::v3::protos;
        use protobuf::Message;

        let mut pb: protos::ContactRequestChannel::Response = Default::default();
        match self {
            Packet::Response(response) => {
                let status = match response.status {
                    Status::Undefined => protos::ContactRequestChannel::response::Status::Undefined,
                    Status::Pending => protos::ContactRequestChannel::response::Status::Pending,
                    Status::Accepted => protos::ContactRequestChannel::response::Status::Accepted,
                    Status::Rejected => protos::ContactRequestChannel::response::Status::Rejected,
                    Status::Error => protos::ContactRequestChannel::response::Status::Error,
                };
                pb.set_status(status);
            }
        }

        pb.write_to_vec(v).map_err(Error::ProtobufError)?;
        Ok(())
    }
}

impl TryFrom<&[u8]> for Packet {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        use crate::v3::protos;
        use protobuf::Message;

        let pb = protos::ContactRequestChannel::Response::parse_from_bytes(value)
            .map_err(Self::Error::ProtobufError)?;

        let status = match pb.status() {
            protos::ContactRequestChannel::response::Status::Undefined => Status::Undefined,
            protos::ContactRequestChannel::response::Status::Pending => Status::Pending,
            protos::ContactRequestChannel::response::Status::Accepted => Status::Accepted,
            protos::ContactRequestChannel::response::Status::Rejected => Status::Rejected,
            protos::ContactRequestChannel::response::Status::Error => Status::Error,
        };
        let response = Response { status };
        Ok(Packet::Response(response))
    }
}

impl TryFrom<&Packet> for Vec<u8> {
    type Error = crate::v3::Error;

    fn try_from(packet: &Packet) -> std::result::Result<Self, Self::Error> {
        let mut buf: Self = Default::default();
        packet.write_to_vec(&mut buf)?;
        Ok(buf)
    }
}

#[derive(Debug, PartialEq)]
pub struct OpenChannel {
    pub contact_request: ContactRequest,
}

impl OpenChannel {
    pub(crate) const CONTACT_REQUEST_FIELD_NUMBER: u32 = 200u32;
}

#[derive(Debug, PartialEq)]
pub struct ContactRequest {
    pub nickname: Nickname,
    pub message_text: MessageText,
}

#[derive(Debug, PartialEq)]
pub struct MessageText {
    value: String,
}

impl From<&MessageText> for String {
    fn from(message_text: &MessageText) -> String {
        message_text.value.clone()
    }
}

impl TryFrom<String> for MessageText {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        // TODO: message_text requirements are NOT defined in the spec:
        // - must contain no more than 2000 utf16 code units

        const MAX_MESSAGE_SIZE: usize = 2000;
        let mut count: usize = 0;
        for _code_unit in value.encode_utf16() {
            count += 1;
            if count > MAX_MESSAGE_SIZE {
                return Err(Self::Error::InvalidContactRequestMessageTooLong);
            }
        }

        Ok(MessageText { value })
    }
}

#[derive(Debug, PartialEq)]
pub struct Nickname {
    value: String,
}

impl From<&Nickname> for String {
    fn from(nickname: &Nickname) -> String {
        nickname.value.clone()
    }
}

impl TryFrom<String> for Nickname {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        // TODO: nickname requirements are NOT defined in the spec
        // from Ricochet-Refresh's isAcceptableNickname() function:
        // - must contain no more than 30 utf16 code units
        // - must not contain "\"", "<", ">", "&"
        // - must not contain 'other, format' code units (Cf)
        // - must not contain 'other, control' code units (Cc)
        // - must not be non-characters (i.e.  0xFFFE, 0xFFFF, and 0xFDD0 through 0xFDEF)

        const MAX_NICKNAME_SIZE: usize = 30;
        let mut count: usize = 0;
        for _ in value.encode_utf16() {
            count += 1;
            if count > MAX_NICKNAME_SIZE {
                return Err(Self::Error::InvalidNicknameTooLong);
            }
        }

        for code_unit in value.chars() {
            // ensure not a non-character
            let is_non_character = matches!(code_unit, '\u{FDD0}'..='\u{FDEF}' |
                    '\u{0FFFE}'..='\u{0FFFF}' |
                    '\u{1FFFE}'..='\u{1FFFF}' |
                    '\u{2FFFE}'..='\u{2FFFF}' |
                    '\u{3FFFE}'..='\u{3FFFF}' |
                    '\u{4FFFE}'..='\u{4FFFF}' |
                    '\u{5FFFE}'..='\u{5FFFF}' |
                    '\u{6FFFE}'..='\u{6FFFF}' |
                    '\u{7FFFE}'..='\u{7FFFF}' |
                    '\u{8FFFE}'..='\u{8FFFF}' |
                    '\u{9FFFE}'..='\u{9FFFF}' |
                    '\u{AFFFE}'..='\u{AFFFF}' |
                    '\u{BFFFE}'..='\u{BFFFF}' |
                    '\u{CFFFE}'..='\u{CFFFF}' |
                    '\u{DFFFE}'..='\u{DFFFF}' |
                    '\u{EFFFE}'..='\u{EFFFF}' |
                    '\u{FFFFE}'..='\u{FFFFF}' |
                    '\u{10FFFE}'..='\u{10FFFF}');

            if is_non_character {
                return Err(Self::Error::InvalidNicknameContainsNonCharacter(
                    code_unit as u32,
                ));
            }

            if let Some(character) = char::from_u32(code_unit as u32) {
                // ensure not an html-character
                let is_html_character = matches!(character, '\"' | '<' | '>' | '&');

                if is_html_character {
                    return Err(Self::Error::InvalidNicknameContainsHtmlCharacter(character));
                }

                use unicode_general_category::*;
                match get_general_category(character) {
                    // ensure not a format code unit (Cf)
                    GeneralCategory::Format => {
                        return Err(Self::Error::InvalidNicknameContainsFormatCodeUnit(
                            code_unit as u32,
                        ));
                    }
                    // ensure not a control code unit (Cc)
                    GeneralCategory::Control => {
                        return Err(Self::Error::InvalidNicknameContainsControlCodeUnit(
                            code_unit as u32,
                        ));
                    }
                    _ => (),
                }
            } else {
                unreachable!();
            }
        }

        Ok(Nickname { value })
    }
}

#[derive(Debug, PartialEq)]
pub struct ChannelResult {
    pub response: Response,
}

impl ChannelResult {
    pub(crate) const RESPONSE_FIELD_NUMBER: u32 = 201u32;
}

#[derive(Debug, PartialEq)]
pub struct Response {
    pub status: Status,
}

// TODO: spec says 'Undefined' is "Not valid in transmitted messages" and we should clarify what that actually means
#[derive(Debug, PartialEq)]
pub enum Status {
    Undefined,
    Pending,
    Accepted,
    Rejected,
    Error,
}
