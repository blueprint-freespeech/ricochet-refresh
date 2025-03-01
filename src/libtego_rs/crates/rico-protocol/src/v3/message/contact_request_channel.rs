pub(crate) const CHANNEL_TYPE: &'static str = "im.ricochet.contact.request";

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
    value: String
}

impl From<&MessageText> for String {
    fn from(message_text: &MessageText) -> String {
        message_text.value.clone()
    }
}

impl TryFrom<String> for MessageText {
    type Error = crate::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        // TODO: message_text requirements are NOT defined in the spec:
        // - must contain no more than 2000 utf16 code units

        const MAX_MESSAGE_SIZE: usize = 2000;
        let mut count:usize = 0;
        for _code_unit in value.encode_utf16() {
            count += 1;
            if count > MAX_MESSAGE_SIZE {
                return Err(Self::Error::InvalidContactRequestMessageTooLong);
            }
        }

        Ok(MessageText{value})
    }
}

#[derive(Debug, PartialEq)]
pub struct Nickname {
    value: String
}

impl From<&Nickname> for String {
    fn from(nickname: &Nickname) -> String {
        nickname.value.clone()
    }
}

impl TryFrom<String> for Nickname {
    type Error = crate::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        // TODO: nickname requirements are NOT defined in the spec
        // from Ricochet-Refresh's isAcceptableNickname() function:
        // - must contain no more than 30 utf16 code units
        // - must not contain "\"", "<", ">", "&"
        // - must not contain 'other, format' code units (Cf)
        // - must not contain 'other, control' code units (Cc)
        // - must not be non-characters (i.e.  0xFFFE, 0xFFFF, and 0xFDD0 through 0xFDEF)

        const MAX_NICKNAME_SIZE: usize = 30;
        let mut count:usize = 0;
        for code_unit in value.encode_utf16() {
            count += 1;
            if count > MAX_NICKNAME_SIZE {
                return Err(Self::Error::InvalidNicknameTooLong);
            }

            // ensure not a non-character
            let is_non_character = match code_unit {
                0xFFFEu16..=0xFFFFu16 => true,
                0xFDD0u16..=0xFDEFu16 => true,
                _ => false,
            };

            if is_non_character {
                return Err(Self::Error::InvalidNicknameContainsNonCharacter(code_unit));
            }

            if let Some(character) = char::from_u32(code_unit as u32) {
                // ensure not an html-character
                let is_html_character = match character {
                    '\"' => true,
                    '<' => true,
                    '>' => true,
                    '&' => true,
                    _ => false,
                };

                if is_html_character {
                    return Err(Self::Error::InvalidNicknameContainsHtmlCharacter(character));
                }

                use unicode_general_category::*;
                match get_general_category(character) {
                    // ensure not a format code unit (Cf)
                    GeneralCategory::Format => {
                        return Err(Self::Error::InvalidNicknameContainsFormatCodeUnit(code_unit));
                    },
                    // ensure not a control code unit (Cc)
                    GeneralCategory::Control => {
                        return Err(Self::Error::InvalidNicknameContainsControlCodeUnit(code_unit));
                    },
                    _ => ()
                }
            }

        }

        Ok(Nickname{value})
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

#[derive(Debug, PartialEq)]
pub enum Status {
    Undefined,
    Pending,
    Accepted,
    Rejected,
    Error,
}
