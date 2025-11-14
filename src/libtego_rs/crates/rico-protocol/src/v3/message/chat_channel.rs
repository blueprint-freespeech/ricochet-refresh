use crate::v3::Error;

pub(crate) const CHANNEL_TYPE: &str = "im.ricochet.chat";

#[derive(Debug, PartialEq)]
pub enum Packet {
    ChatMessage(ChatMessage),
    ChatAcknowledge(ChatAcknowledge),
}

impl Packet {
    pub fn write_to_vec(&self, v: &mut Vec<u8>) -> Result<(), Error> {
        use crate::v3::protos;
        use protobuf::Message;

        let mut pb: protos::ChatChannel::Packet = Default::default();

        match self {
            Packet::ChatMessage(chat_message) => {
                let message_text: String = chat_message.message_text().into();
                let message_text = Some(message_text);
                let message_id = Some(chat_message.message_id());
                let time_delta = chat_message
                    .time_delta()
                    .as_ref()
                    .map(|time_delta| -(time_delta.as_secs() as i64));

                let chat_message = protos::ChatChannel::ChatMessage {
                    message_text,
                    message_id,
                    time_delta,
                    ..Default::default()
                };

                pb.chat_message = Some(chat_message).into();
            }
            Packet::ChatAcknowledge(chat_acknowledge) => {
                let message_id = Some(chat_acknowledge.message_id());
                let accepted = Some(chat_acknowledge.accepted());

                let chat_acknowledge = protos::ChatChannel::ChatAcknowledge {
                    message_id,
                    accepted,
                    ..Default::default()
                };

                pb.chat_acknowledge = Some(chat_acknowledge).into();
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

        // parse bytes into protobuf message
        let pb = protos::ChatChannel::Packet::parse_from_bytes(value)
            .map_err(Self::Error::ProtobufError)?;

        let chat_message = pb.chat_message.into_option();
        let chat_acknowledge = pb.chat_acknowledge.into_option();

        match (chat_message, chat_acknowledge) {
            (Some(chat_message), None) => {
                let message_text = chat_message
                    .message_text
                    .ok_or(Self::Error::InvalidProtobufMessage)?;
                let message_text: MessageText = message_text.try_into()?;

                let message_id = chat_message
                    .message_id
                    .ok_or(Self::Error::InvalidProtobufMessage)?;

                let time_delta: Option<std::time::Duration> = match chat_message.time_delta {
                    Some(time_delta) => match time_delta {
                        ..=0 => Some(std::time::Duration::from_secs(-time_delta as u64)),
                        _ => return Err(Self::Error::InvalidProtobufMessage),
                    },
                    None => None,
                };

                let chat_message = ChatMessage::new(message_text, message_id, time_delta)?;
                Ok(Packet::ChatMessage(chat_message))
            }
            (None, Some(chat_acknowledge)) => {
                let message_id = chat_acknowledge
                    .message_id
                    .ok_or(Self::Error::InvalidProtobufMessage)?;
                let accepted = chat_acknowledge
                    .accepted
                    .ok_or(Self::Error::InvalidProtobufMessage)?;

                let chat_acknowledge = ChatAcknowledge {
                    message_id,
                    accepted,
                };
                Ok(Packet::ChatAcknowledge(chat_acknowledge))
            }
            _ => Err(Self::Error::InvalidProtobufMessage),
        }
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
pub struct ChatMessage {
    message_text: MessageText,
    message_id: u32,
    time_delta: Option<std::time::Duration>,
}

impl ChatMessage {
    pub fn new(
        message_text: MessageText,
        message_id: u32,
        time_delta: Option<std::time::Duration>,
    ) -> Result<Self, Error> {
        if let Some(time_delta) = time_delta {
            if time_delta.as_secs() > i64::MAX as u64 {
                return Err(Error::PacketConstructionFailed(
                    "time_delta in seconds must be less than or equal to i64::MAX".to_string(),
                ));
            }
        }

        Ok(Self {
            message_text,
            message_id,
            time_delta,
        })
    }

    pub fn message_text(&self) -> &MessageText {
        &self.message_text
    }

    pub fn message_id(&self) -> u32 {
        self.message_id
    }

    pub fn time_delta(&self) -> &Option<std::time::Duration> {
        &self.time_delta
    }
}

#[derive(Clone, Debug, PartialEq)]
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
        // per message_text requirements are defined in the spec:
        // - must contain at least 1 utf16 code unit
        // - must contain no more than 2000 utf16 code units

        const MAX_MESSAGE_SIZE: usize = 2000;
        let mut count: usize = 0;
        for _code_unit in value.encode_utf16() {
            count += 1;
            if count > MAX_MESSAGE_SIZE {
                return Err(Self::Error::InvalidChatMessageTooLong);
            }
        }
        if count == 0 {
            return Err(Self::Error::InvalidChatMessageEmpty);
        }

        Ok(MessageText { value })
    }
}

#[derive(Debug, PartialEq)]
pub struct ChatAcknowledge {
    message_id: u32,
    accepted: bool,
}

impl ChatAcknowledge {
    pub fn new(message_id: u32, accepted: bool) -> Result<Self, Error> {
        Ok(Self {
            message_id,
            accepted,
        })
    }

    pub fn message_id(&self) -> u32 {
        self.message_id
    }

    pub fn accepted(&self) -> bool {
        self.accepted
    }
}
