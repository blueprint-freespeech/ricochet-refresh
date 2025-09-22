use crate::v3::Error;

#[derive(Debug, PartialEq)]
pub enum Packet {
    OpenChannel(OpenChannel),
    ChannelResult(ChannelResult),
}

impl Packet {
    pub fn write_to_vec(&self, v: &mut Vec<u8>) -> Result<(), Error> {
        use protobuf::Message;
        use crate::v3::protos;

        // construct our protobuf message
        let mut pb: protos::ControlChannel::Packet = Default::default();
        match self {
            Packet::OpenChannel(open_channel) => {
                let channel_identifier = Some(open_channel.channel_identifier() as i32);
                let channel_type = open_channel.channel_type();
                let channel_type: &str = channel_type.into();
                let channel_type = Some(channel_type.to_string());
                let extension = open_channel.extension();

                // construct OpenChannel packet
                let mut open_channel = protos::ControlChannel::OpenChannel{channel_identifier, channel_type, ..Default::default()};

                // set extensions
                match extension {
                    Some(OpenChannelExtension::ContactRequestChannel(extension)) => {
                        let contact_request = &extension.contact_request;
                        let nickname = &contact_request.nickname;
                        let nickname: String = nickname.into();
                        let nickname = Some(nickname);
                        let message_text = &contact_request.message_text;
                        let message_text: String = message_text.into();
                        let message_text = Some(message_text);

                        let contact_request = protos::ContactRequestChannel::ContactRequest{nickname, message_text, ..Default::default()};

                        let field_number = crate::contact_request_channel::OpenChannel::CONTACT_REQUEST_FIELD_NUMBER;

                        open_channel.mut_unknown_fields().add_length_delimited(field_number, contact_request.write_to_bytes().unwrap());
                    },
                    Some(OpenChannelExtension::AuthHiddenService(extension)) => {
                        let client_cookie = &extension.client_cookie;

                        let field_number = crate::auth_hidden_service::OpenChannel::CLIENT_COOKIE_FIELD_NUMBER;

                        open_channel.mut_unknown_fields().add_length_delimited(field_number, client_cookie.into());
                    },
                    None => (),
                }
                pb.open_channel = Some(open_channel).into();
            },
            Packet::ChannelResult(channel_result) => {
                let channel_identifier = Some(channel_result.channel_identifier as i32);
                let opened = Some(channel_result.opened);
                let common_error = &channel_result.common_error;
                let common_error = if let Some(common_error) = common_error {
                    let common_error = match common_error {
                        CommonError::GenericError => protos::ControlChannel::channel_result::CommonError::GenericError,
                        CommonError::UnknownTypeError => protos::ControlChannel::channel_result::CommonError::UnknownTypeError,
                        CommonError::UnauthorizedError => protos::ControlChannel::channel_result::CommonError::UnauthorizedError,
                        CommonError::BadUsageError => protos::ControlChannel::channel_result::CommonError::BadUsageError,
                        CommonError::FailedError => protos::ControlChannel::channel_result::CommonError::FailedError,
                    };
                    Some(protobuf::EnumOrUnknown::new(common_error))
                } else {
                    None
                };
                let extension = channel_result.extension();

                // construct ChannelResult packet
                let mut channel_result = protos::ControlChannel::ChannelResult{channel_identifier, opened, common_error, ..Default::default()};

                match extension {
                    Some(ChannelResultExtension::ContactRequestChannel(extension)) => {
                        let status = &extension.response.status;
                        let status = match status {
                            crate::contact_request_channel::Status::Undefined => protos::ContactRequestChannel::response::Status::Undefined,
                            crate::contact_request_channel::Status::Pending => protos::ContactRequestChannel::response::Status::Pending,
                            crate::contact_request_channel::Status::Accepted => protos::ContactRequestChannel::response::Status::Accepted,
                            crate::contact_request_channel::Status::Rejected => protos::ContactRequestChannel::response::Status::Rejected,
                            crate::contact_request_channel::Status::Error => protos::ContactRequestChannel::response::Status::Error,
                        };
                        let status = Some(protobuf::EnumOrUnknown::new(status));

                        let response = protos::ContactRequestChannel::Response{status, ..Default::default()};

                        let field_number = crate::contact_request_channel::ChannelResult::RESPONSE_FIELD_NUMBER;

                        channel_result.mut_unknown_fields().add_length_delimited(field_number, response.write_to_bytes().unwrap());
                    },
                    Some(ChannelResultExtension::AuthHiddenService(extension)) => {
                        let server_cookie = &extension.server_cookie;

                        let field_number = crate::auth_hidden_service::ChannelResult::SERVER_COOKIE_FIELD_NUMBER;

                        channel_result.mut_unknown_fields().add_length_delimited(field_number, server_cookie.into());
                    },
                    None => (),
                }
                pb.channel_result = Some(channel_result).into();
            },
        }

        // serialise
        pb.write_to_vec(v).map_err(Error::ProtobufError)?;
        Ok(())
    }
}

impl TryFrom<&[u8]> for Packet {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        use protobuf::Message;
        use crate::v3::protos;

        // parse bytes into protobuf message
        let pb = protos::ControlChannel::Packet::parse_from_bytes(value).map_err(Self::Error::ProtobufError)?;

        let open_channel = pb.open_channel.into_option();
        let channel_result = pb.channel_result.into_option();
        let keep_alive = pb.keep_alive.into_option();
        let enable_features = pb.enable_features.into_option();
        let features_enabled = pb.features_enabled.into_option();

        match (open_channel, channel_result, keep_alive, enable_features, features_enabled) {
            (Some(open_channel), None, None, None, None) => {
                // base fields
                let channel_identifier = open_channel.channel_identifier.ok_or(Self::Error::InvalidProtobufMessage)?;
                let channel_type = open_channel.channel_type.as_ref().ok_or(Self::Error::InvalidProtobufMessage)?;
                let channel_type: ChannelType = channel_type.as_str().try_into()?;

                // extension fields
                let contact_request = protos::ContactRequestChannel::exts::contact_request.get(&open_channel);
                let client_cookie = protos::AuthHiddenService::exts::client_cookie.get(&open_channel);

                let extension: Option<OpenChannelExtension> = match channel_type {
                    // contact request channel open channel
                    ChannelType::ContactRequest => {
                        let mut contact_request = contact_request.ok_or(Self::Error::InvalidProtobufMessage)?;
                        if client_cookie.is_some() {
                            return Err(Self::Error::InvalidProtobufMessage);
                        }

                        let nickname = contact_request.take_nickname();
                        let nickname: crate::contact_request_channel::Nickname = nickname.try_into()?;

                        let message_text = contact_request.take_message_text();
                        let message_text: crate::contact_request_channel::MessageText = message_text.try_into()?;

                        let contact_request = crate::contact_request_channel::ContactRequest{nickname, message_text};

                        Some(OpenChannelExtension::ContactRequestChannel(crate::contact_request_channel::OpenChannel{contact_request}))
                    },
                    // auth hidden service open channel
                    ChannelType::AuthHiddenService => {
                        if contact_request.is_some() {
                            return Err(Self::Error::InvalidProtobufMessage);
                        }
                        let client_cookie = client_cookie.ok_or(Self::Error::InvalidProtobufMessage)?;

                        let client_cookie: [u8; crate::auth_hidden_service::CLIENT_COOKIE_SIZE] = match client_cookie.try_into() {
                            Ok(client_cookie) => client_cookie,
                            Err(_) => return Err(Self::Error::InvalidProtobufMessage),
                        };

                        Some(OpenChannelExtension::AuthHiddenService(crate::auth_hidden_service::OpenChannel{client_cookie}))
                    },
                    _ => None,
                };

                let open_channel = OpenChannel::new(channel_identifier, channel_type, extension)?;
                Ok(Packet::OpenChannel(open_channel))
            },
            (None, Some(channel_result), None, None, None) => {
                // base fields
                let channel_identifier = channel_result.channel_identifier.ok_or(Self::Error::InvalidProtobufMessage)?;

                let opened = channel_result.opened.ok_or(Self::Error::InvalidProtobufMessage)?;

                let common_error = if let Some(common_error) = channel_result.common_error {
                    let common_error = match common_error.value() {
                        0 => CommonError::GenericError,
                        1 => CommonError::UnknownTypeError,
                        2 => CommonError::UnauthorizedError,
                        3 => CommonError::BadUsageError,
                        4 => CommonError::FailedError,
                        _ => return Err(Self::Error::InvalidProtobufMessage),
                    };
                    Some(common_error)
                } else {
                    None
                };

                // extension fields
                let response = protos::ContactRequestChannel::exts::response.get(&channel_result);
                let server_cookie = protos::AuthHiddenService::exts::server_cookie.get(&channel_result);

                let extension: Option<ChannelResultExtension> = match (response, server_cookie) {
                    // contact request channel channel result
                    (Some(response), None) => {
                        let status = response.status.ok_or(Self::Error::InvalidProtobufMessage)?;
                        use crate::v3::message::contact_request_channel::Status;
                        let status = match status.value() {
                            0 => Status::Undefined,
                            1 => Status::Pending,
                            2 => Status::Accepted,
                            3 => Status::Rejected,
                            4 => Status::Error,
                            _ => return Err(Self::Error::InvalidProtobufMessage),
                        };

                        let response = crate::contact_request_channel::Response{status};
                        Some(ChannelResultExtension::ContactRequestChannel(crate::contact_request_channel::ChannelResult{response}))
                    },
                    // auth hidden service channel result
                    (None, Some(server_cookie)) => {
                        let server_cookie: [u8; crate::auth_hidden_service::SERVER_COOKIE_SIZE] = match server_cookie.try_into() {
                            Ok(server_cookie) => server_cookie,
                            Err(_) => return Err(Self::Error::InvalidProtobufMessage),
                        };

                        Some(ChannelResultExtension::AuthHiddenService(crate::auth_hidden_service::ChannelResult{server_cookie}))
                    },
                    (None, None) => None,
                    _ => return Err(Self::Error::InvalidProtobufMessage),
                };

                let channel_result = ChannelResult::new(channel_identifier, opened, common_error, extension)?;
                Ok(Packet::ChannelResult(channel_result))
            },
            _ => Err(Self::Error::InvalidProtobufMessage),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct OpenChannel {
    // TODO: spec needs updating, channel_identifier must be positive and non-zero, and less than or equal to u16::MAX
    channel_identifier: u16,
    channel_type: ChannelType,
    extension: Option<OpenChannelExtension>,
}

impl OpenChannel {
    pub fn new(
        channel_identifier: i32,
        channel_type: ChannelType,
        extension: Option<OpenChannelExtension>) -> Result<Self, Error> {
        if channel_identifier < 1 ||
           channel_identifier > u16::MAX as i32 {
            Err(Error::PacketConstructionFailed("channel_identifier must be postive, non-zero, and less than u16::MAX".to_string()))
        } else {
            let channel_identifier = channel_identifier as u16;
            Ok(Self{channel_identifier, channel_type, extension})
        }
    }

    pub fn channel_identifier(&self) -> u16 {
        self.channel_identifier
    }

    pub fn channel_type(&self) -> &ChannelType {
        &self.channel_type
    }

    pub fn extension(&self) -> &Option<OpenChannelExtension> {
        &self.extension
    }
}


#[derive(Debug, PartialEq)]
pub enum ChannelType {
    Chat,
    ContactRequest,
    AuthHiddenService,
    FileTransfer,
}

impl TryFrom<&str> for ChannelType {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let channel_type = match value {
            crate::chat_channel::CHANNEL_TYPE => ChannelType::Chat,
            crate::contact_request_channel::CHANNEL_TYPE => ChannelType::ContactRequest,
            crate::auth_hidden_service::CHANNEL_TYPE => ChannelType::AuthHiddenService,
            crate::file_channel::CHANNEL_TYPE => ChannelType::FileTransfer,
            _ => return Err(Self::Error::InvalidChannelType(value.to_string())),
        };
        Ok(channel_type)
    }
}


impl From<&ChannelType> for &'static str {
    fn from(value: &ChannelType) -> &'static str {
        match value {
            ChannelType::Chat => crate::chat_channel::CHANNEL_TYPE,
            ChannelType::ContactRequest => crate::contact_request_channel::CHANNEL_TYPE,
            ChannelType::AuthHiddenService => crate::auth_hidden_service::CHANNEL_TYPE,
            ChannelType::FileTransfer => crate::file_channel::CHANNEL_TYPE,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum OpenChannelExtension {
    ContactRequestChannel(crate::contact_request_channel::OpenChannel),
    AuthHiddenService(crate::auth_hidden_service::OpenChannel),
}

#[derive(Debug, PartialEq)]
pub struct ChannelResult {
    // TODO: spec needs updating, channel_identifier must be positive and non-zero, and less than or equal to u16::MAX
    channel_identifier: u16,
    opened: bool,
    common_error: Option<CommonError>,
    extension: Option<ChannelResultExtension>,
}

impl ChannelResult {
    pub fn new(
        channel_identifier: i32,
        opened: bool,
        common_error: Option<CommonError>,
        extension: Option<ChannelResultExtension>) -> Result<Self, Error> {
        if channel_identifier < 1 ||
           channel_identifier > u16::MAX as i32 {
            Err(Error::PacketConstructionFailed("channel_identifier must be postive, non-zero, and less than or equal to u16::MAX".to_string()))
        } else {
            let channel_identifier = channel_identifier as u16;
            Ok(Self{channel_identifier, opened, common_error, extension})
        }
    }

    pub fn channel_identifier(&self) -> u16 {
        self.channel_identifier
    }

    pub fn opened(&self) -> bool {
        self.opened
    }

    pub fn common_error(&self) -> &Option<CommonError> {
        &self.common_error
    }

    pub fn extension(&self) -> &Option<ChannelResultExtension> {
        &self.extension
    }
}

#[derive(Debug, PartialEq)]
pub enum ChannelResultExtension {
    ContactRequestChannel(crate::contact_request_channel::ChannelResult),
    AuthHiddenService(crate::auth_hidden_service::ChannelResult),
}

#[derive(Debug, PartialEq)]
pub enum CommonError {
    GenericError,
    UnknownTypeError,
    UnauthorizedError,
    BadUsageError,
    FailedError,
}

#[derive(Debug, PartialEq)]
pub struct KeepAlive {
    response_requested: bool,
}

#[derive(Debug, PartialEq)]
pub struct EnableFeatures {
    feature: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub struct FeaturesEnabled {
    feature: Vec<String>,
}
