// std
use std::cmp::Ord;
use std::collections::{BTreeMap, BTreeSet};

// extern
use rand::{TryRngCore, rngs::OsRng};
use tor_interface::tor_crypto::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, V3OnionServiceId};

//
use crate::v3::message::*;

//
// Ricochet-Refresh Protocol Packet
//
#[derive(Debug, PartialEq)]
pub enum Packet {
    // sent by client to begin Ricochet-Refresh handshake
    IntroductionPacket(introduction::IntroductionPacket),
    // server reply indicating introduction success or failure
    IntroductionResponsePacket(introduction::IntroductionResponsePacket),
    // used to open various channel types
    ControlChannelPacket(control_channel::Packet),
    // used to close a channel
    CloseChannelPacket{channel: u16},
    // used to accept/reject contact requests
    ContactRequestChannelPacket{
        channel: u16,
        packet: contact_request_channel::Packet,
    },
    // used to send/ack messages
    ChatChannelPacket{
        channel: u16,
        packet: chat_channel::Packet,
    },
    // used to authenticate connecting clients
    AuthHiddenServicePacket{
        channel: u16,
        packet: auth_hidden_service::Packet,
    },
    // used to send file attachments
    FileChannelPacket{
        channel: u16,
        packet: file_channel::Packet,
    },
}

impl Packet {
    pub fn write_to_vec(&self, v:& mut Vec<u8>) -> Result<(), crate::Error> {
        match self {
            Packet::IntroductionPacket(packet) => packet.write_to_vec(v)?,
            Packet::IntroductionResponsePacket(packet) => packet.write_to_vec(v)?,
            packet => {
                let packet_begin = v.len();

                let header_begin = packet_begin;
                let size_hi = header_begin + 0usize;
                let size_lo = header_begin + 1usize;
                let channel_hi = header_begin + 2usize;
                let channel_lo = header_begin + 3usize;

                let header_size = 4usize;

                v.resize(v.len() + header_size, 0xffu8);

                let data_begin = v.len();
                let channel = match packet {
                    Packet::IntroductionPacket(_) |
                    Packet::IntroductionResponsePacket(_) => unreachable!(),
                    Packet::ControlChannelPacket(packet) => {
                        packet.write_to_vec(v)?;
                        0u16
                    },
                    Packet::CloseChannelPacket{channel} => {
                        *channel
                    },
                    Packet::ContactRequestChannelPacket{channel, packet} => {
                        packet.write_to_vec(v)?;
                        *channel
                    },
                    Packet::ChatChannelPacket{channel, packet} => {
                        packet.write_to_vec(v)?;
                        *channel
                    },
                    Packet::AuthHiddenServicePacket{channel, packet} => {
                        packet.write_to_vec(v)?;
                        *channel
                    },
                    Packet::FileChannelPacket{channel, packet} => {
                        packet.write_to_vec(v)?;
                        *channel
                    },
                };
                let data_end = v.len();
                let data_size = data_end - data_begin;
                let packet_size = header_size + data_size;
                assert!(packet_size <= u16::MAX as usize);
                let size = (packet_size & 0xffffusize) as u16;

                v[size_hi] = ((size & 0xff00u16) >> 8) as u8;
                v[size_lo] = (size & 0xffu16) as u8;
                v[channel_hi] = ((channel & 0xff00u16) >> 8) as u8;
                v[channel_lo] = (channel & 0xffu16) as u8;
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum ChannelData {
    Control,
    IncomingChat,
    OutgoingChat,
    IncomingContactRequest,
    OutgoingContactRequest,
    IncomingAuthHiddenService{
        client_cookie: [u8; auth_hidden_service::CLIENT_COOKIE_SIZE],
        server_cookie: [u8; auth_hidden_service::SERVER_COOKIE_SIZE],
    },
    OutgoingAuthHiddenService{
        client_cookie: [u8; auth_hidden_service::CLIENT_COOKIE_SIZE],
    },
    IncomingFileTransfer,
    OutgoingFileTransfer,
}
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ChannelDataType {
    Control,
    IncomingChat,
    OutgoingChat,
    IncomingContactRequest,
    OutgoingContactRequest,
    IncomingAuthHiddenService,
    OutgoingAuthHiddenService,
    IncomingFileTransfer,
    OutgoingFileTransfer,
}

impl From<&ChannelData> for ChannelDataType {
    fn from(channel_data: &ChannelData) -> ChannelDataType {
        match channel_data {
            ChannelData::Control => ChannelDataType::Control,
            ChannelData::IncomingChat => ChannelDataType::IncomingChat,
            ChannelData::OutgoingChat => ChannelDataType::OutgoingChat,
            ChannelData::IncomingContactRequest => ChannelDataType::IncomingContactRequest,
            ChannelData::OutgoingContactRequest => ChannelDataType::OutgoingContactRequest,
            ChannelData::IncomingAuthHiddenService{..} => ChannelDataType::IncomingAuthHiddenService,
            ChannelData::OutgoingAuthHiddenService{..} => ChannelDataType::OutgoingAuthHiddenService,
            ChannelData::IncomingFileTransfer => ChannelDataType::IncomingFileTransfer,
            ChannelData::OutgoingFileTransfer => ChannelDataType::OutgoingFileTransfer,
        }
    }
}


#[derive(Default)]
struct ChannelMap {
    type_to_id: BTreeMap<ChannelDataType, u16>,
    id_to_channel: BTreeMap<u16, ChannelData>,
}

impl ChannelMap {
    pub fn is_empty(&self) -> bool {
        self.id_to_channel.is_empty()
    }

    pub fn contains(&self, channel_id: &u16) -> bool {
        self.id_to_channel.contains_key(channel_id)
    }

    pub fn channel_type_to_id(
        &self,
        channel_type: &ChannelDataType) -> Option<u16> {
        if let Some(id) = self.type_to_id.get(channel_type) {
            Some(*id)
        } else {
            None
        }
    }

    pub fn channel_id_to_type(
        &self,
        channel_id: &u16) -> Option<ChannelDataType> {
        match self.id_to_channel.get(channel_id) {
            Some(channel) => Some(channel.into()),
            None => None,
        }
    }

    pub fn insert(
        &mut self,
        channel_id: u16,
        channel_data: ChannelData) -> Result<(), Error> {

        let channel_type: ChannelDataType = (&channel_data).into();

        if self.id_to_channel.contains_key(&channel_id) {
            Err(Error::ChannelAlreadyOpen(channel_id))
        } else if self.type_to_id.contains_key(&channel_type) {
            Err(Error::ChannelTypeAlreadyOpen(channel_type))
        } else {
            self.type_to_id.insert(channel_type, channel_id);
            self.id_to_channel.insert(channel_id, channel_data);
            Ok(())
        }
    }

    pub fn get_by_id(
        &self,
        channel_id: &u16) -> Option<&ChannelData> {
        self.id_to_channel.get(channel_id)
    }

    pub fn get_by_id_mut(
        &mut self,
        channel_id: &u16) -> Option<&mut ChannelData> {
        self.id_to_channel.get_mut(channel_id)
    }

    pub fn get_by_type(
        &self,
        channel_type: &ChannelDataType) -> Option<&ChannelData> {
        if let Some(id)  = self.type_to_id.get(channel_type) {
            let channel = self.id_to_channel.get(id).expect("ChannelMap corrupted");
            Some(channel)
        } else {
            None
        }
    }

    pub fn get_by_type_mut(
        &mut self,
        channel_type: &ChannelDataType) -> Option<&ChannelData> {
        if let Some(id)  = self.type_to_id.get(channel_type) {
            let channel = self.id_to_channel.get_mut(id).expect("ChannelMap corrupted");
            Some(channel)
        } else {
            None
        }
    }

    pub fn remove_by_id(
        &mut self,
        channel_id: &u16) -> Option<ChannelData> {
        if let Some(channel) = self.id_to_channel.remove(channel_id) {
            let channel_type: ChannelDataType = (&channel).into();
            self.type_to_id.remove(&channel_type).expect("ChannelMap corrupted");
            Some(channel)
        } else {
            None
        }
    }
}

#[derive(Debug, PartialEq)]
enum Direction {
    Incoming,
    Outgoing,
}

struct Connection {
    channel_map: ChannelMap,
    direction: Direction,
    peer_service_id: Option<V3OnionServiceId>,
    contact_request_message: Option<contact_request_channel::MessageText>,
    next_outgoing_channel_id: u16,
    sent_message_counter: u64,
}

impl Connection {
    pub fn new_incoming() -> Self {
        Self {
            channel_map: Default::default(),
            direction: Direction::Incoming,
            peer_service_id: None,
            contact_request_message: None,
            next_outgoing_channel_id: 2,
            sent_message_counter: 0u64,
        }
    }

    pub fn new_outgoing(
        service_id: V3OnionServiceId,
        message: Option<contact_request_channel::MessageText>) -> Self {
        Self {
            channel_map: Default::default(),
            direction: Direction::Outgoing,
            peer_service_id: Some(service_id),
            contact_request_message: message,
            next_outgoing_channel_id: 1,
            sent_message_counter: 0u64,
        }
    }

    pub fn next_channel_id(&mut self) -> u16 {
        loop {
            let result = self.next_outgoing_channel_id;
            let next = ((self.next_outgoing_channel_id as u32 + 2u32) % (u16::MAX as u32)) as u16;
            self.next_outgoing_channel_id = next;
            if self.channel_map.contains(&result) {
                continue;
            }
            return result;
        }
    }
}

pub type ConnectionHandle = u32;
pub const INVALID_CONNECTION_HANDLE: ConnectionHandle = 0xffffffffu32;

pub type MessageId = u64;

pub enum Event {
    IntroductionReceived,
    IntroductionResponseReceived,
    OpenChannelAuthHiddenServiceReceived,
    ClientAuthenticated{
        service_id: V3OnionServiceId,
    },
    HostAuthenticated{
        service_id: V3OnionServiceId,
    },
    ContactRequestReceived{
        service_id: V3OnionServiceId,
        nickname: String,
        message_text: String,
    },
    ContactRequestResultPending{
        service_id: V3OnionServiceId,
    },
    ContactRequestResultAccepted{
        service_id: V3OnionServiceId,
    },
    IncomingChatChannelOpened{
        service_id: V3OnionServiceId,
    },
    IncomingFileTransferChannelOpened{
        service_id: V3OnionServiceId,
    },
    OutgoingAuthHiddenServiceChannelOpened{
        service_id: V3OnionServiceId,
    },
    OutgoingChatChannelOpened{
        service_id: V3OnionServiceId,
    },
    OutgoingFileTransferChannelOpened{
        service_id: V3OnionServiceId,
    },
    ChatMessageReceived{
        service_id: V3OnionServiceId,
        message_text: String,
        message_id: MessageId,
        time_delta: std::time::Duration,
    },
    ChatAcknowledgeReceived{
        service_id: V3OnionServiceId,
        message_id: MessageId,
        accepted: bool,
    },
    ChannelClosed{
        id: u16,
        data: ChannelData
    },
    ProtocolFailure{
        message: String
    },
    FatalProtocolFailure,
}

pub struct PacketHandler {
    next_connection_handle: ConnectionHandle,
    connections: BTreeMap<ConnectionHandle, Connection>,
    service_id_to_connection_handle: BTreeMap<V3OnionServiceId, ConnectionHandle>,
    // our service id
    private_key: Ed25519PrivateKey,
    service_id: V3OnionServiceId,
    // set of approved contacts
    contacts: BTreeSet<V3OnionServiceId>,
    // set of blocked contacts
    blocked: BTreeSet<V3OnionServiceId>
}


impl PacketHandler {
    pub fn new(private_key: Ed25519PrivateKey) -> Self {

        let service_id = V3OnionServiceId::from_private_key(&private_key);
        Self {
            next_connection_handle: Default::default(),
            connections: Default::default(),
            service_id_to_connection_handle: Default::default(),
            private_key,
            service_id,
            contacts: Default::default(),
            blocked: Default::default(),
        }
    }

    // On successful packet read returns a (packet, bytes read) tuple
    // If needs more bytes, returns Ok(None)
    // Consumers must drop the returned number of bytes from the start of their
    // read buffer
    pub fn try_parse_packet(
        &self,
        connection_handle: ConnectionHandle,
        bytes: &[u8]) -> Result<(Packet, usize), Error> {

        let connection = self.connections.get(&connection_handle).ok_or(Error::TargetConnectionDoesNotExist(connection_handle))?;
        let channel_map = &connection.channel_map;

        if channel_map.is_empty() {
            match TryInto::<introduction::IntroductionPacket>::try_into(bytes) {
                Ok(packet) => {
                    let offset = 3 + packet.versions().len();
                    return Ok((Packet::IntroductionPacket(packet), offset));
                },
                Err(Error::NeedMoreBytes) => return Err(Error::NeedMoreBytes),
                _ => (),
            }

            match TryInto::<introduction::IntroductionResponsePacket>::try_into(bytes) {
                Ok(packet) => {
                    let offset = 1;
                    return Ok((Packet::IntroductionResponsePacket(packet), offset));
                },
                Err(Error::NeedMoreBytes) => return Err(Error::NeedMoreBytes),
                _ => (),
            }

            return Err(Error::BadDataStream);
        } else {
            if bytes.len() >= 4 {
                // size is encoded as big-endian u16
                let size: u16 = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
                let size = size as usize;
                // channel id is encoded as big-endian u16
                let channel: u16 = ((bytes[2] as u16) << 8) | (bytes[3] as u16);

                // size must be at least
                if size < 4 {
                    Err(Error::BadDataStream)
                } else if bytes.len() < size {
                    Err(Error::NeedMoreBytes)
                } else if size == 4 {
                    Ok((Packet::CloseChannelPacket{channel}, 4))
                } else {
                    let bytes = &bytes[4..size];
                    let packet = match channel_map.get_by_id(&channel) {
                        Some(ChannelData::Control) => {
                            let packet = control_channel::Packet::try_from(bytes)?;
                            Packet::ControlChannelPacket(packet)
                        },
                        Some(ChannelData::IncomingChat) |
                        Some(ChannelData::OutgoingChat) => {
                            let packet = chat_channel::Packet::try_from(bytes)?;
                            Packet::ChatChannelPacket{channel, packet}
                        },
                        Some(ChannelData::IncomingContactRequest) => return Err(Error::BadDataStream),
                        Some(ChannelData::OutgoingContactRequest) => {
                            let packet = contact_request_channel::Packet::try_from(bytes)?;
                            Packet::ContactRequestChannelPacket{channel, packet}
                        },
                        Some(ChannelData::IncomingAuthHiddenService{..}) |
                        Some(ChannelData::OutgoingAuthHiddenService{..}) => {
                            let packet = auth_hidden_service::Packet::try_from(bytes)?;
                            Packet::AuthHiddenServicePacket{channel, packet}
                        },
                        Some(ChannelData::IncomingFileTransfer) |
                        Some(ChannelData::OutgoingFileTransfer) => {
                            let packet = file_channel::Packet::try_from(bytes)?;
                            Packet::FileChannelPacket{channel, packet}
                        },
                        None => return Err(Error::TargetChannelDoesNotExist(channel)),
                    };
                    Ok((packet, size))
                }
            } else {
                Err(Error::NeedMoreBytes)
            }
        }
    }

    // Handle a received packet and returns an event which needs to be handled by
    // the caller
    pub fn handle_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        packet: Packet,
        replies: &mut Vec<Packet>) -> Result<Event, Error> {

        match packet {
            Packet::IntroductionPacket(packet) => self.handle_introduction_packet(connection_handle, packet, replies),
            Packet::IntroductionResponsePacket(packet) => self.handle_introduction_response_packet(connection_handle, packet, replies),
            Packet::ControlChannelPacket(packet) => self.handle_control_channel_packet(connection_handle, packet, replies),
            Packet::CloseChannelPacket{channel} => self.handle_close_channel_packet(connection_handle, channel, replies),
            Packet::ContactRequestChannelPacket{channel, packet} => self.handle_contact_request_channel_packet(connection_handle, channel, packet, replies),
            Packet::ChatChannelPacket{channel, packet} => self.handle_chat_channel_packet(connection_handle, channel, packet, replies),
            Packet::AuthHiddenServicePacket{channel, packet} => self.handle_auth_hidden_service_packet(connection_handle, channel, packet, replies),
            Packet::FileChannelPacket{channel, packet} => self.handle_file_channel_packet(connection_handle, channel, packet, replies),
        }
    }

    pub fn accept_contact_request(
        &mut self,
        service_id: V3OnionServiceId,
        replies: &mut Vec<Packet>) -> Result<ConnectionHandle, Error> {
        if self.contacts.contains(&service_id) {
            return Err(Error::PeerAlreadyAcceptedContact(service_id));
        } else if self.blocked.contains(&service_id) {
            return Err(Error::PeerIsBlocked(service_id));
        }

        if let Some(connection_handle) = self.service_id_to_connection_handle.get(&service_id) {
            if let Some(connection) = self.connections.get_mut(&connection_handle) {
                let channel_identifier = if let Some(channel_identifier) = connection.channel_map.channel_type_to_id(&ChannelDataType::IncomingContactRequest) {
                    channel_identifier
                } else {
                    return Err(Error::NotImplemented);
                };

                let mut pending_replies: Vec<Packet> = Vec::with_capacity(3);

                use contact_request_channel::{Response, Status};
                let channel = channel_identifier;
                let response = Response{status: Status::Accepted};
                let packet = contact_request_channel::Packet::Response(response);
                let reply = Packet::ContactRequestChannelPacket{channel, packet};
                pending_replies.push(reply);

                let reply = Packet::CloseChannelPacket{channel};
                pending_replies.push(reply);

                // build chat channel open packet
                let channel_id = connection.next_channel_id();
                let open_channel = control_channel::OpenChannel::new(
                    channel_id as i32,
                    control_channel::ChannelType::Chat,
                    None).expect("OpenChannel creation failed");
                let packet = control_channel::Packet::OpenChannel(open_channel);
                let reply = Packet::ControlChannelPacket(packet);
                pending_replies.push(reply);
                connection.channel_map.insert(channel_id, ChannelData::OutgoingChat)?;

                // build file transfer channel open packet
                let channel_id = connection.next_channel_id();
                let open_channel = control_channel::OpenChannel::new(
                    channel_id as i32,
                    control_channel::ChannelType::FileTransfer,
                    None).expect("OpenChannel creation failed");
                let packet = control_channel::Packet::OpenChannel(open_channel);
                let reply = Packet::ControlChannelPacket(packet);
                pending_replies.push(reply);
                connection.channel_map.insert(channel_id, ChannelData::OutgoingFileTransfer)?;

                connection.channel_map.remove_by_id(&channel_identifier);
                self.contacts.insert(service_id);
                replies.append(&mut pending_replies);
                return Ok(*connection_handle)
            }
        }

         Err(Error::NotImplemented)
    }

    pub fn send_message(
        &mut self,
        service_id: V3OnionServiceId,
        message_text: chat_channel::MessageText,
        replies: &mut Vec<Packet>) -> Result<(ConnectionHandle, MessageId), crate::Error> {

        if let Some(connection_handle) = self.service_id_to_connection_handle.get(&service_id) {
            let connection_handle = *connection_handle;
            if let Some(connection) = self.connections.get_mut(&connection_handle) {
                if let Some(channel) = connection.channel_map.channel_type_to_id(&ChannelDataType::OutgoingChat) {
                    // get this message's id
                    let message_id = (connection.sent_message_counter & (MessageId::MAX as u64)) as MessageId;
                    // and increment counter
                    connection.sent_message_counter = connection.sent_message_counter + 1;

                    let chat_message = chat_channel::ChatMessage::new(message_text, message_id as u32, None)?;
                    let packet = chat_channel::Packet::ChatMessage(chat_message);
                    let reply = Packet::ChatChannelPacket{channel, packet};
                    replies.push(reply);

                    return Ok((connection_handle, message_id));
                }
            }
        }
        Err(Error::NotImplemented)
    }

    fn connection(
        &self,
        connection_handle: ConnectionHandle) -> Result<&Connection, Error> {
        self.connections
            .get(&connection_handle)
            .ok_or(Error::TargetConnectionDoesNotExist(connection_handle))
    }

    fn connection_mut(
        &mut self,
        connection_handle: ConnectionHandle) -> Result<&mut Connection, Error> {
        self.connections
            .get_mut(&connection_handle)
            .ok_or(Error::TargetConnectionDoesNotExist(connection_handle))
    }

    fn handle_introduction_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        packet: introduction::IntroductionPacket,
        replies: &mut Vec<Packet>) -> Result<Event, Error> {

        use introduction::*;

        let protocol_failure = {
            let connection = self.connection(connection_handle)?;

            // we should not be receiving an introduction packet if we already have channels
            !connection.channel_map.is_empty() ||
            // we should also only receive an introduction packet from a client
            connection.direction != Direction::Incoming
        };

        if protocol_failure {
            let _ = self.connections.remove(&connection_handle);
            Ok(Event::FatalProtocolFailure)
        } else {
            let version = if packet.versions().contains(&Version::RicochetRefresh3) {
                let connection = self.connection_mut(connection_handle)?;
                let _ = connection.channel_map.insert(0u16, ChannelData::Control);
                Some(Version::RicochetRefresh3)
            } else {
                // version not supported
                let _ = self.connections.remove(&connection_handle);
                None
            };

            let reply = Packet::IntroductionResponsePacket(IntroductionResponsePacket{version});
            replies.push(reply);
            Ok(Event::IntroductionReceived)
        }
    }

    fn handle_introduction_response_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        packet: introduction::IntroductionResponsePacket,
        replies: &mut Vec<Packet>) -> Result<Event, Error> {

        use introduction::*;

        let protocol_failure = {
            let connection = self.connection(connection_handle)?;

            // we should not be receiving an introduction response packet if we already have channels
            !connection.channel_map.is_empty() ||
            // we should only receive an introduction response packet from a server
            connection.direction != Direction::Outgoing
        };

        if protocol_failure {
            let _ = self.connections.remove(&connection_handle);
            Ok(Event::FatalProtocolFailure)
        } else {
            if let Some(Version::RicochetRefresh3) = packet.version {
                let connection = self.connection_mut(connection_handle)?;
                let _ = connection.channel_map.insert(0u16, ChannelData::Control);

                // construct AuthHiddenService OpenChannel packet
                let channel_id = connection.next_channel_id();

                let mut client_cookie: [u8; auth_hidden_service::CLIENT_COOKIE_SIZE] = Default::default();
                OsRng.try_fill_bytes(&mut client_cookie)
                    .map_err(Error::RandOsError)?;

                use crate::control_channel::{ChannelType, OpenChannel, OpenChannelExtension};

                let open_channel_extension = OpenChannelExtension::AuthHiddenService(auth_hidden_service::OpenChannel{client_cookie: client_cookie.clone()});

                let open_channel = OpenChannel::new(channel_id as i32, ChannelType::AuthHiddenService, Some(open_channel_extension))?;
                let packet = control_channel::Packet::OpenChannel(open_channel);
                let reply = Packet::ControlChannelPacket(packet);
                replies.push(reply);

                // save off channel state
                connection.channel_map.insert(channel_id, ChannelData::OutgoingAuthHiddenService{client_cookie})?;

                Ok(Event::IntroductionResponseReceived)
            } else {
                // version not supported
                let _ = self.connections.remove(&connection_handle);
                Ok(Event::FatalProtocolFailure)
            }
        }
    }

    fn handle_control_channel_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        packet: control_channel::Packet,
        replies: &mut Vec<Packet>) -> Result<Event, Error> {

        match packet {
            control_channel::Packet::OpenChannel(open_channel) => {
                let channel_identifier = open_channel.channel_identifier();
                let protocol_failure = {
                    let connection = self.connection(connection_handle)?;

                    // client-side may only open odd-numbered connections
                    (!(channel_identifier % 2u16 == 1u16 &&
                    connection.direction == Direction::Incoming) &&
                    // server-side may only open even-numbered connections
                    !(channel_identifier % 2u16 == 0u16 &&
                    connection.direction == Direction::Outgoing)) ||
                    // requested channel already open
                    connection.channel_map.get_by_id(&channel_identifier).is_some()
                };
                if protocol_failure {
                    let _ = self.connections.remove(&connection_handle);
                    return Ok(Event::FatalProtocolFailure)
                }

                use control_channel::{ChannelResultExtension, ChannelResult, ChannelType, OpenChannelExtension};
                match (open_channel.channel_type(), open_channel.extension()) {
                    // IncomingAuthHiddenService
                    (ChannelType::AuthHiddenService, Some(OpenChannelExtension::AuthHiddenService(extension))) => {

                        // build ChannelResult packet
                        let mut server_cookie: [u8; auth_hidden_service::SERVER_COOKIE_SIZE] = Default::default();
                        OsRng.try_fill_bytes(&mut server_cookie)
                            .map_err(Error::RandOsError)?;
                        let channel_result_extension = ChannelResultExtension::AuthHiddenService(auth_hidden_service::ChannelResult{server_cookie: server_cookie.clone()});

                        // save off channel state
                        let client_cookie = extension.client_cookie;
                        let connection = self.connection_mut(connection_handle)?;
                        connection.channel_map.insert(channel_identifier, ChannelData::IncomingAuthHiddenService{client_cookie, server_cookie})?;

                        // buld reply packet
                        let channel_result = ChannelResult::new(
                            channel_identifier as i32,
                            true,
                            None,
                            Some(channel_result_extension))?;
                        let packet = control_channel::Packet::ChannelResult(channel_result);
                        let reply = Packet::ControlChannelPacket(packet);
                        replies.push(reply);

                        Ok(Event::OpenChannelAuthHiddenServiceReceived)
                    },
                    // ContactRequest
                    (ChannelType::ContactRequest, Some(OpenChannelExtension::ContactRequestChannel(extension))) => {
                        let connection = self.connection_mut(connection_handle)?;
                        if let Some(service_id) = &connection.peer_service_id {
                            connection.channel_map.insert(channel_identifier, ChannelData::IncomingContactRequest)?;

                            use control_channel::ChannelResultExtension;
                            use contact_request_channel::{Response, Status};
                            let channel_result_extension = ChannelResultExtension::ContactRequestChannel(contact_request_channel::ChannelResult{response: Response{status: Status::Pending}});

                            let channel_result = control_channel::ChannelResult::new(
                                channel_identifier as i32,
                                true,
                                None,
                                Some(channel_result_extension))?;
                            let packet = control_channel::Packet::ChannelResult(channel_result);
                            let reply = Packet::ControlChannelPacket(packet);
                            replies.push(reply);

                            Ok(Event::ContactRequestReceived{
                                service_id: service_id.clone(),
                                nickname: (&extension.contact_request.nickname).into(),
                                message_text: (&extension.contact_request.message_text).into(),
                            })
                        } else {
                            Ok(Event::FatalProtocolFailure)
                        }
                    },
                    // Chat
                    (ChannelType::Chat, None) => {
                        // verify peer is authorised and a contact
                        let connection = self.connection(connection_handle)?;
                        let service_id = if let Some(service_id) = &connection.peer_service_id {
                            if !self.contacts.contains(service_id) {
                                return Ok(Event::FatalProtocolFailure)
                            } else {
                                service_id.clone()
                            }
                        } else {
                            return Ok(Event::FatalProtocolFailure)
                        };

                        let connection = self.connection_mut(connection_handle)?;
                        connection.channel_map.insert(channel_identifier, ChannelData::IncomingChat)?;

                        // buld reply packet
                        let channel_result = ChannelResult::new(
                            channel_identifier as i32,
                            true,
                            None,
                            None)?;
                        let packet = control_channel::Packet::ChannelResult(channel_result);
                        let reply = Packet::ControlChannelPacket(packet);
                        replies.push(reply);
                        Ok(Event::IncomingChatChannelOpened{service_id})
                    }
                    // FileTransfer
                    (ChannelType::FileTransfer, None) => {
                        // verify peer is authorised and a contact
                        let connection = self.connection(connection_handle)?;
                        let service_id = if let Some(service_id) = &connection.peer_service_id {
                            if !self.contacts.contains(service_id) {
                                return Ok(Event::FatalProtocolFailure)
                            } else {
                                service_id.clone()
                            }
                        } else {
                            return Ok(Event::FatalProtocolFailure)
                        };

                        let connection = self.connection_mut(connection_handle)?;
                        connection.channel_map.insert(channel_identifier, ChannelData::IncomingFileTransfer)?;

                        // buld reply packet
                        let channel_result = ChannelResult::new(
                            channel_identifier as i32,
                            true,
                            None,
                            None)?;
                        let packet = control_channel::Packet::ChannelResult(channel_result);
                        let reply = Packet::ControlChannelPacket(packet);
                        replies.push(reply);
                        Ok(Event::IncomingFileTransferChannelOpened{service_id})
                    },
                    _ => Err(Error::NotImplemented)
                }
            },
            control_channel::Packet::ChannelResult(channel_result) => {
                let connection = self.connection(connection_handle)?;
                let channel_id = channel_result.channel_identifier();
                let channel_data = connection.channel_map.get_by_id(&channel_id);
                let channel_data = if let Some(channel_data) = channel_data {
                    channel_data
                } else {
                    return Ok(Event::ProtocolFailure{message:
                        format!("recived ChannelResult for channel which does not exist: {channel_id}")});
                };
                let service_id = &connection.peer_service_id;

                use control_channel::ChannelResultExtension;
                use auth_hidden_service::{ChannelResult, Proof};
                match (channel_data, service_id, channel_result.opened(), channel_result.common_error(), channel_result.extension()) {
                    (ChannelData::OutgoingAuthHiddenService{client_cookie}, Some(service_id), true, None, Some(ChannelResultExtension::AuthHiddenService(ChannelResult{server_cookie}))) => {
                        // construct proof

                        let client_service_id = &self.service_id;
                        let server_service_id = &service_id;

                        let message = Proof::message(
                            client_cookie,
                            server_cookie,
                            client_service_id,
                            server_service_id);

                        let signature = self.private_key.sign_message(&message);
                        let signature = signature.to_bytes();

                        let proof = Proof::new(signature, client_service_id.clone())?;
                        let packet = auth_hidden_service::Packet::Proof(proof);
                        let reply = Packet::AuthHiddenServicePacket{channel: channel_id, packet};

                        replies.push(reply);

                        Ok(Event::OutgoingAuthHiddenServiceChannelOpened{service_id: service_id.clone()})
                    },
                    (ChannelData::OutgoingContactRequest, Some(service_id), true, None, Some(ChannelResultExtension::ContactRequestChannel(contact_request_channel::ChannelResult{response}))) => {
                        use contact_request_channel::Status;
                        match response.status{
                            Status::Undefined => Err(Error::NotImplemented),
                            Status::Pending => Ok(Event::ContactRequestResultPending{service_id: service_id.clone()}),
                            Status::Accepted => Err(Error::NotImplemented),
                            Status::Rejected => Err(Error::NotImplemented),
                            Status::Error => Err(Error::NotImplemented),
                        }
                    },
                    (ChannelData::OutgoingChat, Some(service_id), true, None, None) => Ok(Event::OutgoingChatChannelOpened{service_id: service_id.clone()}),
                    (ChannelData::OutgoingFileTransfer, Some(service_id), true, None, None) => Ok(Event::OutgoingFileTransferChannelOpened{service_id: service_id.clone()}),
                    _ => Err(Error::NotImplemented),
                }
            }
        }
    }

    fn handle_close_channel_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        channel_id: u16,
        _replies: &mut Vec<Packet>) -> Result<Event, Error> {
        let connection = self.connection_mut(connection_handle)?;
        if let Some(data) = connection.channel_map.remove_by_id(&channel_id) {
            Ok(Event::ChannelClosed{id: channel_id, data})
        } else {
            Ok(Event::ProtocolFailure{message:
                format!("requested closing channel which does not exist: {channel_id}")})
        }
    }

    fn handle_contact_request_channel_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        channel_id: u16,
        packet: contact_request_channel::Packet,
        replies: &mut Vec<Packet>) -> Result<Event, Error> {

        match packet {
            contact_request_channel::Packet::Response(response) => {
                let connection = self.connection_mut(connection_handle)?;

                use contact_request_channel::Status;
                match (response.status, connection.peer_service_id.clone()) {
                    (Status::Accepted, Some(service_id)) => {
                        let mut pending_replies: Vec<Packet> = Vec::with_capacity(2);

                        // build chat channel open packet
                        let channel_id = connection.next_channel_id();
                        let open_channel = control_channel::OpenChannel::new(
                            channel_id as i32,
                            control_channel::ChannelType::Chat,
                            None).expect("OpenChannel creation failed");
                        let packet = control_channel::Packet::OpenChannel(open_channel);
                        let reply = Packet::ControlChannelPacket(packet);
                        pending_replies.push(reply);
                        connection.channel_map.insert(channel_id, ChannelData::OutgoingChat)?;

                        // build file transfer channel open packet
                        let channel_id = connection.next_channel_id();
                        let open_channel = control_channel::OpenChannel::new(
                            channel_id as i32,
                            control_channel::ChannelType::FileTransfer,
                            None).expect("OpenChannel creation failed");
                        let packet = control_channel::Packet::OpenChannel(open_channel);
                        let reply = Packet::ControlChannelPacket(packet);
                        pending_replies.push(reply);
                        connection.channel_map.insert(channel_id, ChannelData::OutgoingFileTransfer)?;

                        self.contacts.insert(service_id.clone());
                        replies.append(&mut pending_replies);
                        Ok(Event::ContactRequestResultAccepted{service_id})
                    }
                    _ => todo!(),
                }
            }
        }
    }

    fn handle_chat_channel_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        channel: u16,
        packet: chat_channel::Packet,
        replies: &mut Vec<Packet>) -> Result<Event, Error> {

        match packet {
            chat_channel::Packet::ChatMessage(message) => {
                let connection = self.connection(connection_handle)?;
                let service_id = if let Some(service_id) = &connection.peer_service_id {
                    if !self.contacts.contains(service_id) {
                        return Ok(Event::FatalProtocolFailure)
                    } else {
                        service_id.clone()
                    }
                } else {
                    return Ok(Event::FatalProtocolFailure)
                };

                let message_text: String = message.message_text().into();
                let message_id = message.message_id() as MessageId;
                let time_delta = if let Some(time_delta) = message.time_delta() {
                    *time_delta
                } else {
                    std::time::Duration::ZERO
                };

                // build ack reply
                let accepted = true;
                let acknowledge = chat_channel::ChatAcknowledge::new(message.message_id(), accepted)?;
                let packet = chat_channel::Packet::ChatAcknowledge(acknowledge);
                let reply = Packet::ChatChannelPacket{channel, packet};
                replies.push(reply);

                Ok(Event::ChatMessageReceived{service_id, message_text, message_id, time_delta})
            },
            chat_channel::Packet::ChatAcknowledge(acknowledge) => {
                let connection = self.connection(connection_handle)?;
                let service_id = if let Some(service_id) = &connection.peer_service_id {
                    if !self.contacts.contains(service_id) {
                        return Ok(Event::FatalProtocolFailure)
                    } else {
                        service_id.clone()
                    }
                } else {
                    return Ok(Event::FatalProtocolFailure)
                };
                let message_id = acknowledge.message_id() as MessageId;
                let accepted = acknowledge.accepted();
                Ok(Event::ChatAcknowledgeReceived{service_id, message_id, accepted})
            },
        }
    }

    fn handle_auth_hidden_service_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        channel: u16,
        packet: auth_hidden_service::Packet,
        replies: &mut Vec<Packet>) -> Result<Event, Error> {

        match packet {
            auth_hidden_service::Packet::Proof(proof) => {
                let protocol_failure = {
                    let connection = self.connection(connection_handle)?;

                    // only connecting clients should be sending a proof packet
                    connection.direction != Direction::Incoming ||
                    // channel has wrong data
                    match connection.channel_map.channel_id_to_type(&channel) {
                        Some(ChannelDataType::IncomingAuthHiddenService) => false,
                        _ => true
                    }
                };
                if protocol_failure {
                    let _ = self.connections.remove(&connection_handle);
                    return Ok(Event::FatalProtocolFailure)
                }

                let server_service_id = self.service_id.clone();

                let (client_cookie, server_cookie) = if let Some(ChannelData::IncomingAuthHiddenService{client_cookie, server_cookie}) = self.connection_mut(connection_handle)?.channel_map.remove_by_id(&channel) {
                    (client_cookie, server_cookie)
                } else {
                    return Ok(Event::FatalProtocolFailure)
                };

                let client_service_id = proof.service_id();

                let message = auth_hidden_service::Proof::message(
                    &client_cookie,
                    &server_cookie,
                    client_service_id,
                    &server_service_id);

                let signature = Ed25519Signature::from_raw(proof.signature()).expect("ed25519 signature creation should never fail");

                let client_public_key = Ed25519PublicKey::from_service_id(client_service_id).expect("v3 onion service id to ed25519 public key conversion should never fail");

                if signature.verify(&message, &client_public_key) {
                    let mut pending_replies: Vec<Packet> = Vec::with_capacity(3);

                    let connection = self.connection_mut(connection_handle)?;
                    connection.peer_service_id = Some(client_service_id.clone());

                    // build reply packet

                    let connection = self.connection(connection_handle)?;
                    let is_known_contact = self.contacts.contains(&client_service_id);
                    let result = auth_hidden_service::Result::new(true, Some(is_known_contact))?;
                    let packet = auth_hidden_service::Packet::Result(result);
                    let reply = Packet::AuthHiddenServicePacket{channel, packet};
                    pending_replies.push(reply);

                    if is_known_contact {
                        let connection = self.connection_mut(connection_handle)?;

                        // build chat channel open packet
                        let channel_id = connection.next_channel_id();
                        let open_channel = control_channel::OpenChannel::new(
                            channel_id as i32,
                            control_channel::ChannelType::Chat,
                            None).expect("OpenChannel creation failed");
                        let packet = control_channel::Packet::OpenChannel(open_channel);
                        let reply = Packet::ControlChannelPacket(packet);
                        pending_replies.push(reply);
                        connection.channel_map.insert(channel_id, ChannelData::OutgoingChat)?;

                        // build file transfer channel open packet
                        let channel_id = connection.next_channel_id();
                        let open_channel = control_channel::OpenChannel::new(
                            channel_id as i32,
                            control_channel::ChannelType::FileTransfer,
                            None).expect("OpenChannel creation failed");
                        let packet = control_channel::Packet::OpenChannel(open_channel);
                        let reply = Packet::ControlChannelPacket(packet);
                        pending_replies.push(reply);
                        connection.channel_map.insert(channel_id, ChannelData::OutgoingFileTransfer)?;
                    }

                    self.service_id_to_connection_handle.insert(client_service_id.clone(), connection_handle);
                    let service_id = client_service_id.clone();
                    replies.append(&mut pending_replies);
                    Ok(Event::ClientAuthenticated{service_id})
                } else {
                    println!("bad signature, impersonator!");
                    let _ = self.connections.remove(&connection_handle);
                    Ok(Event::FatalProtocolFailure)
                }
            },
            auth_hidden_service::Packet::Result(result) => {
                let protocol_failure = {
                    let connection = self.connection(connection_handle)?;

                    // onl outgoing connections should receive an auth hidden service result
                    connection.direction != Direction::Outgoing ||
                    // channel has wrong data
                    match connection.channel_map.channel_id_to_type(&channel) {
                        Some(ChannelDataType::OutgoingAuthHiddenService) => false,
                        _ => true
                    }
                };
                if protocol_failure {
                    let _ = self.connections.remove(&connection_handle);
                    return Ok(Event::FatalProtocolFailure)
                }

                match (result.accepted(), self.connection_mut(connection_handle)?.peer_service_id.clone()) {
                    (true, Some(service_id)) => {
                        let mut pending_replies: Vec<Packet> = Vec::with_capacity(3);

                        let reply = Packet::CloseChannelPacket{channel};
                        pending_replies.push(reply);

                        match result.is_known_contact() {
                            None | Some(false) => {
                                // contact request
                                let connection = self.connection_mut(connection_handle)?;
                                let message_text = if let Some(message_text) = connection.contact_request_message.take() {
                                    message_text
                                } else {
                                    String::new().try_into().unwrap()
                                };

                                let contact_request = contact_request_channel::ContactRequest{nickname: String::new().try_into().unwrap(), message_text};
                                let contact_request = contact_request_channel::OpenChannel {contact_request };
                                let extension = control_channel::OpenChannelExtension::ContactRequestChannel(contact_request);

                                // build contact request open packet
                                let channel_id = connection.next_channel_id();
                                let open_channel = control_channel::OpenChannel::new(
                                    channel_id as i32,
                                    control_channel::ChannelType::ContactRequest,
                                    Some(extension)).expect("OpenChannel creation failed");

                                let packet = control_channel::Packet::OpenChannel(open_channel);
                                let reply = Packet::ControlChannelPacket(packet);
                                pending_replies.push(reply);

                                connection.channel_map.insert(channel_id, ChannelData::OutgoingContactRequest)?;
                            },
                            Some(true) => {
                                let connection = self.connection_mut(connection_handle)?;

                                // build chat channel open packet
                                let channel_id = connection.next_channel_id();
                                let open_channel = control_channel::OpenChannel::new(
                                    channel_id as i32,
                                    control_channel::ChannelType::Chat,
                                    None).expect("OpenChannel creation failed");
                                let packet = control_channel::Packet::OpenChannel(open_channel);
                                let reply = Packet::ControlChannelPacket(packet);
                                pending_replies.push(reply);
                                connection.channel_map.insert(channel_id, ChannelData::OutgoingChat)?;

                                // build file transfer channel open packet
                                let channel_id = connection.next_channel_id();
                                let open_channel = control_channel::OpenChannel::new(
                                    channel_id as i32,
                                    control_channel::ChannelType::FileTransfer,
                                    None).expect("OpenChannel creation failed");
                                let packet = control_channel::Packet::OpenChannel(open_channel);
                                let reply = Packet::ControlChannelPacket(packet);
                                pending_replies.push(reply);

                                connection.channel_map.insert(channel_id, ChannelData::OutgoingFileTransfer)?;
                                self.contacts.insert(service_id.clone());
                            },
                        }

                        replies.append(&mut pending_replies);
                        Ok(Event::HostAuthenticated{service_id})
                    },
                    _ => Ok(Event::FatalProtocolFailure),
                }
            },
        }
    }

    fn handle_file_channel_packet(
        &mut self,
        _connection_handle: ConnectionHandle,
        _channel: u16,
        _packet: file_channel::Packet,
        _replies: &mut Vec<Packet>) -> Result<Event, Error> {
        Err(Error::NotImplemented)
    }

    pub fn new_outgoing_connection(
        &mut self,
        service_id: V3OnionServiceId,
        message_text: Option<contact_request_channel::MessageText>,
        replies: &mut Vec<Packet>) -> ConnectionHandle {
        let handle = self.next_connection_handle;
        self.next_connection_handle += 1u32;

        let connection = Connection::new_outgoing(service_id.clone(), message_text);
        self.connections.insert(handle, connection);
        self.service_id_to_connection_handle.insert(service_id, handle);

        let introduction = introduction::IntroductionPacket::new(vec![introduction::Version::RicochetRefresh3]).expect("IntroductionPacket construction failed");
        let packet = Packet::IntroductionPacket(introduction);
        replies.push(packet);

        handle
    }

    pub fn new_incoming_connection(&mut self) -> ConnectionHandle {
        let handle = self.next_connection_handle;
        self.next_connection_handle += 1u32;

        let connection = Connection::new_incoming();
        self.connections.insert(handle, connection);

        handle
    }
}
