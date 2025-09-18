// std
use std::cmp::Ord;
use std::collections::{BTreeMap, BTreeSet};

// extern
use rand::{TryRngCore, rngs::OsRng};
use tor_interface::tor_crypto::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, V3OnionServiceId};

// internal
use crate::v3::Error;
use crate::v3::file_hasher::{FileHash, FileHasher};
use crate::v3::message::*;
use crate::v3::channel_map::*;

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
    pub fn write_to_vec(&self, v:& mut Vec<u8>) -> Result<(), Error> {
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Direction {
    Incoming,
    Outgoing,
}

struct Connection {
    creation_time: std::time::Instant,
    channel_map: ChannelMap,
    direction: Direction,
    peer_service_id: Option<V3OnionServiceId>,
    contact_request_message: Option<contact_request_channel::MessageText>,
    next_outgoing_channel_id: u16,
    sent_message_counter: u64,
    file_transfers: BTreeMap<FileTransferHandle, FileTransfer>,
}

impl Connection {
    fn age(&self) -> std::time::Duration {
        let now = std::time::Instant::now();
        now.duration_since(self.creation_time)
    }

    fn new_incoming() -> Self {
        Self {
            creation_time: std::time::Instant::now(),
            channel_map: Default::default(),
            direction: Direction::Incoming,
            peer_service_id: None,
            contact_request_message: None,
            next_outgoing_channel_id: 2,
            sent_message_counter: 0u64,
            file_transfers: Default::default(),
        }
    }

    fn new_outgoing(
        service_id: V3OnionServiceId,
        message: Option<contact_request_channel::MessageText>) -> Self {
        Self {
            creation_time: std::time::Instant::now(),
            channel_map: Default::default(),
            direction: Direction::Outgoing,
            peer_service_id: Some(service_id),
            contact_request_message: message,
            next_outgoing_channel_id: 1,
            sent_message_counter: 0u64,
            file_transfers: Default::default(),
        }
    }

    fn next_channel_id(&mut self) -> u16 {
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

    fn close_channel(
        &mut self,
        channel: u16,
        replies: Option<&mut Vec<Packet>>,
    ) -> bool {
        if let Some(_channel_data) = self.channel_map.remove_by_id(&channel) {
            if let Some(replies) = replies {
                let reply = Packet::CloseChannelPacket{channel};
                replies.push(reply);
            }
            true
        } else {
            false
        }
    }
}

enum FileTransfer {
    FileDownload(FileDownload),
    FileUpload(FileUpload),
}

struct FileDownload {
    expected_bytes: u64,
    downloaded_bytes: u64,
    expected_hash: FileHash,
    // hasher for received file contents
    hasher: FileHasher,
}

struct FileUpload {
    file_size: u64,
    uploaded_bytes: u64,
}

pub type ConnectionHandle = u32;
// todo: ensure ConnectionHandles are not reused
pub const CONNECTION_HANDLE_MAX: u32 = 0x7fffffffu32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MessageHandle {
    message_id: u32,
    connection_handle: ConnectionHandle,
    direction: Direction,
}

impl MessageHandle {
    const MESSAGE_ID_BITS: u64 = 0x00000000ffffffffu64;
    const MESSAGE_ID_SHIFT: u64 = 0u64;
    const CONNECTION_HANDLE_BITS: u64 = 0x7fffffff00000000u64;
    const CONNECTION_HANDLE_SHIFT: u64 = 32u64;
    const DIRECTION_BITS: u64 = 0x8000000000000000u64;
    const DIRECTION_SHIFT: u64 = 63u64;
}

impl From<MessageHandle> for u64 {
    // bits:
    // 0..32: message id from protoocl
    // 32..63: connection handle (except the most significant bit)
    // 63: direction (0 for incoming, 1 for outgoing)
    fn from(message_handle: MessageHandle) -> u64 {
        assert!(message_handle.connection_handle <= CONNECTION_HANDLE_MAX);

        let message_id = (message_handle.message_id as u64) << MessageHandle::MESSAGE_ID_SHIFT;
        let connection_handle = (message_handle.connection_handle as u64) << MessageHandle::CONNECTION_HANDLE_SHIFT;
        let direction = match message_handle.direction {
            Direction::Incoming => 0u64,
            Direction::Outgoing => 1u64,
        } << MessageHandle::DIRECTION_SHIFT;

        direction | connection_handle | message_id
    }
}

impl From<u64> for MessageHandle {
    fn from(message_handle_raw: u64) -> MessageHandle {
        let message_id = message_handle_raw & MessageHandle::MESSAGE_ID_BITS;
        let message_id = message_id >> MessageHandle::MESSAGE_ID_SHIFT;
        let message_id = message_id as u32;

        let connection_handle = message_handle_raw & MessageHandle::CONNECTION_HANDLE_BITS;
        let connection_handle = connection_handle >> MessageHandle::CONNECTION_HANDLE_SHIFT;
        let connection_handle = connection_handle as ConnectionHandle;

        let direction = message_handle_raw & MessageHandle::DIRECTION_BITS;
        let direction = direction >> MessageHandle::DIRECTION_SHIFT;
        let direction = match direction {
            0x0u64 => Direction::Incoming,
            0x1u64 => Direction::Outgoing,
            _ => unreachable!(),
        };

        MessageHandle{message_id, connection_handle, direction}
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FileTransferHandle {
    file_id: u32,
    connection_handle: ConnectionHandle,
    direction: Direction,
}

impl FileTransferHandle {
    const FILE_ID_BITS: u64 = 0x00000000ffffffffu64;
    const FILE_ID_SHIFT: u64 = 0u64;
    const CONNECTION_HANDLE_BITS: u64 = 0x7fffffff00000000u64;
    const CONNECTION_HANDLE_SHIFT: u64 = 32u64;
    const DIRECTION_BITS: u64 = 0x8000000000000000u64;
    const DIRECTION_SHIFT: u64 = 63u64;
}

impl From<FileTransferHandle> for u64 {
    // bits:
    // 0..32: file id from protoocl
    // 32..63: connection handle (except the most significant bit)
    // 63: direction (0 for incoming, 1 for outgoing)
    fn from(file_transfer_handle: FileTransferHandle) -> u64 {
        assert!(file_transfer_handle.connection_handle <= CONNECTION_HANDLE_MAX);

        let file_id = (file_transfer_handle.file_id as u64) << FileTransferHandle::FILE_ID_SHIFT;
        let connection_handle = (file_transfer_handle.connection_handle as u64) << FileTransferHandle::CONNECTION_HANDLE_SHIFT;
        let direction = match file_transfer_handle.direction {
            Direction::Incoming => 0u64,
            Direction::Outgoing => 1u64,
        } << FileTransferHandle::DIRECTION_SHIFT;

        direction | connection_handle | file_id
    }
}

impl From<u64> for FileTransferHandle {
    fn from(file_transfer_handle_raw: u64) -> FileTransferHandle {
        let file_id = file_transfer_handle_raw & FileTransferHandle::FILE_ID_BITS;
        let file_id = file_id >> FileTransferHandle::FILE_ID_SHIFT;
        let file_id = file_id as u32;

        let connection_handle = file_transfer_handle_raw & FileTransferHandle::CONNECTION_HANDLE_BITS;
        let connection_handle = connection_handle >> FileTransferHandle::CONNECTION_HANDLE_SHIFT;
        let connection_handle = connection_handle as ConnectionHandle;

        let direction = file_transfer_handle_raw & FileTransferHandle::DIRECTION_BITS;
        let direction = direction >> FileTransferHandle::DIRECTION_SHIFT;
        let direction = match direction {
            0x0u64 => Direction::Incoming,
            0x1u64 => Direction::Outgoing,
            _ => unreachable!(),
        };

        FileTransferHandle{file_id, connection_handle, direction}
    }
}

pub enum Event {
    IntroductionReceived,
    IntroductionResponseReceived,
    OpenChannelAuthHiddenServiceReceived,
    // Fired when a host authorises a connecting client
    // Optionally includes handle of existing connection to drop
    ClientAuthenticated{
        service_id: V3OnionServiceId,
        duplicate_connection: Option<ConnectionHandle>,
    },
    BlockedClientAuthenticationAttempted{
        service_id: V3OnionServiceId,
    },
    // Fired when client receives proof confirmation from host
    // Optionally inludes handle of existing connection to drop
    HostAuthenticated{
        service_id: V3OnionServiceId,
        duplicate_connection: Option<ConnectionHandle>,
    },
    // Fired when a duplicate authenticated connection must be dropped
    DuplicateConnectionDropped {
        duplicate_connection: ConnectionHandle,
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
    ContactRequestResultRejected{
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
        message_handle: MessageHandle,
        time_delta: std::time::Duration,
    },
    ChatAcknowledgeReceived{
        service_id: V3OnionServiceId,
        message_handle: MessageHandle,
        accepted: bool,
    },
    FileTransferRequestReceived{
        service_id: V3OnionServiceId,
        file_transfer_handle: FileTransferHandle,
        file_name: String,
        file_size: u64,
        file_hash: FileHash,
    },
    FileTransferRequestAcknowledgeReceived{
        service_id: V3OnionServiceId,
        file_transfer_handle: FileTransferHandle,
        accepted: bool
    },
    FileTransferRequestAccepted{
        service_id: V3OnionServiceId,
        file_transfer_handle: FileTransferHandle,
    },
    FileTransferRequestRejected{
        service_id: V3OnionServiceId,
        file_transfer_handle: FileTransferHandle,
    },
    FileChunkReceived{
        service_id: V3OnionServiceId,
        file_transfer_handle: FileTransferHandle,
        data: Vec<u8>,
        last_chunk: bool,
        hash_matches: Option<bool>,
    },
    FileChunkAckReceived{
        service_id: V3OnionServiceId,
        file_transfer_handle: FileTransferHandle,
        offset: u64,
    },
    FileTransferSucceeded{
        service_id: V3OnionServiceId,
        file_transfer_handle: FileTransferHandle,
    },
    FileTransferFailed{
        service_id: V3OnionServiceId,
        file_transfer_handle: FileTransferHandle,
    },
    FileTransferCancelled{
        service_id: V3OnionServiceId,
        file_transfer_handle: FileTransferHandle,
    },
    ChannelClosed{
        id: u16,
    },
    ProtocolFailure{
        message: String
    },
    // TODO: add a message
    FatalProtocolFailure,
}

pub struct PacketHandler {
    next_connection_handle: ConnectionHandle,
    connections: BTreeMap<ConnectionHandle, Connection>,
    // map service id to connection handle, only contains connections which have succeeded
    // the auth hidden service handshake (i.e. has received confifrmation of a valid proof)
    service_id_to_connection_handle: BTreeMap<V3OnionServiceId, ConnectionHandle>,
    // our service id
    private_key: Ed25519PrivateKey,
    service_id: V3OnionServiceId,
    // set of known contacts which have been approved by host
    known_contacts: BTreeSet<V3OnionServiceId>,
}

impl PacketHandler {
    pub fn new(
        private_key: Ed25519PrivateKey,
        known_contacts: BTreeSet<V3OnionServiceId>,
    ) -> Self {
        let service_id = V3OnionServiceId::from_private_key(&private_key);
        Self {
            next_connection_handle: Default::default(),
            connections: Default::default(),
            service_id_to_connection_handle: Default::default(),
            private_key,
            service_id,
            known_contacts,
        }
    }

    fn known_contacts(&self) -> &BTreeSet<V3OnionServiceId> {
        &self.known_contacts
    }

    fn connection(
        &self,
        connection_handle: ConnectionHandle) -> Result<&Connection, Error> {
        self.connections
            .get(&connection_handle)
            .ok_or(Error::ConnectionHandleToConnectionMappingFailure(connection_handle))
    }

    fn connection_mut(
        &mut self,
        connection_handle: ConnectionHandle) -> Result<&mut Connection, Error> {
        self.connections
            .get_mut(&connection_handle)
            .ok_or(Error::ConnectionHandleToConnectionMappingFailure(connection_handle))
    }

    fn service_id_to_connection_handle(
        &self,
        service_id: &V3OnionServiceId) -> Result<ConnectionHandle, Error> {
        self.service_id_to_connection_handle
            .get(service_id)
            .ok_or(Error::ServiceIdToConnectionHandleMappingFailure(service_id.clone()))
            .copied()
    }

    // On successful packet read returns a (packet, bytes read) tuple
    // If needs more bytes, returns Ok(None)
    // Consumers must drop the returned number of bytes from the start of their
    // read buffer
    pub fn try_parse_packet(
        &self,
        connection_handle: ConnectionHandle,
        bytes: &[u8]) -> Result<(Packet, usize), Error> {

        let connection = self.connections.get(&connection_handle).ok_or(Error::ConnectionHandleToConnectionMappingFailure(connection_handle))?;
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
                        // todo: why does IncomingContactRequest rueturn an error?
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
    // TODO: this should potentially return Vec<Event>
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
                            if !self.known_contacts.contains(service_id) {
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
                            if !self.known_contacts.contains(service_id) {
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
                            Status::Rejected => Ok(Event::ContactRequestResultRejected{service_id: service_id.clone()}),
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
        if connection.close_channel(channel_id, None) {
            Ok(Event::ChannelClosed{id: channel_id})
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

        let connection = self.connection(connection_handle)?;
        let channel_type = connection.channel_map.channel_id_to_type(&channel_id);

        match packet {
            contact_request_channel::Packet::Response(response) => {
                // chat messags should only come in on the incoming chat channel
                match channel_type {
                    Some(ChannelType::OutgoingContactRequest) => (),
                    _ => return Ok(Event::FatalProtocolFailure),
                }

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

                        self.known_contacts.insert(service_id.clone());
                        replies.append(&mut pending_replies);
                        Ok(Event::ContactRequestResultAccepted{service_id})
                    },
                    (Status::Rejected, Some(service_id)) => {
                        connection.close_channel(channel_id, Some(replies));
                        Ok(Event::ContactRequestResultRejected{service_id})
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

        let connection = self.connection(connection_handle)?;
        let channel_type = connection.channel_map.channel_id_to_type(&channel);

        match packet {
            chat_channel::Packet::ChatMessage(message) => {
                // chat messags should only come in on the incoming chat channel
                match channel_type {
                    Some(ChannelType::IncomingChat) => (),
                    _ => return Ok(Event::FatalProtocolFailure),
                }

                let connection = self.connection(connection_handle)?;
                let service_id = if let Some(service_id) = &connection.peer_service_id {
                    service_id.clone()
                } else {
                    return Ok(Event::FatalProtocolFailure)
                };

                let message_text: String = message.message_text().into();
                let message_id = message.message_id();
                let message_handle = MessageHandle{message_id, connection_handle, direction: Direction::Incoming};
                let time_delta = if let Some(time_delta) = message.time_delta() {
                    *time_delta
                } else {
                    std::time::Duration::ZERO
                };

                // build ack reply
                let accepted = true;
                let acknowledge = chat_channel::ChatAcknowledge::new(message_id, accepted)?;
                let packet = chat_channel::Packet::ChatAcknowledge(acknowledge);
                let reply = Packet::ChatChannelPacket{channel, packet};
                replies.push(reply);

                Ok(Event::ChatMessageReceived{service_id, message_text, message_handle, time_delta})
            },
            chat_channel::Packet::ChatAcknowledge(acknowledge) => {
                // chat ack messsages should only come in on the outgoing chat channel
                match channel_type {
                    Some(ChannelType::OutgoingChat) => (),
                    _ => return Ok(Event::FatalProtocolFailure),
                }

                let connection = self.connection(connection_handle)?;
                let service_id = if let Some(service_id) = &connection.peer_service_id {
                    service_id.clone()
                } else {
                    return Ok(Event::FatalProtocolFailure)
                };
                let message_id = acknowledge.message_id();
                let message_handle = MessageHandle{message_id, connection_handle, direction: Direction::Outgoing};
                let accepted = acknowledge.accepted();
                Ok(Event::ChatAcknowledgeReceived{service_id, message_handle, accepted})
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
                        Some(ChannelType::IncomingAuthHiddenService) => false,
                        _ => true
                    }
                };
                if protocol_failure {
                    let _ = self.connections.remove(&connection_handle);
                    return Ok(Event::FatalProtocolFailure)
                }

                let server_service_id = self.service_id.clone();

                let (client_cookie, server_cookie) = if let Some(ChannelData::IncomingAuthHiddenService{client_cookie, server_cookie}) = self.connection_mut(connection_handle)?.channel_map.get_by_id(&channel) {
                    (client_cookie.clone(), server_cookie.clone())
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

                    // build reply packets

                    let connection = self.connection(connection_handle)?;
                    let is_known_contact = self.known_contacts.contains(&client_service_id);
                    let result = auth_hidden_service::Result::new(true, Some(is_known_contact))?;
                    let packet = auth_hidden_service::Packet::Result(result);
                    let reply = Packet::AuthHiddenServicePacket{channel, packet};
                    pending_replies.push(reply);

                    let connection = self.connection_mut(connection_handle)?;
                    connection.close_channel(channel, Some(&mut pending_replies));

                    // known contacts can begin to chat immediately
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

                    let service_id = client_service_id.clone();

                    // TODO: protocol specification does not describe this logic
                    // equivalent lives in ContactUser.cpp
                    // handle existence of duplicate existing connection
                    let event = match self.service_id_to_connection_handle(&service_id) {
                        Ok(duplicate_connection) =>  {
                            let connection = self.connection(duplicate_connection).unwrap();

                            // newest incoming takes precedence
                            if connection.direction == Direction::Incoming ||
                            // only replace if previous existing outgoing if it is more than 30 seconds old
                               connection.age() > std::time::Duration::from_secs(30) ||
                            // only drop old connection if the peer's service id is less
                            // than our own
                               service_id < self.service_id {
                                replies.append(&mut pending_replies);
                                let service_id = service_id.clone();
                                let duplicate_connection = Some(duplicate_connection);
                                Event::ClientAuthenticated{service_id, duplicate_connection}
                            } else {
                                // otherwise we drop this new conneciton in favor of previous outgoing connection
                                let duplicate_connection = connection_handle;
                                Event::DuplicateConnectionDropped{duplicate_connection}
                            }
                        },
                        Err(Error::ServiceIdToConnectionHandleMappingFailure(..)) => {
                            // no previous connection to drop
                            replies.append(&mut pending_replies);
                            let service_id = service_id.clone();
                            Event::ClientAuthenticated{service_id, duplicate_connection: None}
                        },
                        Err(_) => unreachable!(),
                    };

                    if let Event::ClientAuthenticated{..} = &event {
                        if let Some(old_connection_handle) = self.service_id_to_connection_handle.insert(service_id, connection_handle) {
                            // remove the old connection
                            self.connections.remove(&old_connection_handle);
                        }
                    }

                    Ok(event)
                } else {
                    println!("bad signature, impersonator!");
                    let _ = self.connections.remove(&connection_handle);
                    Ok(Event::FatalProtocolFailure)
                }
            },
            auth_hidden_service::Packet::Result(result) => {
                let protocol_failure = {
                    let connection = self.connection(connection_handle)?;

                    // only outgoing connections should receive an auth hidden service result
                    connection.direction != Direction::Outgoing ||
                    // channel has wrong data
                    match connection.channel_map.channel_id_to_type(&channel) {
                        Some(ChannelType::OutgoingAuthHiddenService) => false,
                        _ => true
                    }
                };
                if protocol_failure {
                    let _ = self.connections.remove(&connection_handle);
                    return Ok(Event::FatalProtocolFailure)
                }

                let client_service_id = self.service_id.clone();

                let connection = self.connection_mut(connection_handle)?;
                match (result.accepted(), connection.peer_service_id.clone()) {
                    (true, Some(server_service_id)) => {
                        let mut pending_replies: Vec<Packet> = Vec::with_capacity(3);

                        connection.close_channel(channel, Some(&mut pending_replies));
                        match result.is_known_contact() {
                            None | Some(false) => {
                                // contact request
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
                            },
                        }

                        let service_id = server_service_id.clone();

                        // TODO: protocol specification does not describe this logic
                        // equivalent lives in ContactUser.cpp
                        // handle existence of duplicate existing connection
                        let event = match self.service_id_to_connection_handle(&service_id) {
                            Ok(duplicate_connection) => {
                                let connection = self.connection(duplicate_connection).unwrap();

                                // newest outgoing takes precedence
                                if connection.direction == Direction::Outgoing ||
                                // only replacce if previous existing outgoing if it is
                                // more than 30 seconds old
                                  connection.age() > std::time::Duration::from_secs(30) ||
                                // only drop old connection if the peer's service id is less
                                // than our own
                                  service_id < self.service_id {
                                    replies.append(&mut pending_replies);
                                    let service_id = service_id.clone();
                                    let duplicate_connection = Some(duplicate_connection);
                                    Event::HostAuthenticated{service_id, duplicate_connection}
                                } else {
                                    // otherwise we drop this new connection in favor of previous incoming connection
                                    let duplicate_connection = connection_handle;
                                    Event::DuplicateConnectionDropped{duplicate_connection}
                                }
                            },
                            Err(Error::ServiceIdToConnectionHandleMappingFailure(..)) => {
                                // no previous connection to drop
                                replies.append(&mut pending_replies);
                                let service_id = service_id.clone();
                                Event::HostAuthenticated{service_id, duplicate_connection: None}
                            },
                            Err(_) => unreachable!()
                        };

                        if let Event::HostAuthenticated{..} = &event {
                            if let Some (old_connection_handle) = self.service_id_to_connection_handle.insert(service_id, connection_handle) {
                                // remove the old connection
                                self.connections.remove(&old_connection_handle);
                            }
                        }

                        Ok(event)
                    },
                    _ => Ok(Event::FatalProtocolFailure),
                }
            },
        }
    }

    fn handle_file_channel_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        channel: u16,
        packet: file_channel::Packet,
        replies: &mut Vec<Packet>) -> Result<Event, Error> {

        let connection = self.connection(connection_handle)?;
        let service_id = if let Some(service_id) = &connection.peer_service_id {
            service_id.clone()
        } else {
            return Ok(Event::FatalProtocolFailure)
        };
        let channel_type = connection.channel_map.channel_id_to_type(&channel);

        match packet {
            file_channel::Packet::FileHeader(file_header) => {
                // file header should only come in on the incoming file channel
                match channel_type {
                    Some(ChannelType::IncomingFileTransfer) => (),
                    _ => return Ok(Event::FatalProtocolFailure),
                }

                let file_id = file_header.file_id();
                let file_transfer_handle = FileTransferHandle{file_id, connection_handle, direction: Direction::Incoming};
                let file_name = file_header.name().to_string();
                let file_size = file_header.file_size();
                let file_hash = file_header.file_hash().clone();

                // construct our internal state for this download
                let connection = self.connection_mut(connection_handle)?;
                if let Some(_) = connection.file_transfers.insert(file_transfer_handle.clone(), FileTransfer::FileDownload(FileDownload{
                    expected_bytes: file_size,
                    downloaded_bytes: 0u64,
                    expected_hash: file_hash.clone(),
                    hasher: Default::default(),
                })) {
                    // peer initiated file transfer with duplicate id
                    return Ok(Event::FatalProtocolFailure);
                }

                // build ack reply
                let accepted = true;
                let file_header_ack = file_channel::FileHeaderAck::new(file_id, accepted)?;
                let packet = file_channel::Packet::FileHeaderAck(file_header_ack);
                let reply = Packet::FileChannelPacket{channel, packet};
                replies.push(reply);

                Ok(Event::FileTransferRequestReceived{service_id, file_transfer_handle, file_name, file_size, file_hash})
            },
            file_channel::Packet::FileChunk(file_chunk) => {
                // file chunks should only come in on the incoming file channel
                match channel_type {
                    Some(ChannelType::IncomingFileTransfer) => (),
                    _ => return Ok(Event::FatalProtocolFailure),
                }

                let file_id = file_chunk.file_id();
                let file_transfer_handle = FileTransferHandle{file_id, connection_handle, direction: Direction::Incoming};
                let data: Vec<u8> = file_chunk.take_chunk_data().into();

                let connection = self.connection_mut(connection_handle)?;
                let file_download = match connection.file_transfers.get_mut(&file_transfer_handle) {
                    Some(FileTransfer::FileDownload(file_download)) => file_download,
                    None => {
                        return Ok(Event::ProtocolFailure{message: "Received orphaned FileChunk packet".to_string()});
                    },
                    _ => todo!(),
                };

                // update the partial download state
                file_download.downloaded_bytes += data.len() as u64;
                file_download.hasher.update(&data);

                // build ack reply
                let file_chunk_ack = file_channel::FileChunkAck::new(file_id, file_download.downloaded_bytes)?;
                let packet = file_channel::Packet::FileChunkAck(file_chunk_ack);
                let reply = Packet::FileChannelPacket{channel, packet};
                replies.push(reply);

                use std::cmp::Ordering;
                match file_download.downloaded_bytes.cmp(&file_download.expected_bytes) {
                    Ordering::Less => {
                        Ok(Event::FileChunkReceived{service_id, file_transfer_handle, data, last_chunk: false, hash_matches: None})
                    },
                    ordering => {
                        let file_download = match connection.file_transfers.remove(&file_transfer_handle) {
                            Some(FileTransfer::FileDownload(file_download)) => file_download,
                            _ => todo!(),
                        };

                        match ordering {
                            Ordering::Equal => {
                                // verify hash matches
                                let calculated_hash: FileHash = file_download.hasher.finalize();
                                let hash_matches = calculated_hash == file_download.expected_hash;

                                // build complete notification reply
                                use file_channel::FileTransferResult;
                                let result = if hash_matches {
                                    FileTransferResult::Success
                                } else {
                                    FileTransferResult::Failure
                                };
                                let file_transfer_complete_notification = file_channel::FileTransferCompleteNotification::new(file_id, result).unwrap();
                                let packet = file_channel::Packet::FileTransferCompleteNotification(file_transfer_complete_notification);
                                let reply = Packet::FileChannelPacket{channel, packet};
                                replies.push(reply);

                                let hash_matches = Some(hash_matches);
                                Ok(Event::FileChunkReceived{service_id, file_transfer_handle, data, last_chunk: true, hash_matches})
                            },
                            // recevied too many bytes from peer something weird is happening
                            Ordering::Greater => Ok(Event::FatalProtocolFailure),
                            _ => unreachable!(),
                        }
                    },
                }
            },
            file_channel::Packet::FileHeaderAck(file_header_ack) => {
                // file header ack should only come in on the outgoing file channel
                match channel_type {
                    Some(ChannelType::OutgoingFileTransfer) => (),
                    _ => return Ok(Event::FatalProtocolFailure),
                }

                let file_id = file_header_ack.file_id();
                let file_transfer_handle = FileTransferHandle{file_id, connection_handle, direction: Direction::Outgoing};
                let accepted = file_header_ack.accepted();
                Ok(Event::FileTransferRequestAcknowledgeReceived{service_id, file_transfer_handle, accepted})
            },
            file_channel::Packet::FileHeaderResponse(file_header_response) => {
                // file header response should only come in on the outgoing file channel
                match channel_type {
                    Some(ChannelType::OutgoingFileTransfer) => (),
                    _ => return Ok(Event::FatalProtocolFailure),
                }

                let file_id = file_header_response.file_id();
                let file_transfer_handle = FileTransferHandle{file_id, connection_handle, direction: Direction::Outgoing};
                let response = file_header_response.response();
                use file_channel::Response;
                match response {
                    Response::Accept => Ok(Event::FileTransferRequestAccepted{service_id, file_transfer_handle}),
                    Response::Reject => {
                        // clean up upload record
                        let connection = self.connection_mut(connection_handle)?;
                        match connection.file_transfers.remove(&file_transfer_handle) {
                            Some(FileTransfer::FileUpload(_)) => (),
                            Some(FileTransfer::FileDownload(_)) => todo!(),
                            None => todo!(),
                        }
                        Ok(Event::FileTransferRequestRejected{service_id, file_transfer_handle})
                    }
                }
            },
            file_channel::Packet::FileChunkAck(file_chunk_ack) => {
                // file chunk ack should only come in on the outgoing file channel
                match channel_type {
                    Some(ChannelType::OutgoingFileTransfer) => (),
                    _ => return Ok(Event::FatalProtocolFailure),
                }

                let file_id = file_chunk_ack.file_id();
                let file_transfer_handle = FileTransferHandle{file_id, connection_handle, direction: Direction::Outgoing};
                // the number of bytes our counterpart claims to have
                // received from us during this file transfer
                let bytes_received = file_chunk_ack.bytes_received();
                // bytes_received is the number of bytes our counterpart
                // has received from us, which is equivalent to the number
                // of bytes *we've* sent for the purposes of state
                // management
                let bytes_sent = bytes_received;

                let file_upload = match connection.file_transfers.get(&file_transfer_handle) {
                    Some(FileTransfer::FileUpload(file_upload)) => file_upload,
                    Some(FileTransfer::FileDownload(_)) => unreachable!("we should only receive file chunk acks for uploads"),
                    None => return Ok(Event::ProtocolFailure{message: "Received orphaned FileChunkAck packet".to_string()}),
                };

                // ensure our state is synchronized before sending more bytes
                if file_upload.uploaded_bytes != bytes_sent {
                    Ok(Event::FatalProtocolFailure)
                // ensure we've sent no more bytes than the size of the file
                } else if file_upload.file_size >= bytes_sent {
                    let offset = bytes_sent;
                    Ok(Event::FileChunkAckReceived{service_id, file_transfer_handle, offset})
                } else {
                    Ok(Event::FatalProtocolFailure)
                }
            },
            file_channel::Packet::FileTransferCompleteNotification(
                // file header should only come in on the incoming file channel
                file_transfer_complete_notification) => {
                let file_id = file_transfer_complete_notification.file_id();
                let direction = match channel_type {
                    Some(ChannelType::IncomingFileTransfer) => Direction::Incoming,
                    Some(ChannelType::OutgoingFileTransfer) => Direction::Outgoing,
                    _ => return Ok(Event::FatalProtocolFailure),
                };
                let file_transfer_handle = FileTransferHandle{file_id, connection_handle, direction};
                use file_channel::FileTransferResult;

                let connection = self.connection_mut(connection_handle)?;

                // cleanup file transfer state
                match (direction, connection.file_transfers.remove(&file_transfer_handle)) {
                    (Direction::Incoming, Some(FileTransfer::FileDownload(file_download))) => (),
                    (Direction::Outgoing, Some(FileTransfer::FileUpload(file_upload))) => (),
                    (_, None) => return Ok(Event::ProtocolFailure{message: "".to_string()}),
                    _ => return Ok(Event::FatalProtocolFailure),
                }

                match file_transfer_complete_notification.result() {
                    FileTransferResult::Success => Ok(Event::FileTransferSucceeded{service_id, file_transfer_handle}),
                    FileTransferResult::Failure => Ok(Event::FileTransferFailed{service_id, file_transfer_handle}),
                    FileTransferResult::Cancelled => Ok(Event::FileTransferCancelled{service_id, file_transfer_handle}),
                }
            },
        }
    }

    pub fn new_outgoing_connection(
        &mut self,
        service_id: V3OnionServiceId,
        message_text: Option<contact_request_channel::MessageText>,
        replies: &mut Vec<Packet>) -> Result<ConnectionHandle, Error> {

        self.known_contacts.insert(service_id.clone());

        let handle = self.next_connection_handle;
        if handle > CONNECTION_HANDLE_MAX {
            return Err(Error::ConnectionHandlesExhausted);
        }
        self.next_connection_handle += 1u32;


        let connection = Connection::new_outgoing(service_id, message_text);
        self.connections.insert(handle, connection);

        let introduction = introduction::IntroductionPacket::new(vec![introduction::Version::RicochetRefresh3])?;
        let packet = Packet::IntroductionPacket(introduction);
        replies.push(packet);

        Ok(handle)
    }

    pub fn new_incoming_connection(&mut self) -> Result<ConnectionHandle, Error> {
        let handle = self.next_connection_handle;
        if handle > CONNECTION_HANDLE_MAX {
            return Err(Error::ConnectionHandlesExhausted);
        }
        self.next_connection_handle += 1u32;

        let connection = Connection::new_incoming();
        self.connections.insert(handle, connection);

        Ok(handle)
    }

    pub fn remove_connection(
        &mut self,
        handle: &ConnectionHandle,
    ) -> () {
        // remove this connection
        if let Some(connection) = self.connections.remove(handle) {
            // remove service_id to handle entry only if it is associated with
            // the passed in handle
            if let Some(service_id) = connection.peer_service_id {
                let remove = if let Some(stored_handle) = self.service_id_to_connection_handle.get(&service_id) {
                    stored_handle == handle
                } else {
                    false
                };

                if remove {
                    self.service_id_to_connection_handle.remove(&service_id);
                }
            }
        }
    }

    pub fn has_verified_connection(
        &self,
        service_id: &V3OnionServiceId,
    ) -> bool {
        self.service_id_to_connection_handle.contains_key(service_id)
    }

    pub fn forget_user(
        &mut self,
        service_id: &V3OnionServiceId,
    ) -> () {
        if let Ok(connection_handle) = self.service_id_to_connection_handle(service_id) {
            self.remove_connection(&connection_handle);
        }
        self.known_contacts.remove(service_id);
    }

    pub fn accept_contact_request(
        &mut self,
        service_id: V3OnionServiceId,
        replies: &mut Vec<Packet>) -> Result<ConnectionHandle, Error> {
        // todo: we can probably remove these checks and specific errors
        // in favor of checking for an IncomingContactRequest channel
        if self.known_contacts.contains(&service_id) {
            return Err(Error::PeerAlreadyKnownContact(service_id));
        }

        let connection_handle = self.service_id_to_connection_handle(&service_id)?;
        let connection = self.connection_mut(connection_handle)?;
        let channel_identifier = if let Some(channel_identifier) = connection.channel_map.channel_type_to_id(&ChannelType::IncomingContactRequest) {
            channel_identifier
        } else {
            // properly handle this error
            todo!();
        };

        let mut pending_replies: Vec<Packet> = Vec::with_capacity(3);

        // build contact request accepted packet
        use contact_request_channel::{Response, Status};
        let channel = channel_identifier;
        let response = Response{status: Status::Accepted};
        let packet = contact_request_channel::Packet::Response(response);
        let reply = Packet::ContactRequestChannelPacket{channel, packet};
        pending_replies.push(reply);

        // close this contact request channel
        connection.close_channel(channel, Some(&mut pending_replies));

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

        self.known_contacts.insert(service_id);
        replies.append(&mut pending_replies);
        Ok(connection_handle)
    }

    pub fn reject_contact_request(
        &mut self,
        service_id: V3OnionServiceId,
        replies: &mut Vec<Packet>) -> Result<ConnectionHandle, Error> {

        let connection_handle = self.service_id_to_connection_handle(&service_id)?;
        let connection = self.connection_mut(connection_handle)?;
        let channel_identifier = if let Some(channel_identifier) = connection.channel_map.channel_type_to_id(&ChannelType::IncomingContactRequest) {
            channel_identifier
        } else {
            // properly handle this error
            todo!();
        };

        let mut pending_replies: Vec<Packet> = Vec::with_capacity(3);

        // build contact request accepted packet
        use contact_request_channel::{Response, Status};
        let channel = channel_identifier;
        let response = Response{status: Status::Rejected};
        let packet = contact_request_channel::Packet::Response(response);
        let reply = Packet::ContactRequestChannelPacket{channel, packet};
        pending_replies.push(reply);

        // close this contact request channel
        connection.close_channel(channel, Some(&mut pending_replies));

        replies.append(&mut pending_replies);

        Ok(connection_handle)
    }

    pub fn send_message(
        &mut self,
        service_id: V3OnionServiceId,
        message_text: chat_channel::MessageText,
        replies: &mut Vec<Packet>) -> Result<(ConnectionHandle, MessageHandle), Error> {

        let connection_handle = self.service_id_to_connection_handle(&service_id)?;
        let connection = self.connection_mut(connection_handle)?;
        if let Some(channel) = connection.channel_map.channel_type_to_id(&ChannelType::OutgoingChat) {
            // get this message's id
            if connection.sent_message_counter > (u32::MAX as u64) {
                return Err(Error::MessageHandlesExhausted);
            }

            let message_id = (connection.sent_message_counter & (u32::MAX as u64)) as u32;
            let message_handle = MessageHandle{message_id, connection_handle, direction: Direction::Outgoing};

            // and increment counter
            connection.sent_message_counter += 1u64;

            let chat_message = chat_channel::ChatMessage::new(message_text, message_id, None)?;
            let packet = chat_channel::Packet::ChatMessage(chat_message);
            let reply = Packet::ChatChannelPacket{channel, packet};
            replies.push(reply);


            Ok((connection_handle, message_handle))
        } else {
            Err(Error::NotImplemented)
        }
    }

    pub fn send_file_transfer_request(
        &mut self,
        service_id: V3OnionServiceId,
        file_name: String,
        file_size: u64,
        file_hash: FileHash,
        replies: &mut Vec<Packet>) -> Result<(ConnectionHandle, FileTransferHandle), Error> {

        let connection_handle = self.service_id_to_connection_handle(&service_id)?;
        let connection = self.connection_mut(connection_handle)?;
        if let Some(channel) = connection.channel_map.channel_type_to_id(&ChannelType::OutgoingFileTransfer) {
            // get this file transfer's id
            // get this message's id
            if connection.sent_message_counter > (u32::MAX as u64) {
                return Err(Error::FileTransferHandlesExhausted);
            }

            let file_id = (connection.sent_message_counter & (u32::MAX as u64)) as u32;
            let file_transfer_handle = FileTransferHandle{file_id, connection_handle, direction: Direction::Outgoing};

            // and increment counter
            connection.sent_message_counter += 1;

            // add a file upload record for this pending transfer
            connection.file_transfers.insert(file_transfer_handle.clone(), FileTransfer::FileUpload(FileUpload{file_size, uploaded_bytes: 0u64}));

            let file_header = file_channel::FileHeader::new(file_id, file_size, file_name, file_hash)?;
            let packet = file_channel::Packet::FileHeader(file_header);
            let reply = Packet::FileChannelPacket{channel, packet};
            replies.push(reply);


            Ok((connection_handle, file_transfer_handle))
        } else {
            Err(Error::NotImplemented)
        }
    }

    pub fn accept_file_transfer_request(
        &mut self,
        service_id: &V3OnionServiceId,
        file_transfer_handle: FileTransferHandle,
        replies: &mut Vec<Packet>) -> Result<ConnectionHandle, Error> {

        let connection_handle = self.service_id_to_connection_handle(service_id)?  ;
        let connection = self.connection_mut(connection_handle)?;

        if let Some(channel) = connection.channel_map.channel_type_to_id(&ChannelType::IncomingFileTransfer) {

            let file_id = file_transfer_handle.file_id;
            let file_header_response = file_channel::FileHeaderResponse::new(file_id, file_channel::Response::Accept)?;
            let packet = file_channel::Packet::FileHeaderResponse(file_header_response);
            let reply = Packet::FileChannelPacket{channel, packet};
            replies.push(reply);

            Ok(connection_handle)
        } else {
            Err(Error::NotImplemented)
        }
    }

    pub fn reject_file_transfer_request(
        &mut self,
        service_id: &V3OnionServiceId,
        file_transfer_handle: FileTransferHandle,
        replies: &mut Vec<Packet>) -> Result<ConnectionHandle, Error> {

        let connection_handle = self.service_id_to_connection_handle(service_id)?;
        let connection = self.connection_mut(connection_handle)?;

        // ensure we're deling with an inc=oming request
        if file_transfer_handle.direction != Direction::Incoming {
            todo!();
        }

        // remove the pending file transfer
        let file_transfer = connection.file_transfers.remove(&file_transfer_handle).ok_or(Error::FileTransferHandleToFileTransferMappingFailure(file_transfer_handle))?;
        match file_transfer {
            FileTransfer::FileDownload(_) => (),
            FileTransfer::FileUpload(_) => return Err(Error::FileUploadCannotBeRejected(file_transfer_handle)),
        }

        let channel_type = ChannelType::IncomingFileTransfer;
        let channel = connection.channel_map.channel_type_to_id(&channel_type).ok_or(Error::TargetChannelTypeNotOpen(channel_type))?;

        // send rejection
        let file_id = file_transfer_handle.file_id;
        let file_header_response = file_channel::FileHeaderResponse::new(file_id, file_channel::Response::Reject)?;
        let packet = file_channel::Packet::FileHeaderResponse(file_header_response);
        let reply = Packet::FileChannelPacket{channel, packet};
        replies.push(reply);

        Ok(connection_handle)
    }

    pub fn cancel_file_transfer(
        &mut self,
        service_id: &V3OnionServiceId,
        file_transfer_handle: FileTransferHandle,
        replies: &mut Vec<Packet>) -> Result<ConnectionHandle, Error> {

        let connection_handle = self.service_id_to_connection_handle(service_id)?;
        let connection = self.connection_mut(connection_handle)?;

        // remove the file transfer
        let file_transfer = connection.file_transfers.remove(&file_transfer_handle).ok_or(Error::FileTransferHandleToFileTransferMappingFailure(file_transfer_handle))?;

        // get the appropriate file channel
        let channel_type = match file_transfer_handle.direction {
            Direction::Incoming => ChannelType::IncomingFileTransfer,
            Direction::Outgoing => ChannelType::OutgoingFileTransfer,
        };
        let channel = connection.channel_map.channel_type_to_id(&channel_type).ok_or(Error::TargetChannelTypeNotOpen(channel_type))?;

        // verify the file transfer type matches expect by then handle
        match (file_transfer_handle.direction, file_transfer) {
            (Direction::Incoming, FileTransfer::FileDownload(_)) |
            (Direction::Outgoing, FileTransfer::FileUpload(_)) => (),
            _ => unreachable!("mismatch between file handle's direction component and the mapped file transfer type"),
        }

        // send cancellation
        let file_id = file_transfer_handle.file_id;
        let file_transfer_complete_notification = file_channel::FileTransferCompleteNotification::new(file_id, file_channel::FileTransferResult::Cancelled)?;
        let packet = file_channel::Packet::FileTransferCompleteNotification(file_transfer_complete_notification);
        let reply = Packet::FileChannelPacket{channel, packet};
        replies.push(reply);

        Ok(connection_handle)
    }

    // chunk must be less than 63*1024 bytes
    pub fn send_file_chunk(
        &mut self,
        service_id: &V3OnionServiceId,
        file_transfer_handle: FileTransferHandle,
        chunk_data: Vec<u8>,
        replies: &mut Vec<Packet>) -> Result<ConnectionHandle, Error> {

        let connection_handle = self.service_id_to_connection_handle(service_id)?;
        let connection = self.connection_mut(connection_handle)?;

        let channel_type = ChannelType::OutgoingFileTransfer;
        let channel = connection.channel_map.channel_type_to_id(&channel_type).ok_or(Error::TargetChannelTypeNotOpen(channel_type))?;

        let file_id = file_transfer_handle.file_id;
        let chunk_len = chunk_data.len();
        let file_transfer = connection.file_transfers.get_mut(&file_transfer_handle).ok_or(Error::FileTransferHandleToFileTransferMappingFailure(file_transfer_handle))?;

        // verify the file transfer type is a file upload
        let file_upload: &mut FileUpload = match file_transfer {
            FileTransfer::FileUpload(file_upload) => file_upload,
            _ => return Err(Error::FileTransferHandleToFileUploadMappingFailure(file_transfer_handle)),
        };

        // send file chunk
        let chunk_data = file_channel::ChunkData::new(chunk_data)?;
        let file_chunk = file_channel::FileChunk::new(file_id, chunk_data)?;
        let packet = file_channel::Packet::FileChunk(file_chunk);
        let reply = Packet::FileChannelPacket{channel, packet};
        replies.push(reply);

        // update our file upload progress
        file_upload.uploaded_bytes += chunk_len as u64;

        Ok(connection_handle)
    }
}
