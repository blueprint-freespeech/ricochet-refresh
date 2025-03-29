// std
use std::collections::BTreeMap;

// extern
use rand::{TryRngCore, rngs::OsRng};
use tor_interface::tor_crypto::{Ed25519PublicKey, Ed25519Signature, V3OnionServiceId};

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
                    Packet::ControlChannelPacket(packet) => {
                        packet.write_to_vec(v)?;
                        0u16
                    },
                    Packet::CloseChannelPacket{channel} => {
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
                    _ => unreachable!(),
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
pub enum Channel {
    Control,
    Chat,
    AuthHiddenService{
        client_cookie: [u8; auth_hidden_service::CLIENT_COOKIE_SIZE],
        server_cookie: [u8; auth_hidden_service::SERVER_COOKIE_SIZE],
    },
    FileTransfer,
}

#[derive(Debug, PartialEq)]
enum Direction {
    Incoming,
    Outgoing,
}

struct Connection {
    channel_map: BTreeMap<u16, Channel>,
    target: Option<V3OnionServiceId>,
    direction: Direction,
    peer_service_id: Option<V3OnionServiceId>
}

pub type ConnectionHandle = u32;
pub const INVALID_CONNECTION_HANDLE: ConnectionHandle = 0xffffffffu32;

pub enum Event {
    IntroductionReceived{
        reply: Packet,
    },
    IntroductionResponseReceived,
    OpenChannelAuthHiddenServiceReceived{
        reply: Packet,
    },
    ClientAuthenticated{
        reply: Packet,
        service_id: V3OnionServiceId,
    },
    ChannelClosed{
        channel: u16,
        data: Channel
    },
    ProtocolFailure{
        message: String
    },
    FatalProtocolFailure,
}

pub struct PacketHandler {
    next_connection_handle: ConnectionHandle,
    connections: BTreeMap<ConnectionHandle, Connection>,
    service_id: V3OnionServiceId,
}


impl PacketHandler {
    pub fn new(service_id: V3OnionServiceId) -> Self {
        Self {
            next_connection_handle: Default::default(),
            connections: Default::default(),
            service_id,
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
                    let packet = match channel_map.get(&channel) {
                        Some(Channel::Control) => {
                            let packet = control_channel::Packet::try_from(bytes)?;
                            Packet::ControlChannelPacket(packet)
                        },
                        Some(Channel::Chat) => {
                            let packet = chat_channel::Packet::try_from(bytes)?;
                            Packet::ChatChannelPacket{channel, packet}
                        },
                        Some(Channel::AuthHiddenService{..}) => {
                            let packet = auth_hidden_service::Packet::try_from(bytes)?;
                            Packet::AuthHiddenServicePacket{channel, packet}
                        },
                        Some(Channel::FileTransfer) => {
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
    // TODO: maybe this should be a Result<Event, Error>
    pub fn handle_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        packet: Packet) -> Result<Option<Event>, Error> {

        match packet {
            Packet::IntroductionPacket(packet) => self.handle_introduction_packet(connection_handle, packet),
            Packet::IntroductionResponsePacket(packet) => self.handle_introduction_response_packet(connection_handle, packet),
            Packet::ControlChannelPacket(packet) => self.handle_control_channel_packet(connection_handle, packet),
            Packet::CloseChannelPacket{channel} => self.handle_close_channel_packet(connection_handle, channel),
            Packet::ChatChannelPacket{channel, packet} => self.handle_chat_channel_packet(connection_handle, channel, packet),
            Packet::AuthHiddenServicePacket{channel, packet} => self.handle_auth_hidden_service_packet(connection_handle, channel, packet),
            Packet::FileChannelPacket{channel, packet} => self.handle_file_channel_packet(connection_handle, channel, packet),
        }
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
        packet: introduction::IntroductionPacket) -> Result<Option<Event>, Error> {

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
            Ok(Some(Event::FatalProtocolFailure))
        } else {
            let version = if packet.versions().contains(&Version::RicochetRefresh3) {
                let mut connection = self.connection_mut(connection_handle)?;
                let _ = connection.channel_map.insert(0u16, Channel::Control);
                Some(Version::RicochetRefresh3)
            } else {
                // version not supported
                let _ = self.connections.remove(&connection_handle);
                None
            };

            let reply = Packet::IntroductionResponsePacket(IntroductionResponsePacket{version});
            Ok(Some(Event::IntroductionReceived{reply}))
        }
    }

    fn handle_introduction_response_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        packet: introduction::IntroductionResponsePacket) -> Result<Option<Event>, Error> {

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
            Ok(Some(Event::FatalProtocolFailure))
        } else {
            if let Some(Version::RicochetRefresh3) = packet.version {
                let mut connection = self.connection_mut(connection_handle)?;
                let _ = connection.channel_map.insert(0u16, Channel::Control);
                Ok(Some(Event::IntroductionResponseReceived))
            } else {
                // version not supported
                let _ = self.connections.remove(&connection_handle);
                Ok(Some(Event::FatalProtocolFailure))
            }
        }
    }

    fn handle_control_channel_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        packet: control_channel::Packet) -> Result<Option<Event>, Error> {

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
                    connection.channel_map.contains_key(&channel_identifier)
                };
                if protocol_failure {
                    let _ = self.connections.remove(&connection_handle);
                    return Ok(Some(Event::FatalProtocolFailure))
                }

                use control_channel::{ChannelResultExtension, ChannelResult, ChannelType, OpenChannelExtension};
                match (open_channel.channel_type(), open_channel.extension()) {
                    // AuthHiddenService
                    (ChannelType::AuthHiddenService, Some(OpenChannelExtension::AuthHiddenService(extension))) => {

                        // build ChannelResult packet
                        let mut server_cookie: [u8; auth_hidden_service::SERVER_COOKIE_SIZE] = Default::default();
                        OsRng.try_fill_bytes(&mut server_cookie)
                            .map_err(Error::RandOsError)?;
                        let channel_result_extension = ChannelResultExtension::AuthHiddenService(auth_hidden_service::ChannelResult{server_cookie: server_cookie.clone()});

                        // save off channel state
                        let client_cookie = extension.client_cookie;
                        let mut connection = self.connection_mut(connection_handle)?;
                        // TODO: handle channel already exists?
                        connection.channel_map.insert(channel_identifier, Channel::AuthHiddenService{client_cookie, server_cookie});

                        // buld reply packet
                        let channel_result = ChannelResult::new(
                            channel_identifier as i32,
                            true,
                            None,
                            Some(channel_result_extension))?;
                        let packet = control_channel::Packet::ChannelResult(channel_result);
                        let reply = Packet::ControlChannelPacket(packet);

                        Ok(Some(Event::OpenChannelAuthHiddenServiceReceived{reply}))
                    },
                    _ => Err(Error::NotImplemented)
                }
            },
            control_channel::Packet::ChannelResult(channel_result) => Err(Error::NotImplemented)
        }
    }

    fn handle_close_channel_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        channel: u16) -> Result<Option<Event>, Error> {
        let connection = self.connection_mut(connection_handle)?;
        if let Some(data) = connection.channel_map.remove(&channel) {
            Ok(Some(Event::ChannelClosed{channel, data}))
        } else {
            Ok(Some(Event::ProtocolFailure{message:
                format!("requested closing channel which does not exist: {channel}")}))
        }
    }

    fn handle_chat_channel_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        channel: u16,
        packet: chat_channel::Packet) -> Result<Option<Event>, Error> {
        Err(Error::NotImplemented)
    }

    fn handle_auth_hidden_service_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        channel: u16,
        packet: auth_hidden_service::Packet) -> Result<Option<Event>, Error> {

        match packet {
            auth_hidden_service::Packet::Proof(proof) => {
                let protocol_failure = {
                    let connection = self.connection(connection_handle)?;

                    // only connecting clients should be sending a proof packet
                    connection.direction != Direction::Incoming ||
                    // channel has wrong data
                    match connection.channel_map.get(&channel) {
                        Some(Channel::AuthHiddenService{..}) => false,
                        _ => true
                    }
                };
                if protocol_failure {
                    let _ = self.connections.remove(&connection_handle);
                    return Ok(Some(Event::FatalProtocolFailure))
                }

                let server_service_id = self.service_id.clone();
                let mut connection = self.connection_mut(connection_handle)?;
                match connection.channel_map.get(&channel) {
                    Some(Channel::AuthHiddenService{client_cookie, server_cookie}) => {
                        let client_service_id = proof.service_id();

                        let message = auth_hidden_service::Proof::message(
                            client_cookie,
                            server_cookie,
                            client_service_id,
                            &server_service_id);

                        let signature = Ed25519Signature::from_raw(proof.signature()).expect("ed25519 signature creation should never fail");

                        let client_public_key = Ed25519PublicKey::from_service_id(client_service_id).expect("v3 onion service id to ed25519 public key conversion should never fail");

                        if signature.verify(&message, &client_public_key) {
                            connection.peer_service_id = Some(client_service_id.clone());

                            // build reply packet
                            // TODO: handle known contacts
                            let result = auth_hidden_service::Result::new(true, Some(false))?;
                            let packet = auth_hidden_service::Packet::Result(result);
                            let reply = Packet::AuthHiddenServicePacket{channel, packet};

                            let service_id = client_service_id.clone();
                            Ok(Some(Event::ClientAuthenticated{service_id, reply}))
                        } else {
                            println!("bad signature, impersonator!");
                            let _ = self.connections.remove(&connection_handle);
                            Ok(Some(Event::FatalProtocolFailure))
                        }
                    },
                    _ => unreachable!("already verified this is an auth hiddnen service channel"),
                }
            },
            _ => Err(Error::NotImplemented)
        }
    }

    fn handle_file_channel_packet(
        &mut self,
        connection_handle: ConnectionHandle,
        channel: u16,
        packet: file_channel::Packet) -> Result<Option<Event>, Error> {
        Err(Error::NotImplemented)
    }

    pub fn new_outgoing_connection(&self, service_id: V3OnionServiceId) -> ConnectionHandle {
        INVALID_CONNECTION_HANDLE
    }

    pub fn new_incoming_connection(&mut self) -> ConnectionHandle {
        let handle = self.next_connection_handle;
        self.next_connection_handle += 1u32;

        let connection = Connection{
            channel_map: Default::default(),
            target: None,
            direction: Direction::Incoming,
            peer_service_id: None,
        };

        self.connections.insert(handle, connection);

        handle
    }
}
