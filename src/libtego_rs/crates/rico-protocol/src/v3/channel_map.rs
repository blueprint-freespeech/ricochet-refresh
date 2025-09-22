// std
use std::collections::{BTreeMap, btree_map::Entry};

// internal
use crate::v3::Error;
use crate::v3::message::auth_hidden_service;

#[derive(Debug, PartialEq)]
pub(crate) enum ChannelData {
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

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ChannelType {
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

impl From<&ChannelData> for ChannelType {
    fn from(channel_data: &ChannelData) -> ChannelType {
        match channel_data {
            ChannelData::Control => ChannelType::Control,
            ChannelData::IncomingChat => ChannelType::IncomingChat,
            ChannelData::OutgoingChat => ChannelType::OutgoingChat,
            ChannelData::IncomingContactRequest => ChannelType::IncomingContactRequest,
            ChannelData::OutgoingContactRequest => ChannelType::OutgoingContactRequest,
            ChannelData::IncomingAuthHiddenService{..} => ChannelType::IncomingAuthHiddenService,
            ChannelData::OutgoingAuthHiddenService{..} => ChannelType::OutgoingAuthHiddenService,
            ChannelData::IncomingFileTransfer => ChannelType::IncomingFileTransfer,
            ChannelData::OutgoingFileTransfer => ChannelType::OutgoingFileTransfer,
        }
    }
}

#[derive(Default)]
pub(crate) struct ChannelMap {
    type_to_id: BTreeMap<ChannelType, u16>,
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
        channel_type: &ChannelType) -> Option<u16> {
        self.type_to_id.get(channel_type).copied()
    }

    pub fn channel_id_to_type(
        &self,
        channel_id: &u16) -> Option<ChannelType> {
        self.id_to_channel.get(channel_id).map(|channel| channel.into())
    }

    pub fn insert(
        &mut self,
        channel_id: u16,
        channel_data: ChannelData) -> Result<(), Error> {

        let channel_type: ChannelType = (&channel_data).into();

        match (self.id_to_channel.entry(channel_id), self.type_to_id.entry(channel_type)) {
            (Entry::Vacant(data), Entry::Vacant(id)) => {
                data.insert(channel_data);
                id.insert(channel_id);
                Ok(())
            },
            (Entry::Occupied(_), _) => Err(Error::ChannelAlreadyOpen(channel_id)),
            (_, Entry::Occupied(_)) => Err(Error::ChannelTypeAlreadyOpen(channel_type)),
        }
    }

    pub fn get_by_id(
        &self,
        channel_id: &u16) -> Option<&ChannelData> {
        self.id_to_channel.get(channel_id)
    }

    pub fn remove_by_id(
        &mut self,
        channel_id: &u16) -> Option<ChannelData> {
        if let Some(channel) = self.id_to_channel.remove(channel_id) {
            let channel_type: ChannelType = (&channel).into();
            self.type_to_id.remove(&channel_type).expect("ChannelMap corrupted");
            Some(channel)
        } else {
            None
        }
    }
}
