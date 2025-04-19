// std
use std::collections::BTreeMap;

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

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ChannelDataType {
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
pub(crate) struct ChannelMap {
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
