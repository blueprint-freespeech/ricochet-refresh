use tor_interface::tor_crypto::V3OnionServiceId;

pub(crate) struct UserId {
    pub service_id: V3OnionServiceId,
}
