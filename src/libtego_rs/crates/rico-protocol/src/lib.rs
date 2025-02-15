#![doc = include_str!("../README.md")]

mod v3;

// usage: https://github.com/stepancheg/rust-protobuf/blob/master/protobuf-examples/pure-vs-protoc/src/main.rs

use protobuf::Message;

pub fn func() -> () {
    println!("hello world");

    use crate::v3::protos::AuthHiddenService::Packet;


    let bytes: Vec<u8> = Default::default();
    let _packet = Packet::parse_from_bytes(&bytes).unwrap();
}
