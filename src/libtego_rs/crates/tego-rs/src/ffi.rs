// standard
use std::collections::BTreeSet;
use std::ffi::{c_char, c_int, c_void};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

// extern
use anyhow::{Result, bail};
use tor_interface::censorship_circumvention::*;
use tor_interface::proxy::*;
use tor_interface::tor_crypto::{Ed25519PrivateKey, V3OnionServiceId};
use tor_interface::tor_provider::{DomainAddr, TargetAddr};

// internal crates
use crate::context::{Context, UserData};
use crate::error::{Error, translate_failures};
use crate::file_hash::*;
use crate::macros::*;
use crate::object_map::ObjectMap;
use crate::tor_daemon_config::TorDaemonConfig;
use crate::tor_launch_config::TorLaunchConfig;
use crate::user_id::UserId;

pub const TEGO_TRUE: i32 = 1;
pub const TEGO_FALSE: i32 = 0;

pub type tego_bool = i32;

/// number of bytes in an ed25519 signature
pub const TEGO_ED25519_SIGNATURE_SIZE: usize = 64usize;
/// length of a valid v3 service id string not including null terminator
pub const TEGO_V3_ONION_SERVICE_ID_LENGTH: usize = 56usize;
/// length of a v3 service id string including null terminator
pub const TEGO_V3_ONION_SERVICE_ID_SIZE: usize = TEGO_V3_ONION_SERVICE_ID_LENGTH + 1usize;
/// length of the ed25519 keyblob string not including null terminator
pub const TEGO_ED25519_KEYBLOB_LENGTH: usize = 99usize;
/// length of an ed25519 keyblob string including null terminator
pub const TEGO_ED25519_KEYBLOB_SIZE: usize = TEGO_ED25519_KEYBLOB_LENGTH + 1usize;

pub struct tego_error;

pub(crate) type TegoKey = usize;
pub(crate) enum TegoObject {
    Error(Error),
    Context(Context),
    Ed25519PrivateKey(Ed25519PrivateKey),
    V3OnionServiceId(V3OnionServiceId),
    UserId(UserId),
    FileHash(FileHash),
    TorDaemonConfig(TorDaemonConfig),
    TorLaunchConfig(TorLaunchConfig),
}

type TegoObjectMap = ObjectMap<TegoObject>;

static OBJECT_MAP: std::sync::Mutex<TegoObjectMap> = std::sync::Mutex::new(TegoObjectMap::new());

pub(crate) fn get_object_map<'a>() -> std::sync::MutexGuard<'a, TegoObjectMap> {
    OBJECT_MAP.lock().expect("another thread panicked while holding OBJECT_MAP's mutex")
}

/// Get error message form tego_error
///
/// @param error : the error object to get the message from
/// @return : null terminated string with error message whose
///  lifetime is tied to the source tego_error_t; null pointer on failure
#[no_mangle]
pub extern "C" fn tego_error_get_message(
    error: *const tego_error) -> *const c_char {
    if error.is_null() {
        std::ptr::null()
    } else {
        let key = error as TegoKey;
        match get_object_map().get(&key) {
            Some(TegoObject::Error(err)) => {
                err.message().as_ptr()
            },
            _ => std::ptr::null(),
        }
    }
}

pub struct tego_context;

#[no_mangle]
pub extern "C" fn tego_initialize(
    out_context: *mut *mut tego_context,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(out_context);

        let object = TegoObject::Context(Default::default());
        let key = get_object_map().insert(object);
        unsafe {
            *out_context = key as *mut tego_context;
        }
        if let Some(TegoObject::Context(context)) = get_object_map().get_mut(&key) {
            context.set_tego_key(key);
        } else {
            bail!("");
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn tego_uninitialize(
    context: *mut tego_context,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(context);

        let key = context as TegoKey;
        let mut object_map = get_object_map();
        match object_map.get(&key) {
            Some(TegoObject::Context(_)) => object_map.remove(&key),
            Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        };

        Ok(())
    })
}

//
// v3 onion/ed25519 functionality
//

pub struct tego_ed25519_private_key;
pub struct tego_v3_onion_service_id;

/// Conversion method for converting the keyblob string returned by
/// ADD_ONION command into an ed25519_private_key_t
///
/// @param out_private_key : returned ed25519 private key
/// @param keyblob : an ED25519 keyblob string in the form
///  "ED25519-V3:abcd1234..."
/// @param keyblob_length : number of characters in keyblob not
///  counting the null terminator
/// @param error : filled on error

#[no_mangle]
pub extern "C" fn tego_ed25519_private_key_from_ed25519_keyblob(
    out_private_key: *mut *mut tego_ed25519_private_key,
    keyblob: *const c_char,
    keyblob_length: usize,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(out_private_key);
        bail_if_null!(keyblob);

        let keyblob = unsafe { std::slice::from_raw_parts(keyblob as *const u8, keyblob_length) };
        let keyblob = std::str::from_utf8(keyblob)?;

        let private_key = if let Ok(private_key) = Ed25519PrivateKey::from_key_blob(keyblob) {
            private_key
        } else {
            // try to fall back to legacy validation if failed
            Ed25519PrivateKey::from_key_blob_legacy(keyblob)?
        };

        let object = TegoObject::Ed25519PrivateKey(private_key);
        let key = get_object_map().insert(object);
        unsafe {
            *out_private_key = key as *mut tego_ed25519_private_key;
        }
        Ok(())
    })
}

/// Conversion method for converting an ed25519 private key
/// to a null-terminated keyblob string for use with ADD_ONION
/// command
///
/// @param out_keyblob : buffer to be filled with ed25519 keyblob in
///  the form "ED25519-V3:abcd1234...\0"
/// @param keyblob_size : size of out_keyblob buffer in bytes, must be at
///  least 100 characters (99 for string + 1 for null terminator)
/// @param private_key : the private key to encode
/// @param error : filled on error
/// @return : the number of characters written (including null terminator)
///  to out_keyblob
 #[no_mangle]
 pub extern "C" fn tego_ed25519_keyblob_from_ed25519_private_key(
    out_keyblob: *mut c_char,
    keyblob_size: usize,
    private_key: *const tego_ed25519_private_key,
    error: *mut *mut tego_error) -> usize {
    translate_failures(0usize, error, || -> Result<usize> {
        bail_if_null!(out_keyblob);
        bail_if!(keyblob_size < TEGO_ED25519_KEYBLOB_SIZE);
        bail_if_null!(private_key);

        let key = private_key as TegoKey;
        match get_object_map().get(&key) {
            Some(TegoObject::Ed25519PrivateKey(private_key)) => {
                let keyblob = private_key.to_key_blob();
                let keyblob = keyblob.as_str();
                assert!(keyblob.len() == TEGO_ED25519_KEYBLOB_LENGTH);

                unsafe {
                    let out_keyblob = std::slice::from_raw_parts_mut(out_keyblob as *mut u8, keyblob_size);
                    std::ptr::copy(
                        keyblob.as_ptr(),
                        out_keyblob.as_mut_ptr(),
                        keyblob.len());
                    out_keyblob[TEGO_ED25519_KEYBLOB_LENGTH] = 0u8;
                }
                Ok(TEGO_ED25519_KEYBLOB_SIZE)
            },
            Some(_) => bail!("not a tego_ed25519_private_key pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        }
    })
 }

/// Checks if a service id string is valid per tor rend spec:
/// https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt
///
/// @param service_id_string : string containing the v3 service id to be validated
/// @param service_id_string_length : length of service_id_string not counting the
///  null terminator
/// @param error : filled on error

#[no_mangle]
pub extern "C" fn tego_v3_onion_service_id_string_is_valid(
    service_id_string: *const c_char,
    service_id_string_length: usize,
    error: *mut *mut tego_error) -> tego_bool {
    translate_failures(TEGO_FALSE, error, || -> Result<tego_bool> {
        bail_if_null!(service_id_string);

        let service_id_string = unsafe { std::slice::from_raw_parts(service_id_string as *const u8, service_id_string_length) };
        let service_id_string = std::str::from_utf8(service_id_string)?;

        if V3OnionServiceId::is_valid(service_id_string) {
            Ok(TEGO_TRUE)
        } else {
            Ok(TEGO_FALSE)
        }
    })
}

/// Construct a service id object from string. Validates
/// the checksum and version byte per spec:
/// https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt
///
/// @param out_service_id : returned v3 onion service id
/// @param service_id_string : a string beginning with a v3 service id
/// @param service_id_string_length : length of the service id string not
///  counting the null terminator
/// @param error : filled on error
 #[no_mangle]
 pub extern "C" fn tego_v3_onion_service_id_from_string(
    out_service_id: *mut *mut tego_v3_onion_service_id,
    service_id_string: *const c_char,
    service_id_string_length: usize,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(out_service_id);
        bail_if_null!(service_id_string);

        let service_id_string = unsafe { std::slice::from_raw_parts(service_id_string as *const u8, service_id_string_length) };
        let service_id_string = std::str::from_utf8(service_id_string)?;

        let service_id = V3OnionServiceId::from_string(service_id_string)?;

        let object = TegoObject::V3OnionServiceId(service_id);
        let key = get_object_map().insert(object);
        unsafe {
            *out_service_id = key as *mut tego_v3_onion_service_id;
        }
        Ok(())
    })
 }

/// Serializes out a service id object as a null-terminated utf8 string
/// to provided character buffer.
///
/// @param service_id : v3 onion service id object to serialize
/// @param out_service_id_string : destination buffer for string
/// @param service_id_string_size : size of out_service_id_string buffer in
///  bytes, must be at least 57 bytes (56 bytes for string + null
///  terminator)
/// @param error : filled on error
/// @return : number of bytes written including null terminator;
///  TEGO_V3_ONION_SERVICE_ID_SIZE (57) on success, 0 on failure
 #[no_mangle]
 pub extern "C" fn tego_v3_onion_service_id_to_string(
    service_id: *const tego_v3_onion_service_id,
    out_service_id_string: *mut c_char,
    service_id_string_size: usize,
    error: *mut *mut tego_error) -> usize {
    translate_failures(0usize, error, || -> Result<usize> {
        bail_if_null!(service_id);
        bail_if_null!(out_service_id_string);
        bail_if!(service_id_string_size < TEGO_V3_ONION_SERVICE_ID_SIZE);

        let key = service_id as TegoKey;
        match get_object_map().get(&key) {
            Some(TegoObject::V3OnionServiceId(service_id)) => {
                let service_id = service_id.to_string();
                let service_id = service_id.as_str();
                assert!(service_id.len() == TEGO_V3_ONION_SERVICE_ID_LENGTH);

                unsafe {
                    let out_service_id_string = std::slice::from_raw_parts_mut(out_service_id_string as *mut u8, service_id_string_size);
                    std::ptr::copy(
                        service_id.as_ptr(),
                        out_service_id_string.as_mut_ptr(),
                        service_id.len());
                    out_service_id_string[TEGO_V3_ONION_SERVICE_ID_LENGTH] = 0u8;
                }
                Ok(TEGO_V3_ONION_SERVICE_ID_SIZE)
            },
            Some(_) => bail!("not a tego_v3_onion_service_id pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        }
    })
 }

//
// Chat protocol functionality
//

// user id

pub struct tego_user_id;

/// Convert a v3 onion service id to a user id
///
/// @param out_user_id : returned user id
/// @param service_id : input v3 onion service id
/// @param error : filled on error
 #[no_mangle]
pub extern "C" fn tego_user_id_from_v3_onion_service_id(
    out_user_id: *mut *mut tego_user_id,
    service_id: *const tego_v3_onion_service_id,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(out_user_id);
        bail_if_null!(service_id);

        let key = service_id as TegoKey;
        let service_id = match get_object_map().get(&key) {
            Some(TegoObject::V3OnionServiceId(service_id)) => service_id.clone(),
            Some(_) => bail!("not a tego_v3_onion_service_id pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        };

        let user_id = get_object_map().insert(TegoObject::UserId(UserId{service_id}));

        unsafe { *out_user_id = user_id as *mut tego_user_id };

        Ok(())
    })
}

/// Get the v3 onion service id from the user id
///
/// @param user_id : input user id
/// @param out_service_id : returned v3 onion service id
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_user_id_get_v3_onion_service_id(
    user_id: *const tego_user_id,
    out_service_id: *mut *mut tego_v3_onion_service_id,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(user_id);
        bail_if_null!(out_service_id);

        let key = user_id as TegoKey;
        let service_id = match get_object_map().get(&key) {
            Some(TegoObject::UserId(user_id)) => user_id.service_id.clone(),
            Some(_) => bail!("not a tego_v3_onion_service_id pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        };

        let service_id = get_object_map().insert(TegoObject::V3OnionServiceId(service_id));

        unsafe {*out_service_id = service_id as *mut tego_v3_onion_service_id};

        Ok(())
    })
}

// contacts/user methods

/// Get the host's user_id (derived from private key)
///
/// @param context : the current tego context
/// @param out_host_user : returned user id
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_get_host_user_id(
    context: *const tego_context,
    out_host_user: *mut *mut tego_user_id,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(context);
        bail_if_null!(out_host_user);

        let key = context as TegoKey;
        let service_id = match get_object_map().get(&key) {
            Some(TegoObject::Context(context)) => {
                if let Some(service_id) = context.host_service_id() {
                    service_id
                } else {
                    bail!("no host key defined");
                }
            }
            Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        };

        let host_user = get_object_map().insert(TegoObject::UserId(UserId{service_id}));

        unsafe { *out_host_user = host_user as *mut tego_user_id };
        Ok(())
    })
}

/// State of the host user's onion service
#[repr(C)]
pub enum tego_host_onion_service_state {
    tego_host_onion_service_state_none,
    tego_host_onion_service_state_service_added,
    tego_host_onion_service_state_service_published,
}

/// TODO: figure out which statuses we need later
#[repr(C)]
pub enum tego_user_status {
    tego_user_status_none,
    tego_user_status_online,
    tego_user_status_offline,
}

/// enum for user type
#[repr(C)]
pub enum tego_user_type {
    /// the host user
    tego_user_type_host,
    /// in host's contact list
    tego_user_type_allowed,
    /// users who have added host but the host has not replied yet
    tego_user_type_requesting,
    /// users who have added host but the host has rejected
    tego_user_type_blocked,
    /// users the host has added but who have not replied yet
    tego_user_type_pending,
    /// user the host has added but replied with rejection
    tego_user_type_rejected,
}

//
// Tor Config
//

pub struct tego_tor_launch_config;

/// Init a default tor configuration struct
///
/// @param out_launch_config : destination to write pointer to empty tor configuration
/// @apram error : filled on error
 #[no_mangle]
pub extern "C" fn tego_tor_launch_config_initialize(
    out_launch_config: *mut *mut tego_tor_launch_config,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(out_launch_config);

        let object = TegoObject::TorLaunchConfig(Default::default());
        let key = get_object_map().insert(object);
        unsafe {
            *out_launch_config = key as *mut tego_tor_launch_config;
        }
        Ok(())
    })
}

/// Set the root directory for the tor daemon to save/read settings
///
/// @param tor_config : config struct to save to
/// @param data_directory : our desired data directory
/// @param data_directory_length : length of data_directory string not counting the
///  null termiantor
/// @param error : filled on error
 #[no_mangle]
 pub extern "C" fn tego_tor_launch_config_set_data_directory(
    launch_config: *mut tego_tor_launch_config,
    data_directory: *const c_char,
    data_directory_length: usize,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(launch_config);
        bail_if_null!(data_directory);
        bail_if_equal!(data_directory_length, 0usize);

        let data_directory = unsafe { std::slice::from_raw_parts(data_directory as *const u8, data_directory_length) };
        let data_directory = std::str::from_utf8(data_directory)?;

        let mut object_map = get_object_map();
        let key = launch_config as TegoKey;
        let launch_config: &mut TorLaunchConfig = match object_map.get_mut(&key) {
            Some(TegoObject::TorLaunchConfig(launch_config)) => launch_config,
            Some(_) => bail!("not a tego_tor_launch_config pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        };

        let data_directory = PathBuf::from(data_directory);
        let data_directory = std::path::absolute(data_directory)?;
        launch_config.data_directory = data_directory;

        Ok(())
    })
 }

/// Start an instance of the tor daemon and associate it with the given context
///
/// @param context : the current tego context
/// @param tor_config : tor configuration params
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_start_tor(
    context: *mut tego_context,
    tor_config: *const tego_tor_launch_config,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(context);
        bail_if_null!(tor_config);

        let mut object_map = get_object_map();

        let tor_data_directory = {
            let tor_config_key = tor_config as TegoKey;
            let tor_config = match object_map.get(&tor_config_key) {
                Some(TegoObject::TorLaunchConfig(tor_config)) => tor_config,
                Some(_) => bail!("not a tego_tor_launch_config pointer: {:?}", tor_config_key as *const c_void),
                None => bail!("not a valid pointer: {:?}", tor_config_key as *const c_void),
            };
            tor_config.data_directory.clone()
        };

        let context_ptr = context;
        let context_key = context_ptr as TegoKey;
        let context = match object_map.get_mut(&context_key) {
            Some(TegoObject::Context(context)) => context,
            Some(_) => bail!("not a tego_context pointer: {:?}", context_key as *const c_void),
            None => bail!("not a valid pointer: {:?}", context_key as *const c_void),
        };

        context.set_tor_data_directory(tor_data_directory);

        let callbacks = context.callbacks.lock().expect("another thread panicked while holding callback's mutex");

        // TODO: these callbacks are required to enable the 'connect' button
        // in the network configuraiton screen
        if let Some(callback) = callbacks.on_tor_control_status_changed {
            callback(context_ptr, tego_tor_control_status::tego_tor_control_status_connected);
        }

        if let Some(callback) = callbacks.on_tor_process_status_changed {
            callback(context_ptr, tego_tor_process_status::tego_tor_process_status_running);
        }

        // we defer tor daemonn launch until after tego_context_update_tor_daemon_config
        Ok(())
    })
}

pub struct tego_tor_daemon_config;

/// Returns a tor daemon config struct with default params
///
/// @param out_config : destination for config
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_tor_daemon_config_initialize(
    out_config: *mut *mut tego_tor_daemon_config,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(out_config);

        let object = TegoObject::TorDaemonConfig(Default::default());
        let key = get_object_map().insert(object);
        unsafe {
            *out_config = key as *mut tego_tor_daemon_config;
        }
        Ok(())
    })
}

/// Set up SOCKS4 proxy params, overwrites any existing
/// proxy settings
///
/// @param config : config to update
/// @param address : proxy addess as encoded utf8 string
/// @param address_length : length of the address not counting
///  the null terminator
/// @param port : proxy port, 0 not allowed
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_tor_daemon_config_set_proxy_socks4(
    config: *mut tego_tor_daemon_config,
    address: *const c_char,
    address_length: usize,
    port: u16,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(config);
        bail_if_null!(address);
        bail_if_equal!(address_length, 0usize);
        bail_if_equal!(port, 0u16);

        // convert args to a proxy config
        let address = unsafe { std::slice::from_raw_parts(address as *const u8, address_length) };
        let address = std::str::from_utf8(address)?;

        let proxy_address = if let Ok(address) = Ipv4Addr::from_str(address) {
            let address = SocketAddr::new(IpAddr::V4(address), port);
            TargetAddr::Socket(address)
        } else if let Ok(address) = Ipv6Addr::from_str(address) {
            let address = SocketAddr::new(IpAddr::V6(address), port);
            TargetAddr::Socket(address)
        } else if let Ok(domain) = DomainAddr::try_from((address.to_string(), port)) {
            TargetAddr::Domain(domain)
        } else {
            bail!("address is not a valid proxy address: {address}");
        };

        let proxy_config = ProxyConfig::Socks4(Socks4ProxyConfig::new(proxy_address)?);

        // update the config
        let key = config as TegoKey;
        match get_object_map().get_mut(&key) {
            Some(TegoObject::TorDaemonConfig(config)) => {
                config.proxy_settings = Some(proxy_config);
            },
            Some(_) => bail!("not a tego_tor_daemon_config pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        };

        Ok(())
    })
}

/// Set up SOCKS5 proxy params, overwrites any existing
/// proxy settings
///
/// @param config : config to update
/// @param address : proxy addess encoded as utf8 string
/// @param address_length : length of the address not counting
///  any NULL terminator
/// @param port : proxy port, 0 not allowed
/// @param username : authentication username encoded as utf8
///  string, may be NULL or empty string if not needed
/// @param username_length : length of username string not counting
///  any NULL terminator
/// @param password : authentication password encoded as utf8
///  string, may be NULL or empty string if not needed
/// @param password_length : lenght of the password string not
///  counting any NULL terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_tor_daemon_config_set_proxy_socks5(
    config: *mut tego_tor_daemon_config,
    address: *const c_char,
    address_length: usize,
    port: u16,
    username: *const c_char,
    username_length: usize,
    password: *const c_char,
    password_length: usize,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(config);
        bail_if_null!(address);
        bail_if_equal!(address_length, 0usize);
        bail_if_equal!(port, 0u16);
        bail_if!(username.is_null() && username_length != 0usize);
        bail_if!(!username.is_null() && username_length == 0usize);
        bail_if!(password.is_null() && password_length != 0usize);
        bail_if!(!password.is_null() && password_length == 0usize);

        // convert args to a proxy config
        let address = unsafe { std::slice::from_raw_parts(address as *const u8, address_length) };
        let address = std::str::from_utf8(address)?;

        let proxy_address = if let Ok(address) = Ipv4Addr::from_str(address) {
            let address = SocketAddr::new(IpAddr::V4(address), port);
            TargetAddr::Socket(address)
        } else if let Ok(address) = Ipv6Addr::from_str(address) {
            let address = SocketAddr::new(IpAddr::V6(address), port);
            TargetAddr::Socket(address)
        } else if let Ok(domain) = DomainAddr::try_from((address.to_string(), port)) {
            TargetAddr::Domain(domain)
        } else {
            bail!("address is not a valid proxy address: {address}");
        };

        let username = if username.is_null() {
            None
        } else {
            let username = unsafe { std::slice::from_raw_parts(username as *const u8, username_length) };
            let username = std::str::from_utf8(username)?;
            Some(username.to_string())
        };

        let password = if password.is_null() {
            None
        } else {
            let password = unsafe { std::slice::from_raw_parts(password as *const u8, password_length) };
            let password = std::str::from_utf8(password)?;
            Some(password.to_string())
        };

        let proxy_config = ProxyConfig::Socks5(Socks5ProxyConfig::new(proxy_address, username, password)?);

        // update the config
        let key = config as TegoKey;
        match get_object_map().get_mut(&key) {
            Some(TegoObject::TorDaemonConfig(config)) => {
                config.proxy_settings = Some(proxy_config);
            },
            Some(_) => bail!("not a tego_tor_daemon_config pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        };

        Ok(())
    })
}

/// Set up HTTPS proxy params, overwrites any existing
/// proxy settings
///
/// @param config : config to update
/// @param address : proxy addess encoded as utf8 string
/// @param address_length : length of the address not counting
///  any NULL terminator
/// @param port : proxy port, 0 not allowed
/// @param username : authentication username encoded as utf8
///  string, may be NULL or empty string if not needed
/// @param username_length : length of username string not counting
///  any NULL terminator
/// @param password : authentication password encoded as utf8
///  string, may be NULL or empty string if not needed
/// @param password_length : lenght of the password string not
///  counting any NULL terminator
/// @param error : filled on error
 #[no_mangle]
 pub extern "C" fn tego_tor_daemon_config_set_proxy_https(
    config: *mut tego_tor_daemon_config,
    address: *const c_char,
    address_length: usize,
    port: u16,
    username: *const c_char,
    username_length: usize,
    password: *const c_char,
    password_length: usize,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(config);
        bail_if_null!(address);
        bail_if_equal!(address_length, 0usize);
        bail_if_equal!(port, 0u16);
        bail_if!(username.is_null() && username_length != 0usize);
        bail_if!(!username.is_null() && username_length == 0usize);
        bail_if!(password.is_null() && password_length != 0usize);
        bail_if!(!password.is_null() && password_length == 0usize);

        // convert args to a proxy config
        let address = unsafe { std::slice::from_raw_parts(address as *const u8, address_length) };
        let address = std::str::from_utf8(address)?;

        let proxy_address = if let Ok(address) = Ipv4Addr::from_str(address) {
            let address = SocketAddr::new(IpAddr::V4(address), port);
            TargetAddr::Socket(address)
        } else if let Ok(address) = Ipv6Addr::from_str(address) {
            let address = SocketAddr::new(IpAddr::V6(address), port);
            TargetAddr::Socket(address)
        } else if let Ok(domain) = DomainAddr::try_from((address.to_string(), port)) {
            TargetAddr::Domain(domain)
        } else {
            bail!("address is not a valid proxy address: {address}");
        };

        let username = if username.is_null() {
            None
        } else {
            let username = unsafe { std::slice::from_raw_parts(username as *const u8, username_length) };
            let username = std::str::from_utf8(username)?;
            Some(username.to_string())
        };

        let password = if password.is_null() {
            None
        } else {
            let password = unsafe { std::slice::from_raw_parts(password as *const u8, password_length) };
            let password = std::str::from_utf8(password)?;
            Some(password.to_string())
        };

        let proxy_config = ProxyConfig::Https(HttpsProxyConfig::new(proxy_address, username, password)?);

        // update the config
        let key = config as TegoKey;
        match get_object_map().get_mut(&key) {
            Some(TegoObject::TorDaemonConfig(config)) => {
                config.proxy_settings = Some(proxy_config);
            },
            Some(_) => bail!("not a tego_tor_daemon_config pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        };

        Ok(())
    })
}

/// Set the allowed ports the tor daemon may use
///
/// @param config : config to update
/// @param ports : array of allowed ports
/// @param ports_count : the number of ports in list
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_tor_daemon_config_set_allowed_ports(
    config: *mut tego_tor_daemon_config,
    ports: *const u16,
    ports_count: usize,
    error: *mut *mut tego_error) -> () {
        translate_failures((), error, || -> Result<()> {

        bail_if_null!(config);

        let ports: Option<Vec<u16>> = if ports.is_null() {
            None
        } else {
            let ports = unsafe { std::slice::from_raw_parts(ports, ports_count) };
            Some(ports.into())
        };

        // update the config
        let key = config as TegoKey;
        match get_object_map().get_mut(&key) {
            Some(TegoObject::TorDaemonConfig(config)) => {
                config.allowed_ports = ports;
            },
            Some(_) => bail!("not a tego_tor_daemon_config pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        };

        Ok(())
    })
}

/// Set the list of bridges for tor to use
///
/// @param config : config to update
/// @param bridge_lines : array of utf8 encoded bridge-line strings
/// @param bridge_line_lengths : array of lengths of the strings stored
///  in 'bridge_lines', does not include any NULL terminators
/// @param bridge_count : the number of bridge strings being
///  passed in
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_tor_daemon_config_set_bridges(
    config: *mut tego_tor_daemon_config,
    bridge_lines: *const *const c_char,
    bridge_line_lengths: *const usize,
    bridge_count: usize,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(config);

        let bridge_lines: Option<Vec<BridgeLine>> = if bridge_lines.is_null() {
            None
        } else {
            let bridge_lines = unsafe { std::slice::from_raw_parts(bridge_lines, bridge_count) };
            bail_if_null!(bridge_line_lengths);
            let bridge_line_lengths = unsafe { std::slice::from_raw_parts(bridge_line_lengths, bridge_count) };
            let mut bridge_line_vec: Vec<BridgeLine> = Vec::with_capacity(bridge_count);
            for (bridge_line, bridge_line_length) in bridge_lines.iter().zip(bridge_line_lengths.iter()) {
                let bridge_line = unsafe { std::slice::from_raw_parts(*bridge_line as *const u8, *bridge_line_length) };
                let bridge_line = std::str::from_utf8(bridge_line)?;
                let bridge_line = BridgeLine::from_str(bridge_line)?;

                bridge_line_vec.push(bridge_line);
            }

            Some(bridge_line_vec)
        };

        // update the config
        let key = config as TegoKey;
        match get_object_map().get_mut(&key) {
            Some(TegoObject::TorDaemonConfig(config)) => {
                config.bridge_lines = bridge_lines;
            },
            Some(_) => bail!("not a tego_tor_daemon_config pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        };

        Ok(())
    })
}

/// Update the tor daemon settings of running instance of tor associated
/// with a given tego context
///
/// @param context : the current tego context
/// @param tor_config : tor configuration params
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_update_tor_daemon_config(
    context: *mut tego_context,
    tor_config: *const tego_tor_daemon_config,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(context);
        bail_if_null!(tor_config);

        let context_ptr = context;

        let mut object_map = get_object_map();

        // TODO: add bridge and pts
        let (proxy_settings, allowed_ports) = {
            let key = tor_config as TegoKey;
            match object_map.get(&key) {
                Some(TegoObject::TorDaemonConfig(config)) => {
                    (config.proxy_settings.clone(), config.allowed_ports.clone())
                },
                Some(_) => bail!("not a tego_tor_daemon_config pointer: {:?}", key as *const c_void),
                None => bail!("not a valid pointer: {:?}", key as *const c_void),
            }
        };

        let key = context_ptr as TegoKey;
        match object_map.get_mut(&key) {
            Some(TegoObject::Context(context)) => {
                context.set_tor_config(proxy_settings, allowed_ports);

                let callbacks = context.callbacks.lock().expect("another thread panicked while holding callback's mutex");

                // TODO: remove need for this callback
                if let Some(callback) = callbacks.on_update_tor_daemon_config_succeeded {
                            callback(context_ptr, TEGO_TRUE);
                }

                Ok(())
            },
            Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        }
    })
}

/// Set the DisableNetwork flag of running instance of tor associated
/// with a given tego context
///
/// @param context : the current tego context
/// @param disable_network : TEGO_TRUE or TEGO_FALSE
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_update_disable_network_flag(
    context: *mut tego_context,
    disable_network: tego_bool,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(context);
        bail_if_not_equal!(disable_network, TEGO_FALSE);

        let context_ptr = context;

        let key = context_ptr as TegoKey;
        match get_object_map().get_mut(&key) {
            Some(TegoObject::Context(context)) => {
                context.connect()?;

                let callbacks = context.callbacks.lock().expect("another thread panicked while holding callback's mutex");

                // TODO: this callback invocation is required to move
                // the network configuration screen forward into the
                // bootstrapping progression screen
                if let Some(callback) = callbacks.on_update_tor_daemon_config_succeeded {
                    callback(context_ptr, TEGO_TRUE);
                }

            },
            Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        }
        Ok(())
    })
}

/// Start tego's onion service and try to connect to users
///
/// @param context : the current tego context
/// @param host_private_key : the hosts private ed25519 key, or null if
///  we want to create a new identity
/// @param user_buffer : the list of all users we care about
/// @param user_type_buffer : the types associated with all of our users
/// @param user_count : the length of the user and user type buffers
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_start_service(
    context: *mut tego_context,
    host_private_key: *const tego_ed25519_private_key,
    user_buffer: *const *const tego_user_id,
    user_type_buffer: *const tego_user_type,
    user_count: usize,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        // TODO: refactor so this funciton is called *after* bootstrap
        bail_if_null!(context);
        bail_if!(user_buffer.is_null() && !user_type_buffer.is_null());
        bail_if!(!user_buffer.is_null() && user_type_buffer.is_null());

        let context_ptr = context;

        let key = context_ptr as TegoKey;
        match get_object_map().get(&key) {
            Some(TegoObject::Context(context)) => bail_if!(context.private_key().is_some()),
            Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        }
        let private_key = if host_private_key.is_null() {
            let private_key = Ed25519PrivateKey::generate();
            // notify caller new identity created
            let on_new_identity_created = match get_object_map().get(&key) {
                Some(TegoObject::Context(context)) => {
                    let callbacks = context.callbacks.lock().expect("another thread panicked while holding callback's mutex");
                    callbacks.on_new_identity_created.clone()
                },
                Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
                None => bail!("not a valid pointer: {:?}", key as *const c_void),
            };
            if let Some(on_new_identity_created) = on_new_identity_created {
                let object = TegoObject::Ed25519PrivateKey(private_key.clone());
                let key = get_object_map().insert(object);
                on_new_identity_created(context_ptr, key as *const tego_ed25519_private_key);
            }
            private_key
        } else {
            let key = host_private_key as TegoKey;
            match get_object_map().get(&key) {
                Some(TegoObject::Ed25519PrivateKey(private_key)) => private_key.clone(),
                Some(_) => bail!("not a tego_ed25519_private_key pointer: {:?}", key as *const c_void),
                None => bail!("not a valid pointer: {:?}", key as *const c_void),
            }
        };

        let mut allowed: BTreeSet<V3OnionServiceId> = Default::default();
        let mut blocked: BTreeSet<V3OnionServiceId> = Default::default();

        if !user_buffer.is_null() && !user_type_buffer.is_null() {
            let user_buffer = unsafe { std::slice::from_raw_parts(user_buffer, user_count) };
            let user_type_buffer = unsafe { std::slice::from_raw_parts(user_type_buffer, user_count) };

            for (user_id, user_type) in user_buffer.iter().zip(user_type_buffer.iter()) {
                let key = *user_id as TegoKey;
                let service_id = match get_object_map().get(&key) {
                    Some(TegoObject::UserId(UserId{service_id})) => service_id.clone(),
                    Some(_) => bail!("not a tego_user_id pointer: {:?}", key as *const c_void),
                    None => bail!("not a valid pointer: {:?}", key as *const c_void),
                };

                use tego_user_type::*;
                match user_type {
                    tego_user_type_allowed => {
                        bail_if!(blocked.contains(&service_id));
                        bail_if!(!allowed.insert(service_id));
                    },
                    tego_user_type_blocked => {
                        bail_if!(allowed.contains(&service_id));
                        bail_if!(!blocked.insert(service_id));
                    },
                    tego_user_type_host => bail!("user type may not be tego_user_type_host"),
                    _ => (),
                }
            }
        }

        let key = context_ptr as TegoKey;
        match get_object_map().get_mut(&key) {
            Some(TegoObject::Context(context)) => {
                context.set_private_key(private_key);
                context.set_users(allowed, blocked);
            },
            Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        };
        Ok(())
    })
}

/// Returns the number of charactres required (including null) to
/// write out the tor logs
///
/// @param context : the current tego context
/// @param error : filled on error
/// @return : the number of characters required
#[no_mangle]
pub extern "C" fn tego_context_get_tor_logs_size(
    context: *const tego_context,
    error: *mut *mut tego_error) -> usize {
    translate_failures(0usize, error, || -> Result<usize> {
        bail_if_null!(context);

        let context_ptr = context;
        let key = context_ptr as TegoKey;
        match get_object_map().get(&key) {
            Some(TegoObject::Context(context)) => {
                Ok(context.tor_logs_size())
            },
            Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        }
    })
}

/// Fill the passed in buffer with the tor daemon's logs, each entry delimitted
/// by newline character '\n'
///
/// @param context : the current tego context
/// @param out_log_buffer : user allocated buffer where tor log is to be written
/// @param log_buffer_size : the size of the passed in out_log_buffer buffer
/// @param error : filled on error
/// @return : the nuber of characters written (including null terminator) to
///  out_log_buffer
#[no_mangle]
pub extern "C" fn tego_context_get_tor_logs(
    context: *const tego_context,
    out_log_buffer: *mut c_char,
    log_buffer_size: usize,
    error: *mut *mut tego_error) -> usize {
    translate_failures(0usize, error, || -> Result<usize> {
        bail_if_null!(context);
        bail_if_null!(out_log_buffer);

        if log_buffer_size == 0usize {
            return Ok(0usize);
        }

        let context_ptr = context;
        let key = context_ptr as TegoKey;
        match get_object_map().get(&key) {
            Some(TegoObject::Context(context)) => {
                let tor_logs = context.tor_logs();
                let tor_logs = tor_logs.as_str();

                // number of bytes to write
                let bytes = std::cmp::min(log_buffer_size - 1, tor_logs.len());

                unsafe {
                    let out_log_buffer = std::slice::from_raw_parts_mut(
                        out_log_buffer as *mut u8,
                        log_buffer_size);
                    std::ptr::copy(
                        tor_logs.as_ptr(),
                        out_log_buffer.as_mut_ptr(),
                        bytes);
                    out_log_buffer[bytes] = 0u8;
                }
                Ok(bytes)
            },
            Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        }
    })
}

/// Get the null-terminated tor version string
///
/// @param context : the curent tego context
/// @param error : filled on error
/// @return : the version string for the context's running tor daemon
#[no_mangle]
pub extern "C" fn tego_context_get_tor_version_string(
    context: *const tego_context,
    error: *mut *mut tego_error) -> *const c_char {
    translate_failures(std::ptr::null(), error, || -> Result<*const c_char> {
        bail_if_null!(context);

        let key = context as TegoKey;
        match get_object_map().get_mut(&key) {
            Some(TegoObject::Context(context)) => {
                if let Some(tor_version) = context.tor_version_string() {
                    Ok(tor_version.as_c_str().as_ptr())
                } else {
                    Ok(std::ptr::null())
                }
            },
            Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        }
    })
}

/// corresponds to Ricochet's Tor::TorControl::Status enum
#[repr(C)]
pub enum tego_tor_control_status {
    tego_tor_control_status_error = -1,
    tego_tor_control_status_not_connected,
    tego_tor_control_status_connecting,
    tego_tor_control_status_authenticating,
    tego_tor_control_status_connected,
}

/// Get the current status of our tor control channel
///
/// @param context : the current tego context
/// @param out_status : destination to save control status
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_get_tor_control_status(
    context: *const tego_context,
    out_status: *mut tego_tor_control_status,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        // TODO: remove this function
        bail_if_null!(context);
        bail_if_null!(out_status);
        unsafe { *out_status = tego_tor_control_status::tego_tor_control_status_connected; }
        Ok(())
    })
}

#[repr(C)]
pub enum tego_tor_process_status {
    tego_tor_process_status_unknown,
    tego_tor_process_status_external,
    tego_tor_process_status_not_started,
    tego_tor_process_status_starting,
    tego_tor_process_status_running,
    tego_tor_process_status_failed,
}

#[repr(C)]
pub enum tego_tor_network_status {
    tego_tor_network_status_unknown,
    tego_tor_network_status_offline,
    tego_tor_network_status_ready,
}

/// Get the current status of the tor daemon's connection
/// to the tor network
///
/// @param context : the current tego context
/// @param out_status : destination to save network status
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_get_tor_network_status(
    context: *const tego_context,
    out_status: *mut tego_tor_network_status,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(context);
        bail_if_null!(out_status);

        let key = context as TegoKey;
        match get_object_map().get(&key) {
            Some(TegoObject::Context(context)) => {
                use tego_tor_network_status::*;
                let status = if context.connect_complete() {
                    tego_tor_network_status_ready
                } else {
                    tego_tor_network_status_offline
                };

                unsafe { *out_status = status };
            },
            Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        }

        Ok(())
    })
}

#[repr(C)]
pub enum tego_tor_bootstrap_tag {
    tego_tor_bootstrap_tag_invalid = -1,
    tego_tor_bootstrap_tag_starting,
    tego_tor_bootstrap_tag_conn_pt,
    tego_tor_bootstrap_tag_conn_done_pt,
    tego_tor_bootstrap_tag_conn_proxy,
    tego_tor_bootstrap_tag_conn_done_proxy,
    tego_tor_bootstrap_tag_conn,
    tego_tor_bootstrap_tag_conn_done,
    tego_tor_bootstrap_tag_handshake,
    tego_tor_bootstrap_tag_handshake_done,
    tego_tor_bootstrap_tag_onehop_create,
    tego_tor_bootstrap_tag_requesting_status,
    tego_tor_bootstrap_tag_loading_status,
    tego_tor_bootstrap_tag_loading_keys,
    tego_tor_bootstrap_tag_requesting_descriptors,
    tego_tor_bootstrap_tag_loading_descriptors,
    tego_tor_bootstrap_tag_enough_dirinfo,
    tego_tor_bootstrap_tag_ap_conn_pt_summary,
    tego_tor_bootstrap_tag_ap_conn_done_pt,
    tego_tor_bootstrap_tag_ap_conn_proxy,
    tego_tor_bootstrap_tag_ap_conn_done_proxy,
    tego_tor_bootstrap_tag_ap_conn,
    tego_tor_bootstrap_tag_ap_conn_done,
    tego_tor_bootstrap_tag_ap_handshake,
    tego_tor_bootstrap_tag_ap_handshake_done,
    tego_tor_bootstrap_tag_circuit_create,
    tego_tor_bootstrap_tag_done,

    tego_tor_bootstrap_tag_count
}

impl From<&str> for tego_tor_bootstrap_tag {
    fn from(value: &str) -> Self {
        use tego_tor_bootstrap_tag::*;
        match value {
            "starting" => tego_tor_bootstrap_tag_starting,
            "conn_pt" => tego_tor_bootstrap_tag_conn_pt,
            "conn_done_pt" => tego_tor_bootstrap_tag_conn_done_pt,
            "conn_proxy" => tego_tor_bootstrap_tag_conn_proxy,
            "conn_done_proxy" => tego_tor_bootstrap_tag_conn_done_proxy,
            "conn" => tego_tor_bootstrap_tag_conn,
            "conn_done" => tego_tor_bootstrap_tag_conn_done,
            "handshake" => tego_tor_bootstrap_tag_handshake,
            "handshake_done" => tego_tor_bootstrap_tag_handshake_done,
            "onehop_create" => tego_tor_bootstrap_tag_onehop_create,
            "requesting_status" => tego_tor_bootstrap_tag_requesting_status,
            "loading_status" => tego_tor_bootstrap_tag_loading_status,
            "loading_keys" => tego_tor_bootstrap_tag_loading_keys,
            "requesting_descriptors" => tego_tor_bootstrap_tag_requesting_descriptors,
            "loading_descriptors" => tego_tor_bootstrap_tag_loading_descriptors,
            "enough_dirinfo" => tego_tor_bootstrap_tag_enough_dirinfo,
            "ap_conn_pt" => tego_tor_bootstrap_tag_ap_conn_pt_summary,
            "ap_conn_done_pt" => tego_tor_bootstrap_tag_ap_conn_done_pt,
            "ap_conn_proxy" => tego_tor_bootstrap_tag_ap_conn_proxy,
            "ap_conn_done_proxy" => tego_tor_bootstrap_tag_ap_conn_done_proxy,
            "ap_conn" => tego_tor_bootstrap_tag_ap_conn,
            "ap_conn_done" => tego_tor_bootstrap_tag_ap_conn_done,
            "ap_handshake" => tego_tor_bootstrap_tag_ap_handshake,
            "ap_handshake_done" => tego_tor_bootstrap_tag_ap_handshake_done,
            "circuit_create" => tego_tor_bootstrap_tag_circuit_create,
            "done" => tego_tor_bootstrap_tag_done,
            _ => tego_tor_bootstrap_tag_invalid,
        }
    }
}



/// Get the summary string associated with the given bootstrap tag
///
/// @param tag : the tag to get the summary of
/// @param error : filled on error
/// @return : utf8 null-terminated summary string, NULL on error
#[no_mangle]
pub extern "C" fn tego_tor_bootstrap_tag_to_summary(
    tag: tego_tor_bootstrap_tag,
    error: *mut *mut tego_error) -> *const c_char {
    translate_failures(std::ptr::null(), error, || -> Result<*const c_char> {
        use tego_tor_bootstrap_tag::*;
        let summary = match tag {
            tego_tor_bootstrap_tag_starting => "Starting\0",
            tego_tor_bootstrap_tag_conn_pt => "Connecting to pluggable transport\0",
            tego_tor_bootstrap_tag_conn_done_pt => "Connected to pluggable transport\0",
            tego_tor_bootstrap_tag_conn_proxy => "Connecting to proxy\0",
            tego_tor_bootstrap_tag_conn_done_proxy => "Connected to proxy\0",
            tego_tor_bootstrap_tag_conn => "Connecting to a relay\0",
            tego_tor_bootstrap_tag_conn_done => "Connected to a relay\0",
            tego_tor_bootstrap_tag_handshake => "Handshaking with a relay\0",
            tego_tor_bootstrap_tag_handshake_done => "Handshake with a relay done\0",
            tego_tor_bootstrap_tag_onehop_create => "Establishing an encrypted directory connection\0",
            tego_tor_bootstrap_tag_requesting_status => "Asking for networkstatus consensus\0",
            tego_tor_bootstrap_tag_loading_status => "Loading networkstatus consensus\0",
            tego_tor_bootstrap_tag_loading_keys => "Loading authority key certs\0",
            tego_tor_bootstrap_tag_requesting_descriptors => "Asking for relay descriptors\0",
            tego_tor_bootstrap_tag_loading_descriptors => "Loading relay descriptors\0",
            tego_tor_bootstrap_tag_enough_dirinfo => "Loaded enough directory info to build circuits\0",
            tego_tor_bootstrap_tag_ap_conn_pt_summary => "Connecting to pluggable transport to build circuits\0",
            tego_tor_bootstrap_tag_ap_conn_done_pt => "Connected to pluggable transport to build circuits\0",
            tego_tor_bootstrap_tag_ap_conn_proxy => "Connecting to proxy to build circuits\0",
            tego_tor_bootstrap_tag_ap_conn_done_proxy => "Connected to proxy to build circuits\0",
            tego_tor_bootstrap_tag_ap_conn => "Connecting to a relay to build circuits\0",
            tego_tor_bootstrap_tag_ap_conn_done => "Connected to a relay to build circuits\0",
            tego_tor_bootstrap_tag_ap_handshake => "Finishing handshake with a relay to build circuits\0",
            tego_tor_bootstrap_tag_ap_handshake_done => "Handshake finished with a relay to build circuits\0",
            tego_tor_bootstrap_tag_circuit_create => "Establishing a Tor circuit\0",
            tego_tor_bootstrap_tag_done => "Done\0",
            _ => bail!("unknown tego_tor_bootstrap_tag: {}", tag as c_int),
        };
        Ok(summary.as_ptr() as *const c_char)
    })
}

//
// Tego Chat Methods
//

/// milliseconds since 1970-01-01T00:00:00 utc.
pub type tego_time = u64;
/// unique (per user) message identifier
pub type tego_message_id = u64;
/// unique (per user) file transfer identifier
pub type tego_file_transfer_id = u64;
// struct for file hash
pub struct tego_file_hash;
/// integer type for file size
pub type tego_file_size = u64;

/// Calculates the number of bytes needed to serialize a file hash to
/// a null-terminated utf8 string
///
/// @param file_hash : file hash object to serialize
/// @param error : filled on error
/// @return : the number of bytes required to serialize fileHash including
///  the null-terinator
#[no_mangle]
pub extern "C" fn tego_file_hash_string_size(
    file_hash: *const tego_file_hash,
    error: *mut *mut tego_error) -> usize {
    translate_failures(0usize, error, || -> Result<usize> {
        bail_if_null!(file_hash);
        let file_hash = file_hash as TegoKey;
        match get_object_map().get(&file_hash) {
            Some(TegoObject::FileHash(file_hash)) => {
                Ok(FILE_HASH_STRING_SIZE)
            },
            Some(_) => bail!("not a tego_file_hash pointer: {:?}", file_hash as *const c_void),
            None => bail!("not a valid pointer: {:?}", file_hash as *const c_void),
        }
    })
}

/// Serializes out a file hash as a null-terminated utf8 string to
/// provided character buffer.
///
/// @param file_hash : file hash object to serialize
/// @param out_hash_string : destination buffer to write string
/// @param hash_string_size : size of the out_hash_string buffer in bytes
/// @param error : filled on error
/// @return : number of bytes written to out_hash_string including the
///  null-terminator
#[no_mangle]
pub extern "C" fn tego_file_hash_to_string(
    file_hash: *const tego_file_hash,
    out_hash_string: *mut c_char,
    hash_string_size: usize,
    error: *mut *mut tego_error) -> usize {
    translate_failures(0usize, error, || -> Result<usize> {
        bail_if_null!(file_hash);
        bail_if_null!(out_hash_string);
        bail_if!(hash_string_size < FILE_HASH_STRING_SIZE);

        let file_hash = file_hash as TegoKey;
        match get_object_map().get(&file_hash) {
            Some(TegoObject::FileHash(file_hash)) => {
                let hash_string = file_hash.to_string();
                unsafe {
                    let out_hash_string = std::slice::from_raw_parts_mut(out_hash_string as *mut u8, hash_string_size);
                    std::ptr::copy(
                        hash_string.as_bytes().as_ptr(),
                        out_hash_string.as_mut_ptr(),
                        FILE_HASH_STRING_LENGTH);
                    out_hash_string[FILE_HASH_STRING_LENGTH] = 0u8;
                }
                Ok(FILE_HASH_STRING_SIZE)
            },
            Some(_) => bail!("not a tego_file_hash pointer: {:?}", file_hash as *const c_void),
            None => bail!("not a valid pointer: {:?}", file_hash as *const c_void),
        }
    })
}


/// Send a text message from the host to the given user
///
/// @param context : the current tego context
/// @param user : the user to send a message to
/// @param message : utf8 text message to send
/// @param message_length : length of message not including null-terminator
/// @param out_id : filled with assigned message id for callbacks
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_send_message(
    context: *mut tego_context,
    user: *const tego_user_id,
    message: *const c_char,
    message_length: usize,
    out_id: *mut tego_message_id,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(context);
        bail_if_null!(user);
        bail_if_null!(message);
        bail_if_equal!(message_length, 0usize);
        bail_if_null!(out_id);

        let user = user as TegoKey;
        let user = match get_object_map().get(&user) {
            Some(TegoObject::UserId(user)) => {
                user.service_id.clone()
            },
            Some(_) => bail!("not a tego_user_id pointer: {:?}", user as *const c_void),
            None => bail!("not a valid pointer: {:?}", user as *const c_void),
        };

        let message = unsafe { std::slice::from_raw_parts(message as *const u8, message_length) };
        let message = std::str::from_utf8(message)?.to_string();
        use rico_protocol::v3::message::chat_channel::MessageText;
        let message: MessageText = message.try_into()?;

        let context = context as TegoKey;
        match get_object_map().get(&context) {
            Some(TegoObject::Context(context)) => {
                let message_id = context.send_message(user, message)?;
                unsafe { *out_id = message_id };
            },
            Some(_) => bail!("not a tego_context pointer: {:?}", context as *const c_void),
            None => bail!("not a valid pointer: {:?}", context as *const c_void),
        }

        Ok(())
    })
}

/// Request to send a file to the given user
///
/// @param context : the current tego context
/// @param user : the user to send a file to
/// @param file_path : utf8 path to file to send
/// @param file_path_length : length of file_path not including null-terminator
/// @param out_id : optional, filled with assigned file transfer id for callbacks
/// @param out_file_hash : optional, filled with hash of the file to send
/// @param out_file_size : optional, filled with the size of the file in bytes
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_send_file_transfer_request(
    context: *mut tego_context,
    user: *const tego_user_id,
    file_path: *const c_char,
    file_path_length: usize,
    out_id: *mut tego_file_transfer_id,
    out_file_hash: *mut *mut tego_file_hash,
    out_file_size: *mut tego_file_size,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(context);
        bail_if_null!(user);
        bail_if_null!(file_path);
        if !out_file_hash.is_null() {
            let out_file_hash = unsafe {*out_file_hash};
            bail_if_not_null!(out_file_hash);
        }
        bail_if_equal!(file_path_length, 0usize);

        let mut object_map = get_object_map();

        let context = context as TegoKey;
        let context = match object_map.get(&context) {
            Some(TegoObject::Context(context)) => context,
            Some(_) => bail!("not a tego_context pointer: {:?}", context as *const c_void),
            None => bail!("not a valid pointer: {:?}", context as *const c_void),
        };

        let user = user as TegoKey;
        let user = match object_map.get(&user) {
            Some(TegoObject::UserId(user)) => user.service_id.clone(),
            Some(_) => bail!("not a tego_user_id pointer: {:?}", user as *const c_void),
            None => bail!("not a valid pointer: {:?}", user as *const c_void),
        };

        let file_path = unsafe { std::slice::from_raw_parts(file_path as *const u8, file_path_length) };
        let file_path = std::str::from_utf8(file_path)?.to_string();
        let file_path = PathBuf::from(file_path);

        let (id, file_size) = context.send_file_transfer_request(user, file_path)?;

        // write out results
        unsafe {
            if !out_id.is_null() {
                *out_id = id;
            }
            if !out_file_size.is_null() {
                *out_file_size = file_size;
            }
        }

        Ok(())
    })
}

#[repr(C)]
pub enum tego_file_transfer_response {
    /// proceed with a file transfer
    tego_file_transfer_response_accept,
    /// reject the file transfer
    tego_file_transfer_response_reject,
}

/// Acknowledges a request to send an file_transfer
///
/// @param context : the current tego context
/// @param user : the user that sent the file transfer request
/// @param id : which file transfer to respond to
/// @param response : how to respond to the request
/// @param dest_path : optional, destination to save the file
/// @param dest_path_length : length of dest_path not including the null-terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_respond_file_transfer_request(
    context: *mut tego_context,
    user: *const tego_user_id,
    id: tego_file_transfer_id,
    response: tego_file_transfer_response,
    dest_path: *const c_char,
    dest_path_length: usize,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(context);
        bail_if_null!(user);

        let object_map = get_object_map();

        let context = context as TegoKey;
        let context = match object_map.get(&context) {
            Some(TegoObject::Context(context)) => context,
            Some(_) => bail!("not a tego_context pointer: {:?}", context as *const c_void),
            None => bail!("not a valid pointer: {:?}", context as *const c_void),
        };

        let user = user as TegoKey;
        let user = match object_map.get(&user) {
            Some(TegoObject::UserId(user)) => user.service_id.clone(),
            Some(_) => bail!("not a tego_user_id pointer: {:?}", user as *const c_void),
            None => bail!("not a valid pointer: {:?}", user as *const c_void),
        };

        match response {
            tego_file_transfer_response::tego_file_transfer_response_accept => {
                bail_if_null!(dest_path);
                bail_if_equal!(dest_path_length, 0usize);
                let dest_path = unsafe { std::slice::from_raw_parts(dest_path as *const u8, dest_path_length) };
                let dest_path = std::str::from_utf8(dest_path)?.to_string();
                let dest_path = PathBuf::from(dest_path);

                context.accept_file_transfer_request(user, id, dest_path)?;
            },
            tego_file_transfer_response::tego_file_transfer_response_reject => {
                bail_if_not_null!(dest_path);
                bail_if_not_equal!(dest_path_length, 0usize);

                context.reject_file_transfer_request(user, id)?;
            },
            _ => bail!("not a valid tego_file_transfer_response: {}", response as c_int),
        }

        Ok(())
    })
}

/// Cancel an in-progress file transfer
///
/// @param context : the current tego context
/// @param user : the user that is sending/receiving the transfer
/// @param id : the file transfer to cancel
/// @param error: filled on error
#[no_mangle]
pub extern "C" fn tego_context_cancel_file_transfer(
    context: *mut tego_context,
    user: *const tego_user_id,
    id: tego_file_transfer_id,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        bail_if_null!(context);
        bail_if_null!(user);

        let object_map = get_object_map();

        let context = context as TegoKey;
        let context = match object_map.get(&context) {
            Some(TegoObject::Context(context)) => context,
            Some(_) => bail!("not a tego_context pointer: {:?}", context as *const c_void),
            None => bail!("not a valid pointer: {:?}", context as *const c_void),
        };

        let user = user as TegoKey;
        let user = match object_map.get(&user) {
            Some(TegoObject::UserId(user)) => user.service_id.clone(),
            Some(_) => bail!("not a tego_user_id pointer: {:?}", user as *const c_void),
            None => bail!("not a valid pointer: {:?}", user as *const c_void),
        };

        context.cancel_file_transfer(user, id)?;

        Ok(())
    })
}

/// Sends a request to chat to a user
///
/// @param context : the current tego context
/// @param user : the user we want to chat with
/// @param mesage : utf8 text greeting message to send
/// @param message_length : length of message not including null-terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_send_chat_request(
    context: *mut tego_context,
    user: *const tego_user_id,
    message: *const c_char,
    message_length: usize,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        let key = user as TegoKey;
        let service_id = match get_object_map().get(&key) {
            Some(TegoObject::UserId(user_id)) => {
                user_id.service_id.clone()
            },
            Some(_) => bail!("not a tego_user_id pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        };

        let message = unsafe { std::slice::from_raw_parts(message as *const u8, message_length) };
        let message = std::str::from_utf8(message)?.to_string();
        use rico_protocol::v3::message::contact_request_channel::MessageText;
        let message: MessageText = message.try_into()?;

        let key = context as TegoKey;
        match get_object_map().get(&key) {
            Some(TegoObject::Context(context)) => {
                context.send_contact_request(service_id, message);
            },
            Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        }

        Ok(())
    })
}

#[repr(C)]
pub enum tego_chat_acknowledge {
    /// allows the user to chat with us
    tego_chat_acknowledge_accept,
    // do not allow the user to chat with us
    tego_chat_acknowledge_reject,
    // do not allow and reject all future requests
    tego_chat_acknowledge_block,
}

/// Acknowledges chat request sent from another user. Would be called after receiving
/// a chat_request_received callback.
///
/// @param context : the current tego context
/// @param user : the user that sent the chat request
/// @param response : how to respond to the request
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_acknowledge_chat_request(
    context: *mut tego_context,
    user: *const tego_user_id,
    response: tego_chat_acknowledge,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {

        let key = user as TegoKey;
        let service_id = match get_object_map().get(&key) {
            Some(TegoObject::UserId(user_id)) => {
                user_id.service_id.clone()
            },
            Some(_) => bail!("not a tego_user_id pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        };

        let key = context as TegoKey;
        match get_object_map().get(&key) {
            Some(TegoObject::Context(context)) => {
                context.acknowledge_contact_request(service_id, response)
            },
            Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
            None => bail!("not a valid pointer: {:?}", key as *const c_void),
        }

        Ok(())
    })
}

/// Forget about a given user, said user will be removed
/// from all internal lists and will be needed to be re-added
/// to chat
///
/// @param context : the current tego context
/// @param user : the user to forget
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_forget_user(
    _context: *mut tego_context,
    _user: *const tego_user_id,
    error: *mut *mut tego_error) -> () {
    translate_failures((), error, || -> Result<()> {
        println!("tego_context_forget_user() not implemented");
        bail_not_implemented!()
    })
}

//
// Callbacks for frontend to respond to events
// Provides no guarantees on what thread they are running on or thread safety
// All parameters (such as tego_error*) are automatically destroyed after user
//  callback is invoked, so duplicate/marshall data as necessary
//

/// TODO: remove the origin param once we better understand how errors are routed through the UI
/// temporarily used by the error callback
#[repr(C)]
pub enum tego_tor_error_origin {
    tego_tor_error_origin_control,
    tego_tor_error_origin_manager,
}

/// Callback fired when an error relating to Tor occurs, unrelated to an existing
/// execution context (ie a function being called)
///
/// @param context : the current tego context
/// @param origin : which legacy Qt component the error came from
/// @param error : error containing our message
pub type tego_tor_error_occurred_callback = Option<
    extern "C" fn(
        context: *mut tego_context,
        origin: tego_tor_error_origin,
        error: *const tego_error,
    ) -> ()
>;

/// TODO: this should go away and only exists for the ricochet Qt UI :(
///  saving the daemon config should probably just be synchrynous
/// Callback fired after we attempt to save the tor configuration
///
/// @param context : the current tego context
/// @param out_success : where the result is saved, TEGO_TRUE on success, else TEGO_FALSE
pub type tego_update_tor_daemon_config_succeeded_callback = Option<
    extern "C" fn(
        context: *mut tego_context,
        success: tego_bool
    ) -> ()
>;

/// Callback fired when the tor control port status has changed
///
/// @param context : the current tego context
/// @param status : the new control status
pub type tego_tor_control_status_changed_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        status: tego_tor_control_status,
    ) -> ()
>;

/// Callback fired when the tor daemon process' status changes
///
/// @param context : the current tego context
/// @param status : the new process status
pub type tego_tor_process_status_changed_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        status: tego_tor_process_status,
    ) -> ()
>;

/// Callback fired when the tor daemon's network status changes
///
/// @param context : the current tego context
/// @param status : the new network status
pub type tego_tor_network_status_changed_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        status: tego_tor_network_status,
    ) -> ()
>;

/// Callback fired when tor's bootstrap status changes
///
/// @param context : the current tego context
/// @param progress : the bootstrap progress percent
/// @param tag : the bootstrap tag
pub type tego_tor_bootstrap_status_changed_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        progress: i32,
        tag: tego_tor_bootstrap_tag,
    ) -> ()
>;

/// Callback fired when a log entry is received from the tor daemon
///
/// @param context : the current tego context
/// @param message : a null-terminated log entry string
/// @param message_length : length of the message not including null-terminator
pub type tego_tor_log_received_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        message: *const c_char,
        message_length: usize
    ) -> ()
>;

/// Callback fired when the host user state changes
///
/// @param context : the current tego context
/// @param state : the current host user state
pub type tego_host_onion_service_state_changed_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        state: tego_host_onion_service_state,
    ) -> ()
>;

/// Callback fired when the host receives a chat request from another user
///
/// @param context : the current tego context
/// @param sender : the user that wants to chat
/// @param message : null-terminated message string received from the requesting user
/// @param message_length : length of the message not including null-terminator
pub type tego_chat_request_received_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        sender: *const tego_user_id,
        message: *const c_char,
        message_length: usize,
    ) -> ()
>;

/// Callback fired when the host receives a response to their sent chat request
///
/// @param context : the current tego context
/// @param sender : the user responding to our chat request
/// @param accepted_request : TEGO_TRUE if request accepted, TEGO_FALSE if rejected
pub type tego_chat_request_response_received_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        sender: *const tego_user_id,
        accepted_request: tego_bool,
    ) -> ()
>;

/// Callback fired when the host receives a message from another user
///
/// @param context : the current tego context
/// @param sender : the user that sent host the message
/// @param timestamp : the time the message was sent
/// @param message_id : id of the message received
/// @param message : null-terminated message string
/// @param message_length : length of the message not including null-terminator
pub type tego_message_received_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        sender: *const tego_user_id,
        timestamp: tego_time,
        message_id: tego_message_id,
        message: *const c_char,
        message_length: usize,
    ) -> ()
>;

/// Callback fired when a chat message is received and acknowledge
/// by the recipient
///
/// @param context : the current tego context
/// @param user_id : the user the message was sent to
/// @param message_id : id of the message being acknowledged
/// @param message_acked : TEGO_TRUE if acknowledged, TEGO_FALSE if error
pub type tego_message_acknowledged_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        user_id: *const tego_user_id,
        message_id: tego_message_id,
        message_acked: tego_bool,
    ) -> ()
>;

/// Callback fired when a user wants to send recipient a file
///
/// @param context : the current tego context
/// @param sender : the user sending the request
/// @param id : id of the file transfer received
/// @param file_name : name of the file user wants to send
/// @param file_name_length : length of file_name not including the null-terminator
/// @param file_size : size of the file in bytes
/// @param file_hash : hash of the file
pub type tego_file_transfer_request_received_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        sender: *const tego_user_id,
        id: tego_file_transfer_id,
        file_name: *const c_char,
        file_name_length: usize,
        file_size: tego_file_size,
        file_hash: *const tego_file_hash,
    ) -> ()
>;

/// Callback fired when a file transfer request message is received and
/// acknowledged by the recipient (not whether the recipient wishes to start
/// the file transfer)
///
/// @param context : the current tego cotext
/// @param receiver : the user acknowledging our request
/// @param id : the id of the file transfer that is being acknowledged
/// @param request_acked : TEGO_TRUE if acknowledged, TEGO_FALSE if error
 pub type tego_file_transfer_request_acknowledged_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        receiver: *const tego_user_id,
        id: tego_file_transfer_id,
        request_acked: tego_bool,
    ) -> ()
>;

/// Callback fired when the user responds to an file transfer request
///
/// @param context : the current tego context
/// @param receiver : the user accepting or rejecting our request
/// @param id : the id of the file transfer that is being accepted
/// @param response : TEGO_TRUE if the recipients wants to recevie
///  our file, TEGO_FALSE otherwise
pub type tego_file_transfer_request_response_received_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        receiver: *const tego_user_id,
        id: tego_file_transfer_id,
        response: tego_file_transfer_response,
    ) -> ()
>;

#[repr(C)]
pub enum tego_file_transfer_direction {
    tego_file_transfer_direction_sending,
    tego_file_transfer_direction_receiving,
}

/// Callback fired when file transfer send or receive progress has changed
/// This callback is fired for both the sender and the receiver
///
/// @param context : the current tego context
/// @param user_id : the user sending/receiving the file
/// @param id : the file transfer associated with this callback
/// @param direction : the direction this file is going
/// @param bytes_complete : number of bytes sent/received
/// @param bytes_total : the total size of the file
pub type tego_file_transfer_progress_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        user_id: *const tego_user_id,
        id: tego_file_transfer_id,
        direction: tego_file_transfer_direction,
        bytes_complete: tego_file_size,
        bytes_total: tego_file_size,
    ) -> ()
>;

#[repr(C)]
pub enum tego_file_transfer_result {
    /// file transfer completed successfully
    tego_file_transfer_result_success,
    /// file transfer failed for unknown reason
    tego_file_transfer_result_failure,
    /// file transfer was cancelled by one of the participants after it had started
    tego_file_transfer_result_cancelled,
    /// file transfer request was rejected by the receiver
    tego_file_transfer_result_rejected,
    /// file transfer completed but final file's hash did not match the one advertised
    tego_file_transfer_result_bad_hash,
    /// file transfer failed due to connectivity problem
    tego_file_transfer_result_network_error,
    /// file transfer failed due to a file system error
    tego_file_transfer_result_filesystem_error,
}

/// Callback fired when a file transfer has completed
/// either successfully or in error
///
/// @param context : the current tego context
/// @param user_id : the user sending/receivintg the file
/// @param id : the file transfer associated with this callback
/// @param direction : the direction this file was going
/// @param result : how the transfer completed
pub type tego_file_transfer_complete_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        user_id: *const tego_user_id,
        id: tego_file_transfer_id,
        direction: tego_file_transfer_direction,
        result: tego_file_transfer_result,
    ) -> ()
>;

/// Callback fired when a user's status changes
///
/// @param context : the current tego context
/// @param user : the user whose status has changed
/// @param status: the user's new status
pub type tego_user_status_changed_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        user: *const tego_user_id,
        status: tego_user_status,
    ) -> ()
>;

/// Callback fired when tor creates a new onion service for
/// the host
///
/// @param context : the current tego context
/// @param private_key : the host's private key
 pub type tego_new_identity_created_callback = Option<
    extern "C" fn (
        context: *mut tego_context,
        private_key: *const tego_ed25519_private_key,
    ) -> ()
>;

//
// Setters for various callbacks
//

macro_rules! impl_callback_setter {
    ($dest:ident, $context:expr, $callback:expr, $error:expr) => {
        translate_failures((), $error, || -> Result<()> {
            let key = $context as TegoKey;
            match get_object_map().get_mut(&key) {
                Some(TegoObject::Context(context)) => {
                    let mut callbacks = context.callbacks.lock().expect("another thread panicked while holding callback's mutex");
                    callbacks.$dest = $callback;
                },
                Some(_) => bail!("not a tego_context pointer: {:?}", key as *const c_void),
                None => bail!("not a valid pointer: {:?}", key as *const c_void),
            };
            Ok(())
        })
    }
}

#[no_mangle]
pub extern "C" fn tego_context_set_tor_error_occurred_callback(
    context: *mut tego_context,
    callback: tego_tor_error_occurred_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_tor_error_occurred, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_update_tor_daemon_config_succeeded_callback(
    context: *mut tego_context,
    callback: tego_update_tor_daemon_config_succeeded_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_update_tor_daemon_config_succeeded, context, callback, error);

}

#[no_mangle]
pub extern "C" fn tego_context_set_tor_control_status_changed_callback(
    context: *mut tego_context,
    callback: tego_tor_control_status_changed_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_tor_control_status_changed, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_tor_process_status_changed_callback(
    context: *mut tego_context,
    callback: tego_tor_process_status_changed_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_tor_process_status_changed, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_tor_network_status_changed_callback(
    context: *mut tego_context,
    callback: tego_tor_network_status_changed_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_tor_network_status_changed, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_tor_bootstrap_status_changed_callback(
    context: *mut tego_context,
    callback: tego_tor_bootstrap_status_changed_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_tor_bootstrap_status_changed, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_tor_log_received_callback(
    context: *mut tego_context,
    callback: tego_tor_log_received_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_tor_log_received, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_host_onion_service_state_changed_callback(
    context: *mut tego_context,
    callback: tego_host_onion_service_state_changed_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_host_onion_service_state_changed, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_chat_request_received_callback(
    context: *mut tego_context,
    callback: tego_chat_request_received_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_chat_request_received, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_chat_request_response_received_callback(
    context: *mut tego_context,
    callback: tego_chat_request_response_received_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_chat_request_response_received, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_message_received_callback(
    context: *mut tego_context,
    callback: tego_message_received_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_message_received, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_message_acknowledged_callback(
    context: *mut tego_context,
    callback: tego_message_acknowledged_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_message_acknowledged, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_file_transfer_request_received_callback(
    context: *mut tego_context,
    callback: tego_file_transfer_request_received_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_file_transfer_request_received, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_file_transfer_request_acknowledged_callback(
    context: *mut tego_context,
    callback: tego_file_transfer_request_acknowledged_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_file_transfer_request_acknowledged, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_file_transfer_request_response_received_callback(
    context: *mut tego_context,
    callback: tego_file_transfer_request_response_received_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_file_transfer_request_response_received, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_file_transfer_progress_callback(
    context: *mut tego_context,
    callback: tego_file_transfer_progress_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_file_transfer_progress, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_file_transfer_complete_callback(
    context: *mut tego_context,
    callback: tego_file_transfer_complete_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_file_transfer_complete, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_user_status_changed_callback(
    context: *mut tego_context,
    callback: tego_user_status_changed_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_user_status_changed, context, callback, error);
}

#[no_mangle]
pub extern "C" fn tego_context_set_new_identity_created_callback(
    context: *mut tego_context,
    callback: tego_new_identity_created_callback,
    error: *mut *mut tego_error) -> () {
    impl_callback_setter!(on_new_identity_created, context, callback, error);
}

//
// Destructors for various tego types
//

macro_rules! impl_deleter {
    ($tego_object:pat, $value:expr) => {
        let key = $value as TegoKey;
        let mut object_map = get_object_map();
        if let Some($tego_object) = object_map.get(&key) {
            object_map.remove(&key);
        }
    }
}

#[no_mangle]
pub extern "C" fn tego_error_delete(value: *mut tego_error) -> () {
    impl_deleter!(TegoObject::Error(_), value);
}

#[no_mangle]
pub extern "C" fn tego_ed25519_private_key_delete(value: *mut tego_ed25519_private_key) -> () {
    impl_deleter!(TegoObject::Ed25519PrivateKey(_), value);
}

#[no_mangle]
pub extern "C" fn tego_v3_onion_service_id_delete(value: *mut tego_v3_onion_service_id) -> () {
    impl_deleter!(TegoObject::V3OnionServiceId(_), value);
}

#[no_mangle]
pub extern "C" fn tego_user_id_delete(value: *mut tego_user_id) -> () {
    impl_deleter!(TegoObject::UserId(_), value);
}

#[no_mangle]
pub extern "C" fn tego_tor_launch_config_delete(value: *mut tego_tor_launch_config) -> () {
    impl_deleter!(TegoObject::TorLaunchConfig(_), value);
}

#[no_mangle]
pub extern "C" fn tego_tor_daemon_config_delete(value: *mut tego_tor_daemon_config) -> () {
    impl_deleter!(TegoObject::TorDaemonConfig(_), value);
}

#[no_mangle]
pub extern "C" fn tego_file_hash_delete(value: *mut tego_file_hash) -> () {
    impl_deleter!(TegoObject::FileHash(_), value);
}
