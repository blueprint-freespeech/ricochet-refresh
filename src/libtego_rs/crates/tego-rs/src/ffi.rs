// standard
use std::ffi::c_char;

// internal crates
use crate::object_map::ObjectMap;

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




/// Get error message form tego_error
///
/// @param error : the error object to get the message from
/// @return : null terminated string with error message whose
///  lifetime is tied to the source tego_error_t
#[no_mangle]
pub extern "C" fn tego_error_get_message(
    _error: *const tego_error) -> *const c_char {
    std::ptr::null()
}

pub struct tego_context;

#[no_mangle]
pub extern "C" fn tego_initialize(
    _out_context: *mut *mut tego_context,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_uninitialize(
    _context: *mut tego_context,
    _error: *mut *mut tego_error) -> () {
}

//
// v3 onion/ed25519 functionality
//

pub struct tego_ed25519_private_key;
pub struct tego_ed25519_public_key;
pub struct tego_ed25519_signature;
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
    _out_private_key: *mut *mut tego_ed25519_private_key,
    _keyblob: *const c_char,
    _keyblob_length: usize,
    _error: *mut *mut tego_error) -> () {
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
    _out_keyblob: *mut c_char,
    _keyblob_size: usize,
    _private_key: *const tego_ed25519_private_key,
    _error: *mut *mut tego_error) -> usize {
    0usize
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
    _service_id_string: *const c_char,
    _service_id_string_length: usize,
    _error: *mut *mut tego_error) -> tego_bool {
    TEGO_FALSE
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
    _out_service_id: *mut *mut tego_v3_onion_service_id,
    _service_id_string: *const c_char,
    _service_id_string_length: usize,
    _error: *mut *mut tego_error) -> () {
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
    _service_id: *const tego_v3_onion_service_id,
    _out_service_id_string: *mut c_char,
    _service_id_string_size: usize,
    _error: *mut *mut tego_error) -> usize {
    0
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
    _out_user_id: *mut *mut tego_user_id,
    _service_id: *const tego_v3_onion_service_id,
    _error: *mut *mut tego_error) -> () {
}

/// Get the v3 onion service id from the user id
///
/// @param user_id : input user id
/// @param out_service_id : returned v3 onion service id
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_user_id_get_v3_onion_service_id(
    _user_id: *const tego_user_id,
    _out_service_id: *mut *mut tego_v3_onion_service_id,
    _error: *mut *mut tego_error) -> () {
}

// contacts/user methods

/// Get the host's user_id (derived from private key)
///
/// @param context : the current tego context
/// @param out_host_user : returned user id
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_get_host_user_id(
    _context: *const tego_context,
    _out_host_user: *mut *mut tego_user_id,
    _error: *mut *mut tego_error) -> () {
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
    _out_launch_config: *mut *mut tego_tor_launch_config,
    _error: *mut *mut tego_error) -> () {
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
    _launch_config: *mut tego_tor_launch_config,
    _data_directory: *const c_char,
    _data_directory_length: usize,
    _error: *mut *mut tego_error) -> () {
 }

/// Start an instance of the tor daemon and associate it with the given context
///
/// @param context : the current tego context
/// @param tor_config : tor configuration params
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_start_tor(
    _context: *mut tego_context,
    _tor_config: *const tego_tor_launch_config,
    _error: *mut *mut tego_error) -> () {
}

pub struct tego_tor_daemon_config;

/// Returns a tor daemon config struct with default params
///
/// @param out_config : destination for config
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_tor_daemon_config_initialize(
    _out_config: *mut *mut tego_tor_daemon_config,
    _error: *mut *mut tego_error) -> () {
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
    _config: *mut tego_tor_daemon_config,
    _address: *const c_char,
    _address_length: usize,
    _port: u16,
    _error: *mut *mut tego_error) -> () {
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
    _config: *mut tego_tor_daemon_config,
    _address: *const c_char,
    _address_length: usize,
    _port: u16,
    _username: *const c_char,
    _username_length: usize,
    _password: *const c_char,
    _password_length: usize,
    _error: *mut *mut tego_error) -> () {
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
    _config: *mut tego_tor_daemon_config,
    _address: *const c_char,
    _address_length: usize,
    _port: u16,
    _username: *const c_char,
    _username_length: usize,
    _password: *const c_char,
    _password_length: usize,
    _error: *mut *mut tego_error) -> () {
}

/// Set the allowed ports the tor daemon may use
///
/// @param config : config to update
/// @param ports : array of allowed ports
/// @param ports_count : the number of ports in list
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_tor_daemon_config_set_allowed_ports(
    _config: *mut tego_tor_daemon_config,
    _ports: *const u16,
    _ports_count: usize,
    _error: *mut *mut tego_error) -> () {
}

/// Set the list of bridges for tor to use
///
/// @param config : config to update
/// @param bridges : array of utf8 encoded bridge strings
/// @param bridge_lengths : array of lengths of the strings stored
///  in 'bridges', does not include any NULL terminators
/// @param bridge_count : the number of bridge strings being
///  passed in
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_tor_daemon_config_set_bridges(
    _config: *mut tego_tor_daemon_config,
    _bridges: *const *const c_char,
    _bridge_lengths: *const usize,
    _bridge_count: usize,
    _error: *mut *mut tego_error) -> () {
}

/// Update the tor daemon settings of running instance of tor associated
/// with a given tego context
///
/// @param context : the current tego context
/// @param tor_config : tor configuration params
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_update_tor_daemon_config(
    _context: *mut tego_context,
    _tor_config: *const tego_tor_daemon_config,
    _error: *mut *mut tego_error) -> () {
}

/// Set the DisableNetwork flag of running instance of tor associated
/// with a given tego context
///
/// @param context : the current tego context
/// @param disable_network : TEGO_TRUE or TEGO_FALSE
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_update_disable_network_flag(
    _context: *mut tego_context,
    _disable_network: tego_bool,
    _error: *mut *mut tego_error) -> () {
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
    _context: *mut tego_context,
    _host_private_key: *const tego_ed25519_private_key,
    _user_buffer: *const *const tego_user_id,
    _user_type_buffer: *const tego_user_type,
    _user_count: usize,
    _error: *mut *mut tego_error) -> () {
}

/// Returns the number of charactres required (including null) to
/// write out the tor logs
///
/// @param context : the current tego context
/// @param error : filled on error
/// @return : the number of characters required
#[no_mangle]
pub extern "C" fn tego_context_get_tor_logs_size(
    _context: *const tego_context,
    _error: *mut *mut tego_error) -> usize {
    0usize
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
    _context: *const tego_context,
    _out_log_buffer: *mut c_char,
    _log_buffer_size: usize,
    _error: *mut *mut tego_error) -> usize {
    0usize
}

/// Get the null-terminated tor version string
///
/// @param context : the curent tego context
/// @param error : filled on error
/// @return : the version string for the context's running tor daemon
#[no_mangle]
pub extern "C" fn tego_context_get_tor_version_string(
    _context: *const tego_context,
    _error: *mut *mut tego_error) -> *const c_char {
    std::ptr::null()
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
    _context: *const tego_context,
    _out_status: *mut tego_tor_control_status,
    _error: *mut *mut tego_error) -> () {
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
    tego_tor_network_status_ready,
    tego_tor_network_status_offline,
}

/// Get the current status of the tor daemon's connection
/// to the tor network
///
/// @param context : the current tego context
/// @param out_status : destination to save network status
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn tego_context_get_tor_network_status(
    _context: *const tego_context,
    _out_status: *mut tego_tor_network_status,
    _error: *mut *mut tego_error) -> () {
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

/// Get the summary string associated with the given bootstrap tag
///
/// @param tag : the tag to get the summary of
/// @param error : filled on error
/// @return : utf8 null-terminated summary string, NULL on error
#[no_mangle]
pub extern "C" fn tego_tor_bootstrap_tag_to_summary(
    _tag: tego_tor_bootstrap_tag,
    _error: *mut *mut tego_error) -> *const c_char {
    std::ptr::null()
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
    _file_hash: *const tego_file_hash,
    _error: *mut *mut tego_error) -> usize {
    0usize
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
    _file_hash: *const tego_file_hash,
    _out_hash_string: *mut c_char,
    _hash_string_size: usize,
    _error: *mut *mut tego_error) -> usize {
    0usize
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
    _context: *mut tego_context,
    _user: *const tego_user_id,
    _message: *const c_char,
    _message_length: usize,
    _out_id: *mut tego_message_id,
    _error: *mut *mut tego_error) -> () {
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
    _context: *mut tego_context,
    _user: *const tego_user_id,
    _file_path: *const c_char,
    _file_path_length: usize,
    _out_id: *mut tego_file_transfer_id,
    _out_file_hash: *mut *mut tego_file_hash,
    _out_file_size: *mut tego_file_size,
    _error: *mut *mut tego_error) -> () {
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
    _context: *mut tego_context,
    _user: *const tego_user_id,
    _id: tego_file_transfer_id,
    _response: tego_file_transfer_response,
    _dest_path: *const c_char,
    _dest_path_length: usize,
    _error: *mut *mut tego_error) -> () {
}

/// Cancel an in-progress file transfer
///
/// @param context : the current tego context
/// @param user : the user that is sending/receiving the transfer
/// @param id : the file transfer to cancel
/// @param error: filled on error
#[no_mangle]
pub extern "C" fn tego_context_cancel_file_transfer(
    _context: *mut tego_context,
    _user: *const tego_user_id,
    _id: tego_file_transfer_id,
    _error: *mut *mut tego_error) -> () {
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
    _context: *mut tego_context,
    _user: *const tego_user_id,
    _message: *const c_char,
    _message_length: usize,
    _error: *mut *mut tego_error) -> () {
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
    _context: *mut tego_context,
    _user: *const tego_user_id,
    _response: tego_chat_acknowledge,
    _error: *mut *mut tego_error) -> () {
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
    _error: *mut *mut tego_error) -> () {
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
// Setters for varoius callbacks
//

#[no_mangle]
pub extern "C" fn tego_context_set_tor_error_occurred_callback(
    _context: *mut tego_context,
    _callback: tego_tor_error_occurred_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_update_tor_daemon_config_succeeded_callback(
    _context: *mut tego_context,
    _callback: tego_update_tor_daemon_config_succeeded_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_tor_control_status_changed_callback(
    _context: *mut tego_context,
    _callback: tego_tor_control_status_changed_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_tor_process_status_changed_callback(
    _context: *mut tego_context,
    _callback: tego_tor_process_status_changed_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_tor_network_status_changed_callback(
    _context: *mut tego_context,
    _callback: tego_tor_network_status_changed_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_tor_bootstrap_status_changed_callback(
    _context: *mut tego_context,
    _callback: tego_tor_bootstrap_status_changed_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_tor_log_received_callback(
    _context: *mut tego_context,
    _callback: tego_tor_log_received_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_host_onion_service_state_changed_callback(
    _context: *mut tego_context,
    _callback: tego_host_onion_service_state_changed_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_chat_request_received_callback(
    _context: *mut tego_context,
    _callback: tego_chat_request_received_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_chat_request_response_received_callback(
    _context: *mut tego_context,
    _callback: tego_chat_request_response_received_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_message_received_callback(
    _context: *mut tego_context,
    _callback: tego_message_received_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_message_acknowledged_callback(
    _context: *mut tego_context,
    _callback: tego_message_acknowledged_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_file_transfer_request_received_callback(
    _context: *mut tego_context,
    _callback: tego_file_transfer_request_received_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_file_transfer_request_acknowledged_callback(
    _context: *mut tego_context,
    _callback: tego_file_transfer_request_acknowledged_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_file_transfer_request_response_received_callback(
    _context: *mut tego_context,
    _callback: tego_file_transfer_request_response_received_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_file_transfer_progress_callback(
    _context: *mut tego_context,
    _callback: tego_file_transfer_progress_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_file_transfer_complete_callback(
    _context: *mut tego_context,
    _callback: tego_file_transfer_complete_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_user_status_changed_callback(
    _context: *mut tego_context,
    _callback: tego_user_status_changed_callback,
    _error: *mut *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_context_set_new_identity_created_callback(
    _context: *mut tego_context,
    _callback: tego_new_identity_created_callback,
    _error: *mut *mut tego_error) -> () {
}

//
// Destructors for various tego types
//

#[no_mangle]
pub extern "C" fn tego_error_delete(_value: *mut tego_error) -> () {
}

#[no_mangle]
pub extern "C" fn tego_ed25519_private_key_delete(_value: *mut tego_ed25519_private_key) -> () {
}

#[no_mangle]
pub extern "C" fn tego_ed25519_public_key_delete(_value: *mut tego_ed25519_public_key) -> () {
}

#[no_mangle]
pub extern "C" fn tego_ed25519_signature_delete(_value: *mut tego_ed25519_signature) -> () {
}

#[no_mangle]
pub extern "C" fn tego_v3_onion_service_id_delete(_value: *mut tego_v3_onion_service_id) -> () {
}

#[no_mangle]
pub extern "C" fn tego_user_id_delete(_value: *mut tego_user_id) -> () {
}

#[no_mangle]
pub extern "C" fn tego_tor_launch_config_delete(_value: *mut tego_tor_launch_config) -> () {
}

#[no_mangle]
pub extern "C" fn tego_tor_daemon_config_delete(_value: *mut tego_tor_daemon_config) -> () {
}

#[no_mangle]
pub extern "C" fn tego_file_hash_delete(_value: *mut tego_file_hash) -> () {
}
