// standard
use std::ffi::CString;

// internal crates
use crate::ffi::{get_object_map, tego_error, TegoObject};

pub(crate) struct Error {
    message: CString,
}

impl Error {
    pub fn new(message: &str) -> Self {
        let message = CString::new(message).unwrap_or_default();
        Self { message }
    }

    pub fn message(&self) -> &CString {
        &self.message
    }
}

/// Wrapper around rust code which may panic or return a failing Result to be used at FFI boundaries.
/// Converts panics or error Results into Error if a memory location is provided.
///
/// @param default: The default value to return in the event of failure
/// @param out_error: A pointer to pointer to Error 'struct' for the C FFI
/// @param closure: The functionality we need to encapsulate behind the error handling logic
/// @return The result of closure() on success, or the value of default on failure.
pub(crate) fn translate_failures<R, F>(default: R, out_error: *mut *mut tego_error, closure: F) -> R
where
    F: FnOnce() -> anyhow::Result<R> + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(closure) {
        // handle success
        Ok(Ok(retval)) => retval,
        // handle runtime error
        Ok(Err(err)) => {
            if !out_error.is_null() {
                // populate error with runtime error message
                let error = Error::new(format!("{:?}", err).as_str());
                let object = TegoObject::Error(error);
                let key = get_object_map().insert(object);
                unsafe {
                    *out_error = key as *mut tego_error;
                };
            }
            default
        }
        // handle panic
        Err(_) => {
            if !out_error.is_null() {
                // populate error with panic message
                let error = Error::new("panic occurred");
                let object = TegoObject::Error(error);
                let key = get_object_map().insert(object);
                unsafe {
                    *out_error = key as *mut tego_error;
                };
            }
            default
        }
    }
}
