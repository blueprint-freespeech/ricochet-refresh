//
// Argument validation macros
//

//
macro_rules! bail_if {
    ($cond:expr) => {
        if $cond {
            anyhow::bail!(stringify!([<$cond>] must not be true));
}
    };
}
pub(crate) use bail_if;

// ensure pointer is not null
macro_rules! bail_if_null {
    ($ptr:ident) => {
        if $ptr.is_null() {
            anyhow::bail!(stringify!([<$ptr>] must not be null));
        }
    };
}
pub(crate) use bail_if_null;

// ensure pointer is null
macro_rules! bail_if_not_null {
    ($ptr:ident) => {
        if !$ptr.is_null() {
            anyhow::bail!(stringify!([<$ptr>] must be null));
        }
    };
}
pub(crate) use bail_if_not_null;

// ensure values are not equal
macro_rules! bail_if_equal {
    ($left:expr, $right:expr) => {
        if $left == $right {
            anyhow::bail!(stringify!([<$left>] must not be equal [<$right>]));
        }
    };
}
pub(crate) use bail_if_equal;

// ensure values are equal
macro_rules! bail_if_not_equal {
    ($left:expr, $right:expr) => {
        if $left != $right {
            anyhow::bail!(stringify!([<$left>] must equal [<$right>]));
        }
    };
}
pub(crate) use bail_if_not_equal;

//
// logging macros
//

macro_rules! log_error {
    ($($arg:tt)*) => {{
        #[cfg(feature = "logging")]
        crate::logger::Logger::log(crate::logger::LogLevel::Error, format!($($arg)*))
    }};
}
pub(crate) use log_error;

macro_rules! log_info {
    ($($arg:tt)*) => {{
        #[cfg(feature = "logging")]
        crate::logger::Logger::log(crate::logger::LogLevel::Info, format!($($arg)*))
    }};
}
pub(crate) use log_info;

#[cfg(feature = "logging")]
macro_rules! func {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let func = type_name_of(f);
        func.strip_suffix("::f").unwrap().to_string()
    }};
}
#[cfg(feature = "logging")]
pub(crate) use func;

macro_rules! log_trace {
    () => {{
        #[cfg(feature = "logging")]
        crate::logger::Logger::log(crate::logger::LogLevel::Trace, format!("{} in {}:{}", func!(), std::file!(), std::line!()))
    }};
    ($($arg:tt)*) => {{
        #[cfg(feature = "logging")]
        crate::logger::Logger::log(crate::logger::LogLevel::Trace, format!("{} in {}:{} {}", func!(), std::file!(), std::line!(), format!($($arg)*)))
    }};
}
pub(crate) use log_trace;

macro_rules! log_packet {
    ($($arg:tt)*) => {{
        #[cfg(feature = "logging")]
        crate::logger::Logger::log(crate::logger::LogLevel::Packet, format!($($arg)*))
    }};
}
pub(crate) use log_packet;
