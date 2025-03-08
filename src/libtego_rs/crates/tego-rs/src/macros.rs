//extern
use anyhow::bail;
use paste::paste;

macro_rules! bail_not_implemented {
    () => {
        bail!("not implemented")
    }
}
pub(crate) use bail_not_implemented;

//
// Argument validation macros
//
// ensure pointer is not null
macro_rules! bail_if_null {
    ($ptr:ident) => {
        paste::paste! {
            if $ptr.is_null() {
                bail!(stringify!([<$ptr>] must not be null));
            }
        }
    };
}
pub(crate) use bail_if_null;
