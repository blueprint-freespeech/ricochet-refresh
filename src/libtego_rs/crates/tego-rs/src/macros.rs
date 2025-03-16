macro_rules! bail_not_implemented {
    () => {
        anyhow::bail!("not implemented")
    }
}
pub(crate) use bail_not_implemented;

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
