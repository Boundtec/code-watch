use serde::Serialize;

/// The serde name of a unit-variant enum, so text output and `--json` can never disagree.
pub(crate) fn wire_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => String::new(),
    }
}

/// Implements `Display` for enums with `#[serde(rename_all = ...)]` using their serde names.
macro_rules! display_as_wire_name {
    ($($ty:ty),+ $(,)?) => {$(
        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&crate::names::wire_name(self))
            }
        }
    )+};
}
pub(crate) use display_as_wire_name;
