use dbus::{FromMessageItem, MessageItem};
use toml::{decode, Table, Value};

use datatype::{InstalledFirmware, InstalledPackage, OperationResult};


static MISSING_ARG: &'static str = "Error.MissingArgument";
static MALFORMED_ARG: &'static str = "Error.MalformedArgument";

/// Format a `DBus` error message indicating a missing argument.
pub fn missing_arg() -> (&'static str, String) {
    (MISSING_ARG, "Missing argument".to_string())
}

/// Format a `DBus` error message indicating a malformed argument.
pub fn malformed_arg() -> (&'static str, String) {
    (MALFORMED_ARG, "Malformed argument".to_string())
}


struct DecodedValue(pub Value);

impl<'m> FromMessageItem<'m> for DecodedValue {
    fn from(m: &'m MessageItem) -> Result<Self, ()> {
        match *m {
            MessageItem::Str(ref b)     => Ok(DecodedValue(Value::String(b.clone()))),
            MessageItem::Bool(ref b)    => Ok(DecodedValue(Value::Boolean(*b))),
            MessageItem::Byte(ref b)    => Ok(DecodedValue(Value::Integer(*b as i64))),
            MessageItem::Int16(ref b)   => Ok(DecodedValue(Value::Integer(*b as i64))),
            MessageItem::Int32(ref b)   => Ok(DecodedValue(Value::Integer(*b as i64))),
            MessageItem::Int64(ref b)   => Ok(DecodedValue(Value::Integer(*b as i64))),
            MessageItem::UInt16(ref b)  => Ok(DecodedValue(Value::Integer(*b as i64))),
            MessageItem::UInt32(ref b)  => Ok(DecodedValue(Value::Integer(*b as i64))),
            MessageItem::UInt64(ref b)  => Ok(DecodedValue(Value::Integer(*b as i64))),
            MessageItem::Variant(ref b) => FromMessageItem::from(&**b),
            _                           => Err(())
        }
    }
}


struct DecodedStruct(pub Value);

impl<'m> FromMessageItem<'m> for DecodedStruct {
    fn from(item: &'m MessageItem) -> Result<Self, ()> {
        let items: &Vec<MessageItem> = try!(FromMessageItem::from(item));
        items.iter().map(|entry| {
            let entry: Result<(&MessageItem, &MessageItem), ()> = FromMessageItem::from(entry);
            entry.and_then(|(key, val)| {
                let key: Result<&String,()> = FromMessageItem::from(key);
                key.and_then(|key| {
                    let val: Result<DecodedValue,()> = FromMessageItem::from(val);
                    val.map(|val| (key.clone(), val.0))
                })
            })
        }).collect::<Result<Vec<(_, _)>, ()>>()
          .map(|arr| DecodedStruct(Value::Table(arr.into_iter().collect::<Table>())))
    }
}


impl<'m> FromMessageItem<'m> for OperationResult {
    fn from(item: &'m MessageItem) -> Result<Self, ()> {
        let item: DecodedStruct = try!(FromMessageItem::from(item));
        decode::<OperationResult>(item.0).ok_or(())
    }
}

impl<'m> FromMessageItem<'m> for InstalledPackage {
    fn from(item: &'m MessageItem) -> Result<Self, ()> {
        let item: DecodedStruct = try!(FromMessageItem::from(item));
        decode::<InstalledPackage>(item.0).ok_or(())
    }
}

impl<'m> FromMessageItem<'m> for InstalledFirmware {
    fn from(item: &'m MessageItem) -> Result<Self, ()> {
        let item: DecodedStruct = try!(FromMessageItem::from(item));
        decode::<InstalledFirmware>(item.0).ok_or(())
    }
}
