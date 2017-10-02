use itoa;
use json;
use std::collections::BTreeMap;

use datatype::Error;


pub struct CanonicalJson;

impl CanonicalJson {
    pub fn convert(value: json::Value) -> Result<Vec<u8>, Error> {
        let json = JsonValue::from(value)?;
        let mut buf = Vec::new();
        json.write(&mut buf)?;
        Ok(buf)
    }
}


enum JsonNumber {
    I64(i64),
    U64(u64),
}

enum JsonValue {
    Array(Vec<JsonValue>),
    Bool(bool),
    Null,
    Number(JsonNumber),
    Object(BTreeMap<String, JsonValue>),
    String(String),
}

impl JsonValue {
    fn from(value: json::Value) -> Result<JsonValue, Error> {
        match value {
            json::Value::Null => Ok(JsonValue::Null),
            json::Value::Bool(b) => Ok(JsonValue::Bool(b)),
            json::Value::Number(n) => {
                n.as_i64()
                    .map(JsonNumber::I64)
                    .or_else(|| n.as_u64().map(JsonNumber::U64))
                    .map(JsonValue::Number)
                    .ok_or_else(|| Error::Canonical(format!("couldn't parse as i64 or u64: {}", n)))
            }
            json::Value::Array(arr) => {
                let vals = arr.into_iter().map(Self::from).collect::<Result<Vec<_>, _>>()?;
                Ok(JsonValue::Array(vals))
            }
            json::Value::Object(obj) => {
                let out = obj.into_iter()
                    .map(|(key, val)| Ok((key, Self::from(val)?)))
                    .collect::<Result<BTreeMap<_, _>, Error>>()?;
                Ok(JsonValue::Object(out))
            }
            json::Value::String(s) => Ok(JsonValue::String(s)),
        }
    }

    fn write(&self, mut buf: &mut Vec<u8>) -> Result<(), Error> {
        match *self {
            JsonValue::Null => Ok(buf.extend(b"null")),
            JsonValue::Bool(true) => Ok(buf.extend(b"true")),
            JsonValue::Bool(false) => Ok(buf.extend(b"false")),
            JsonValue::Number(JsonNumber::I64(n)) => Ok(itoa::write(buf, n).map(|_| ())?),
            JsonValue::Number(JsonNumber::U64(n)) => Ok(itoa::write(buf, n).map(|_| ())?),
            JsonValue::String(ref s) => Ok(Self::write_str(&mut buf, s)?),
            JsonValue::Array(ref arr) => {
                buf.push(b'[');
                let mut first = true;
                for val in arr {
                    if first {
                        first = false;
                    } else {
                        buf.push(b',');
                    }
                    val.write(&mut buf)?;
                }
                Ok(buf.push(b']'))
            }
            JsonValue::Object(ref obj) => {
                buf.push(b'{');
                let mut first = true;
                for (key, val) in obj.iter() {
                    if first {
                        first = false;
                    } else {
                        buf.push(b',');
                    }
                    Self::write_str(&mut buf, key)?;
                    buf.push(b':');
                    val.write(&mut buf)?;
                }
                Ok(buf.push(b'}'))
            }
        }
    }

    fn write_str(buf: &mut Vec<u8>, input: &str) -> Result<(), Error> {
        let val = json::to_value(json::Value::String(input.into()))?;
        Ok(buf.extend(json::to_string(&val)?.as_bytes()))
    }
}


#[cfg(test)]
mod test {
    use super::*;


    #[test]
    fn canonical_string() {
        let input = JsonValue::String("\"quotes\" and \\backslashes\\".into());
        let mut buf = Vec::new();
        input.write(&mut buf).expect("write failed");
        assert_eq!(&buf, br#""\"quotes\" and \\backslashes\\""#);
    }

    #[test]
    fn canonical_array() {
        let input = JsonValue::Array(vec![
            JsonValue::String("mixed types".into()),
            JsonValue::Number(JsonNumber::U64(123)),
            JsonValue::Bool(true),
        ]);
        let mut buf = Vec::new();
        input.write(&mut buf).expect("write failed");
        assert_eq!(&buf, b"[\"mixed types\",123,true]");
    }

    #[test]
    fn canonical_object() {
        let mut map = BTreeMap::new();
        let _ = map.insert("some key".into(), JsonValue::Array(vec![
            JsonValue::String("some val array".into()),
            JsonValue::Number(JsonNumber::I64(-1)),
        ]));
        let input = JsonValue::Object(map);
        let mut buf = Vec::new();
        input.write(&mut buf).expect("write failed");
        assert_eq!(&buf, &"{\"some key\":[\"some val array\",-1]}".as_bytes());
    }
}
