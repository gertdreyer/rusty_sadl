use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
use serde_bytes::ByteBuf;
pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    } else {
        ByteBuf::from(v).serialize(s)
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    if d.is_human_readable() {
        let base64 = String::deserialize(d)?;
        base64::decode(base64.as_bytes()).map_err(serde::de::Error::custom)
    } else {
        let data = ByteBuf::deserialize(d)?;
        Ok(data.to_vec())
    }
}
