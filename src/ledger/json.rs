use std::fmt;

pub(super) const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct JsonError(pub String);

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for JsonError {}

impl Json {
    pub(super) fn parse(input: &str) -> Result<Self, JsonError> {
        let mut parser = Parser { input, pos: 0 };
        let value = parser.value()?;
        parser.ws();
        if parser.pos != input.len() {
            return Err(JsonError("trailing data after JSON value".into()));
        }
        Ok(value)
    }

    pub(super) fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    pub(super) fn as_array(&self) -> Option<&[Json]> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    pub(super) fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub(super) fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub(super) fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(value) if integer_text(value) => value.parse().ok(),
            _ => None,
        }
    }

    pub(super) fn get(&self, key: &str) -> Option<&Json> {
        object_get(self.as_object()?, key)
    }
}

pub(super) fn object_get<'a>(object: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    object
        .iter()
        .find_map(|(name, value)| (name == key).then_some(value))
}

pub(super) fn object_string<'a>(object: &'a [(String, Json)], key: &str) -> Option<&'a str> {
    object_get(object, key)?.as_str()
}

pub(super) fn object_u64(object: &[(String, Json)], key: &str) -> Option<u64> {
    object_get(object, key)?.as_u64()
}

pub(super) fn object_bool(object: &[(String, Json)], key: &str) -> Option<bool> {
    object_get(object, key)?.as_bool()
}

pub(super) fn jcs(value: &Json) -> Result<String, JsonError> {
    let mut output = String::new();
    write_jcs(value, &mut output)?;
    Ok(output)
}

fn write_jcs(value: &Json, output: &mut String) -> Result<(), JsonError> {
    match value {
        Json::Null => output.push_str("null"),
        Json::Bool(true) => output.push_str("true"),
        Json::Bool(false) => output.push_str("false"),
        Json::Number(value) => {
            if !integer_text(value) {
                return Err(JsonError(
                    "canonical Governance requests forbid floating-point JSON numbers".into(),
                ));
            }
            let number: i64 = value
                .parse()
                .map_err(|_| JsonError("JSON integer is outside the supported range".into()))?;
            if number.unsigned_abs() > MAX_SAFE_INTEGER as u64 {
                return Err(JsonError(
                    "JCS integer exceeds the IEEE-754 safe-integer range".into(),
                ));
            }
            output.push_str(&number.to_string());
        }
        Json::String(value) => write_json_string(value, output),
        Json::Array(values) => {
            output.push('[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_jcs(item, output)?;
            }
            output.push(']');
        }
        Json::Object(values) => {
            let mut ordered = values.iter().collect::<Vec<_>>();
            ordered.sort_by(|left, right| utf16_cmp(&left.0, &right.0));
            output.push('{');
            for (index, (key, item)) in ordered.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_json_string(key, output);
                output.push(':');
                write_jcs(item, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn utf16_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    let left = left.encode_utf16().collect::<Vec<_>>();
    let right = right.encode_utf16().collect::<Vec<_>>();
    left.cmp(&right)
}

fn write_json_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{0009}' => output.push_str("\\t"),
            '\u{000a}' => output.push_str("\\n"),
            '\u{000c}' => output.push_str("\\f"),
            '\u{000d}' => output.push_str("\\r"),
            value if value <= '\u{001f}' => {
                output.push_str(&format!("\\u{:04x}", value as u32));
            }
            value => output.push(value),
        }
    }
    output.push('"');
}

fn integer_text(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(['.', 'e', 'E', '+'])
        && value
            .strip_prefix('-')
            .unwrap_or(value)
            .bytes()
            .all(|byte| byte.is_ascii_digit())
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while let Some(byte) = self.input.as_bytes().get(self.pos) {
            if byte.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn value(&mut self) -> Result<Json, JsonError> {
        self.ws();
        match self.peek_byte()? {
            b'n' => {
                self.literal("null")?;
                Ok(Json::Null)
            }
            b't' => {
                self.literal("true")?;
                Ok(Json::Bool(true))
            }
            b'f' => {
                self.literal("false")?;
                Ok(Json::Bool(false))
            }
            b'"' => Ok(Json::String(self.string()?)),
            b'[' => self.array(),
            b'{' => self.object(),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(JsonError("unsupported JSON token".into())),
        }
    }

    fn peek_byte(&self) -> Result<u8, JsonError> {
        self.input
            .as_bytes()
            .get(self.pos)
            .copied()
            .ok_or_else(|| JsonError("unexpected end of JSON".into()))
    }

    fn literal(&mut self, literal: &str) -> Result<(), JsonError> {
        if self.input[self.pos..].starts_with(literal) {
            self.pos += literal.len();
            Ok(())
        } else {
            Err(JsonError("invalid JSON literal".into()))
        }
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.pos += 1;
        let mut output = String::new();
        while self.pos < self.input.len() {
            let byte = self.input.as_bytes()[self.pos];
            if byte == b'"' {
                self.pos += 1;
                return Ok(output);
            }
            if byte == b'\\' {
                self.pos += 1;
                let escape = self.peek_byte()?;
                self.pos += 1;
                match escape {
                    b'"' => output.push('"'),
                    b'\\' => output.push('\\'),
                    b'/' => output.push('/'),
                    b'b' => output.push('\u{0008}'),
                    b'f' => output.push('\u{000c}'),
                    b'n' => output.push('\n'),
                    b'r' => output.push('\r'),
                    b't' => output.push('\t'),
                    b'u' => output.push(self.unicode_escape()?),
                    _ => return Err(JsonError("invalid JSON escape".into())),
                }
                continue;
            }
            if byte < 0x20 {
                return Err(JsonError(
                    "unescaped control character in JSON string".into(),
                ));
            }
            let remaining = &self.input[self.pos..];
            let character = remaining
                .chars()
                .next()
                .ok_or_else(|| JsonError("invalid UTF-8 JSON string".into()))?;
            output.push(character);
            self.pos += character.len_utf8();
        }
        Err(JsonError("unterminated JSON string".into()))
    }

    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let first = self.hex_u16()?;
        if (0xd800..=0xdbff).contains(&first) {
            if !self.input[self.pos..].starts_with("\\u") {
                return Err(JsonError("unpaired high surrogate in JSON string".into()));
            }
            self.pos += 2;
            let second = self.hex_u16()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(JsonError("invalid JSON surrogate pair".into()));
            }
            let code = 0x10000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00);
            char::from_u32(code).ok_or_else(|| JsonError("invalid Unicode scalar".into()))
        } else if (0xdc00..=0xdfff).contains(&first) {
            Err(JsonError("unpaired low surrogate in JSON string".into()))
        } else {
            char::from_u32(u32::from(first))
                .ok_or_else(|| JsonError("invalid Unicode scalar".into()))
        }
    }

    fn hex_u16(&mut self) -> Result<u16, JsonError> {
        let end = self.pos.saturating_add(4);
        let text = self
            .input
            .get(self.pos..end)
            .ok_or_else(|| JsonError("short Unicode escape".into()))?;
        if !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(JsonError("invalid Unicode escape".into()));
        }
        self.pos = end;
        u16::from_str_radix(text, 16).map_err(|_| JsonError("invalid Unicode escape".into()))
    }

    fn array(&mut self) -> Result<Json, JsonError> {
        self.pos += 1;
        let mut values = Vec::new();
        self.ws();
        if self.input.as_bytes().get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(Json::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.ws();
            match self.input.as_bytes().get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(JsonError("invalid JSON array".into())),
            }
        }
        Ok(Json::Array(values))
    }

    fn object(&mut self) -> Result<Json, JsonError> {
        self.pos += 1;
        let mut values = Vec::new();
        self.ws();
        if self.input.as_bytes().get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(Json::Object(values));
        }
        loop {
            self.ws();
            if self.input.as_bytes().get(self.pos) != Some(&b'"') {
                return Err(JsonError("JSON object key must be a string".into()));
            }
            let key = self.string()?;
            if values.iter().any(|(existing, _)| existing == &key) {
                return Err(JsonError("duplicate JSON object key".into()));
            }
            self.ws();
            if self.input.as_bytes().get(self.pos) != Some(&b':') {
                return Err(JsonError("missing JSON object colon".into()));
            }
            self.pos += 1;
            let value = self.value()?;
            values.push((key, value));
            self.ws();
            match self.input.as_bytes().get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(JsonError("invalid JSON object".into())),
            }
        }
        Ok(Json::Object(values))
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.pos;
        if self.input.as_bytes().get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        match self.input.as_bytes().get(self.pos) {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.input.as_bytes().get(self.pos), Some(b'0'..=b'9')) {
                    return Err(JsonError("JSON number has a leading zero".into()));
                }
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.input.as_bytes().get(self.pos), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(JsonError("invalid JSON number".into())),
        }
        if self.input.as_bytes().get(self.pos) == Some(&b'.') {
            self.pos += 1;
            let fraction_start = self.pos;
            while matches!(self.input.as_bytes().get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == fraction_start {
                return Err(JsonError("invalid JSON fraction".into()));
            }
        }
        if matches!(self.input.as_bytes().get(self.pos), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.input.as_bytes().get(self.pos), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            let exponent_start = self.pos;
            while matches!(self.input.as_bytes().get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == exponent_start {
                return Err(JsonError("invalid JSON exponent".into()));
            }
        }
        Ok(Json::Number(self.input[start..self.pos].to_owned()))
    }
}

pub(super) fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h = [
        0x6a09e667_u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in message.as_chunks::<64>().0 {
        let mut words = [0_u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut output = [0_u8; 32];
    for (index, value) in h.into_iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    output
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

pub(super) fn sha256_hex(input: &[u8]) -> String {
    hex(&sha256(input))
}

pub(super) fn hmac_sha256_hex(key: &[u8], input: &[u8]) -> String {
    let mut normalized = [0_u8; 64];
    if key.len() > 64 {
        normalized[..32].copy_from_slice(&sha256(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_key = [0_u8; 64];
    let mut outer_key = [0_u8; 64];
    for index in 0..64 {
        inner_key[index] = normalized[index] ^ 0x36;
        outer_key[index] = normalized[index] ^ 0x5c;
    }
    let mut inner = Vec::with_capacity(64 + input.len());
    inner.extend_from_slice(&inner_key);
    inner.extend_from_slice(input);
    let inner_hash = sha256(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&outer_key);
    outer.extend_from_slice(&inner_hash);
    hex(&sha256(&outer))
}

pub(super) fn verify_github_signature(secret: &[u8], body: &[u8], header: &str) -> bool {
    let Some(provided) = header.strip_prefix("sha256=") else {
        return false;
    };
    if provided.len() != 64 || !provided.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return false;
    }
    let expected = hmac_sha256_hex(secret, body);
    let mut difference = 0_u8;
    for (left, right) in expected.bytes().zip(provided.bytes()) {
        difference |= left ^ right.to_ascii_lowercase();
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_phase_1a_digest_vector_matches() {
        let request = Json::parse(
            r#"{"schema_version":1,"request_id":"req-0001","created_at":"2026-08-26T23:00:00Z","expires_at":"2026-08-27T00:00:00Z","base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation":"task.transition_status","parameters":{"task_id":"ZACH-001","target_status":"active"},"contract_revision":"3bbbb3463573893571f45ee92625a54414f8df13"}"#,
        )
        .unwrap();
        let canonical = jcs(&request).unwrap();
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            "93694132312a78a14ba2ead077036aa931349d00f3d2fe93e95dca8dd93b2928"
        );
    }

    #[test]
    fn jcs_orders_keys_by_utf16_and_decodes_surrogate_pairs() {
        let value = Json::parse(r#"{"\ud83d\ude00":1,"a":2,"\ue000":3}"#).unwrap();
        let canonical = jcs(&value).unwrap();
        assert_eq!(canonical, "{\"a\":2,\"😀\":1,\"\":3}");
    }

    #[test]
    fn jcs_rejects_floats_and_unsafe_integers() {
        assert!(jcs(&Json::parse("1.0").unwrap()).is_err());
        assert!(jcs(&Json::parse("9007199254740992").unwrap()).is_err());
    }

    #[test]
    fn github_hmac_verifies_exact_raw_bytes() {
        let body = br#"{"issue":1}"#;
        let signature = format!("sha256={}", hmac_sha256_hex(b"secret", body));
        assert!(verify_github_signature(b"secret", body, &signature));
        assert!(!verify_github_signature(
            b"secret",
            br#"{"issue":1} "#,
            &signature
        ));
    }
}
