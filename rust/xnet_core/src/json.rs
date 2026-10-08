use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Json {
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut p = Parser { input, pos: 0 };
        let value = p.value()?;
        p.space();
        if p.pos != input.len() {
            return Err(format!("unexpected trailing JSON at byte {}", p.pos));
        }
        Ok(value)
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(fields) => fields.get(key),
            _ => None,
        }
    }

    pub fn str_field(&self, key: &str) -> Result<&str, String> {
        match self.get(key) {
            Some(Json::String(value)) => Ok(value),
            _ => Err(format!("missing or invalid string field: {key}")),
        }
    }

    pub fn usize_field(&self, key: &str) -> Result<usize, String> {
        match self.get(key) {
            Some(Json::Number(value)) => value.parse::<usize>().map_err(|_| format!("invalid integer field: {key}")),
            _ => Err(format!("missing or invalid integer field: {key}")),
        }
    }

    pub fn encode(&self) -> String {
        let mut out = String::new();
        self.append_to(&mut out);
        out
    }

    fn append_to(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Json::Number(value) => out.push_str(value),
            Json::String(value) => append_string(out, value),
            Json::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 { out.push(','); }
                    item.append_to(out);
                }
                out.push(']');
            }
            Json::Object(fields) => {
                out.push('{');
                for (index, (key, value)) in fields.iter().enumerate() {
                    if index > 0 { out.push(','); }
                    append_string(out, key);
                    out.push(':');
                    value.append_to(out);
                }
                out.push('}');
            }
        }
    }
}

pub fn obj(fields: impl IntoIterator<Item = (String, Json)>) -> Json {
    Json::Object(fields.into_iter().collect())
}

pub fn s(value: impl Into<String>) -> Json { Json::String(value.into()) }
pub fn n(value: usize) -> Json { Json::Number(value.to_string()) }

fn append_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> { input: &'a str, pos: usize }

impl Parser<'_> {
    fn bytes(&self) -> &[u8] { self.input.as_bytes() }
    fn peek(&self) -> Option<u8> { self.bytes().get(self.pos).copied() }
    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) { self.pos += 1; }
    }
    fn take(&mut self, expected: u8) -> Result<(), String> {
        if self.peek() == Some(expected) { self.pos += 1; Ok(()) }
        else { Err(format!("expected '{}' at byte {}", expected as char, self.pos)) }
    }
    fn value(&mut self) -> Result<Json, String> {
        self.space();
        match self.peek() {
            Some(b'"') => self.string().map(Json::String),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b't') => { self.literal("true")?; Ok(Json::Bool(true)) }
            Some(b'f') => { self.literal("false")?; Ok(Json::Bool(false)) }
            Some(b'n') => { self.literal("null")?; Ok(Json::Null) }
            Some(b'-' | b'0'..=b'9') => self.number().map(Json::Number),
            _ => Err(format!("invalid JSON value at byte {}", self.pos)),
        }
    }
    fn literal(&mut self, literal: &str) -> Result<(), String> {
        if self.input[self.pos..].starts_with(literal) { self.pos += literal.len(); Ok(()) }
        else { Err(format!("invalid literal at byte {}", self.pos)) }
    }
    fn string(&mut self) -> Result<String, String> {
        self.take(b'"')?;
        let mut out = String::new();
        let mut segment = self.pos;
        loop {
            let c = self.peek().ok_or_else(|| "unterminated JSON string".to_string())?;
            match c {
                b'"' => {
                    out.push_str(&self.input[segment..self.pos]);
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    out.push_str(&self.input[segment..self.pos]);
                    self.pos += 1;
                    let escaped = self.peek().ok_or_else(|| "unterminated JSON escape".to_string())?;
                    self.pos += 1;
                    match escaped {
                        b'"' => out.push('"'), b'\\' => out.push('\\'), b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'), b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'), b'r' => out.push('\r'), b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let cp = if (0xd800..=0xdbff).contains(&first) {
                                self.take(b'\\')?;
                                self.take(b'u')?;
                                let second = self.hex4()?;
                                if !(0xdc00..=0xdfff).contains(&second) { return Err("invalid low surrogate".into()); }
                                0x10000 + ((first as u32 - 0xd800) << 10) + (second as u32 - 0xdc00)
                            } else if (0xdc00..=0xdfff).contains(&first) {
                                return Err("unpaired low surrogate".into());
                            } else { first as u32 };
                            out.push(char::from_u32(cp).ok_or_else(|| "invalid Unicode scalar".to_string())?);
                        }
                        _ => return Err(format!("invalid escape at byte {}", self.pos - 1)),
                    }
                    segment = self.pos;
                }
                0..=31 => return Err(format!("control character in JSON string at byte {}", self.pos)),
                _ => self.pos += 1,
            }
        }
    }
    fn hex4(&mut self) -> Result<u16, String> {
        let end = self.pos + 4;
        let part = self.input.get(self.pos..end).ok_or_else(|| "short Unicode escape".to_string())?;
        let value = u16::from_str_radix(part, 16).map_err(|_| "invalid Unicode escape".to_string())?;
        self.pos = end;
        Ok(value)
    }
    fn number(&mut self) -> Result<String, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') { self.pos += 1; }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => while matches!(self.peek(), Some(b'0'..=b'9')) { self.pos += 1; },
            _ => return Err(format!("invalid JSON number at byte {start}")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) { return Err("invalid JSON fraction".into()); }
            while matches!(self.peek(), Some(b'0'..=b'9')) { self.pos += 1; }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) { self.pos += 1; }
            if !matches!(self.peek(), Some(b'0'..=b'9')) { return Err("invalid JSON exponent".into()); }
            while matches!(self.peek(), Some(b'0'..=b'9')) { self.pos += 1; }
        }
        Ok(self.input[start..self.pos].to_string())
    }
    fn array(&mut self) -> Result<Json, String> {
        self.take(b'[')?;
        self.space();
        let mut items = Vec::new();
        if self.peek() == Some(b']') { self.pos += 1; return Ok(Json::Array(items)); }
        loop {
            items.push(self.value()?);
            self.space();
            match self.peek() {
                Some(b',') => { self.pos += 1; }
                Some(b']') => { self.pos += 1; return Ok(Json::Array(items)); }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.pos)),
            }
        }
    }
    fn object(&mut self) -> Result<Json, String> {
        self.take(b'{')?;
        self.space();
        let mut fields = BTreeMap::new();
        if self.peek() == Some(b'}') { self.pos += 1; return Ok(Json::Object(fields)); }
        loop {
            self.space();
            let key = self.string()?;
            self.space();
            self.take(b':')?;
            let value = self.value()?;
            if fields.insert(key.clone(), value).is_some() { return Err(format!("duplicate JSON key: {key}")); }
            self.space();
            match self.peek() {
                Some(b',') => { self.pos += 1; }
                Some(b'}') => { self.pos += 1; return Ok(Json::Object(fields)); }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.pos)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_json_and_unicode() {
        let value = Json::parse("{\"z\":1,\"a\":\"\\uD83D\\uDC1D\",\"b\":[true,null]}").unwrap();
        assert_eq!(value.encode(), "{\"a\":\"🐝\",\"b\":[true,null],\"z\":1}");
        assert!(Json::parse("{\"a\":1,\"a\":2}").is_err());
        assert!(Json::parse("\"\\uD83D\"").is_err());
        assert!(Json::parse("01").is_err());
    }
}
