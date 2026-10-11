//! JSON Schema inference from example documents.
//!
//! Analogy: identifying a species from field sightings. One sighting of a
//! bird with a red chest tells you little; fifty sightings tell you which
//! features are *always* present (required), which are occasional (optional),
//! and what each looks like (type and format). Each observed JSON body is a
//! sighting, and [`Shape::merge`] folds them into one description.

use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Recognised string formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StrFormat {
    /// RFC 3339 timestamp.
    DateTime,
    /// YYYY-MM-DD.
    Date,
    /// Email address.
    Email,
    /// UUID.
    Uuid,
    /// URI.
    Uri,
    /// IPv4.
    Ipv4,
}

impl StrFormat {
    fn as_str(self) -> &'static str {
        match self {
            StrFormat::DateTime => "date-time",
            StrFormat::Date => "date",
            StrFormat::Email => "email",
            StrFormat::Uuid => "uuid",
            StrFormat::Uri => "uri",
            StrFormat::Ipv4 => "ipv4",
        }
    }
}

/// Detect a string's format, if any.
pub fn detect_format(s: &str) -> Option<StrFormat> {
    let b = s.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|x| x.iter().all(u8::is_ascii_digit));
    if b.len() == 10
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
    {
        return Some(StrFormat::Date);
    }
    if b.len() >= 19
        && digits(0..4)
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
    {
        return Some(StrFormat::DateTime);
    }
    if is_uuid(s) {
        return Some(StrFormat::Uuid);
    }
    if (s.starts_with("http://") || s.starts_with("https://")) && !s.contains(' ') {
        return Some(StrFormat::Uri);
    }
    if let Some((user, host)) = s.split_once('@') {
        if !user.is_empty() && host.contains('.') && !s.contains(' ') && !host.contains('@') {
            return Some(StrFormat::Email);
        }
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
    {
        return Some(StrFormat::Ipv4);
    }
    None
}

/// UUID (8-4-4-4-12 hex).
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// An inferred shape.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Shape {
    /// Times observed.
    pub seen: usize,
    /// Saw `null`.
    pub null: bool,
    /// Saw booleans.
    pub boolean: bool,
    /// Saw integers.
    pub integer: bool,
    /// Saw non-integer numbers.
    pub number: bool,
    /// String observations (None if never a string).
    pub string: Option<StringShape>,
    /// Array element shape (None if never an array).
    pub array: Option<Box<Shape>>,
    /// Object properties (None if never an object).
    pub object: Option<ObjectShape>,
}

/// String-specific facts.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StringShape {
    /// Formats seen (a format is kept only if every sample had it).
    pub formats: BTreeSet<Option<StrFormat>>,
    /// Up to 8 distinct example values.
    pub examples: BTreeSet<String>,
    /// Count of string samples.
    pub count: usize,
}

/// Object-specific facts.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ObjectShape {
    /// Objects observed.
    pub count: usize,
    /// Property shapes (`Shape::seen` = how many objects had the key).
    pub props: BTreeMap<String, Shape>,
}

impl Shape {
    /// Shape of a single value.
    pub fn of(v: &Value) -> Shape {
        let mut s = Shape::default();
        s.observe(v);
        s
    }

    /// Fold one more observation in.
    pub fn observe(&mut self, v: &Value) {
        self.seen += 1;
        match v {
            Value::Null => self.null = true,
            Value::Bool(_) => self.boolean = true,
            Value::Number(n) => {
                if n.is_i64() || n.is_u64() {
                    self.integer = true;
                } else {
                    self.number = true;
                }
            }
            Value::String(st) => {
                let ss = self.string.get_or_insert_with(StringShape::default);
                ss.count += 1;
                ss.formats.insert(detect_format(st));
                if ss.examples.len() < 8 && st.len() <= 80 {
                    ss.examples.insert(st.clone());
                }
            }
            Value::Array(items) => {
                let el = self.array.get_or_insert_with(|| Box::new(Shape::default()));
                for it in items.iter().take(200) {
                    el.observe(it);
                }
            }
            Value::Object(m) => {
                let o = self.object.get_or_insert_with(ObjectShape::default);
                o.count += 1;
                for (k, val) in m {
                    o.props.entry(k.clone()).or_default().observe(val);
                }
            }
        }
    }

    /// Merge another shape into this one.
    pub fn merge(&mut self, other: &Shape) {
        self.seen += other.seen;
        self.null |= other.null;
        self.boolean |= other.boolean;
        self.integer |= other.integer;
        self.number |= other.number;
        if let Some(os) = &other.string {
            let ss = self.string.get_or_insert_with(StringShape::default);
            ss.count += os.count;
            ss.formats.extend(os.formats.iter().copied());
            for e in &os.examples {
                if ss.examples.len() < 8 {
                    ss.examples.insert(e.clone());
                }
            }
        }
        if let Some(oa) = &other.array {
            self.array
                .get_or_insert_with(|| Box::new(Shape::default()))
                .merge(oa);
        }
        if let Some(oo) = &other.object {
            let so = self.object.get_or_insert_with(ObjectShape::default);
            so.count += oo.count;
            for (k, v) in &oo.props {
                so.props.entry(k.clone()).or_default().merge(v);
            }
        }
    }

    /// Render as a JSON Schema (2020-12 subset used by OpenAPI 3.1).
    pub fn to_schema(&self) -> Value {
        let mut variants: Vec<Value> = Vec::new();
        if self.boolean {
            variants.push(json!({"type": "boolean"}));
        }
        if self.integer && !self.number {
            variants.push(json!({"type": "integer"}));
        } else if self.number {
            variants.push(json!({"type": "number"}));
        }
        if let Some(s) = &self.string {
            let mut m = Map::new();
            m.insert("type".into(), json!("string"));
            if s.formats.len() == 1 {
                if let Some(Some(f)) = s.formats.iter().next() {
                    m.insert("format".into(), json!(f.as_str()));
                }
            }
            if !s.examples.is_empty() {
                m.insert(
                    "examples".into(),
                    json!(s.examples.iter().take(3).collect::<Vec<_>>()),
                );
            }
            variants.push(Value::Object(m));
        }
        if let Some(a) = &self.array {
            let items = if a.seen == 0 {
                json!({})
            } else {
                a.to_schema()
            };
            variants.push(json!({"type": "array", "items": items}));
        }
        if let Some(o) = &self.object {
            let mut props = Map::new();
            let mut required = Vec::new();
            for (k, v) in &o.props {
                props.insert(k.clone(), v.to_schema());
                if v.seen >= o.count {
                    required.push(json!(k));
                }
            }
            let mut m = Map::new();
            m.insert("type".into(), json!("object"));
            if !props.is_empty() {
                m.insert("properties".into(), Value::Object(props));
            }
            if !required.is_empty() {
                m.insert("required".into(), Value::Array(required));
            }
            variants.push(Value::Object(m));
        }
        let mut schema = match variants.len() {
            0 if self.null => json!({"type": "null"}),
            0 => json!({}),
            1 => variants.pop().expect("one"),
            _ => json!({"oneOf": variants}),
        };
        if self.null && schema.get("type").is_some_and(|t| t != "null") {
            // OpenAPI 3.1: nullable via type array.
            let t = schema["type"].clone();
            schema["type"] = json!([t, "null"]);
        }
        schema
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_required_and_formats() {
        let mut s = Shape::of(
            &json!({"id": 1, "email": "a@b.co", "tags": ["x"], "created": "2024-01-02T03:04:05Z"}),
        );
        s.observe(&json!({"id": 2, "email": "c@d.io", "tags": [], "nick": null}));
        let schema = s.to_schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["id"]["type"], "integer");
        assert_eq!(schema["properties"]["email"]["format"], "email");
        assert_eq!(schema["properties"]["created"]["format"], "date-time");
        assert_eq!(schema["properties"]["tags"]["items"]["type"], "string");
        let req: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(req, vec!["email", "id", "tags"]);
        assert_eq!(schema["properties"]["nick"]["type"], "null");
    }

    #[test]
    fn unions_and_nullable() {
        let mut s = Shape::of(&json!(1));
        s.observe(&json!(1.5));
        assert_eq!(s.to_schema()["type"], "number");
        let mut s = Shape::of(&json!("x"));
        s.observe(&json!(null));
        assert_eq!(s.to_schema()["type"], json!(["string", "null"]));
        let mut s = Shape::of(&json!("x"));
        s.observe(&json!(3));
        assert!(s.to_schema()["oneOf"].is_array());
    }

    #[test]
    fn formats() {
        assert_eq!(detect_format("2024-02-29"), Some(StrFormat::Date));
        assert_eq!(
            detect_format("123e4567-e89b-12d3-a456-426614174000"),
            Some(StrFormat::Uuid)
        );
        assert_eq!(detect_format("https://x.y/z"), Some(StrFormat::Uri));
        assert_eq!(detect_format("10.0.0.255"), Some(StrFormat::Ipv4));
        assert_eq!(detect_format("hello"), None);
    }
}
