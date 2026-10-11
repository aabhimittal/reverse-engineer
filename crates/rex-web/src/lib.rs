//! # rex-web
//!
//! Reverse engineering for the web and mobile layer.
//!
//! | Module | Turns … | … into |
//! |---|---|---|
//! | [`har`] + [`openapi`] | captured browser/proxy traffic (HAR) | an OpenAPI 3.1 spec of the undocumented API |
//! | [`schema`] | example JSON bodies | a JSON Schema |
//! | [`audit`] | HTTP exchanges | security observations (headers, cookies, JWTs, CORS) |
//! | [`js`] | a minified bundle | endpoints, secrets, frameworks, DOM sinks, unpacked sources |
//! | [`apk`], [`axml`], [`dex`] | an Android app | manifest, components, permissions, classes, risky APIs |
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod analyzers;
pub mod apk;
pub mod audit;
pub mod axml;
pub mod b64;
pub mod dex;
pub mod har;
pub mod js;
pub mod openapi;
pub mod schema;
pub mod yaml;

pub use analyzers::register;
