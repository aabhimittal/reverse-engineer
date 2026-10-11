//! # rex-code
//!
//! Reverse engineering for source trees: *"I've just inherited this repo. Where do I start?"*
//!
//! | Module | Answers |
//! |---|---|
//! | [`lang`] | What languages, how much code? |
//! | [`syntax`] | What's defined where, what calls what, how complex is it? (tree-sitter) |
//! | [`project`] | How do modules depend on each other, and which are central? |
//! | [`patterns`] | What are the entry points and HTTP routes, what's the stack, what looks risky? |
//! | [`git`] | Where does change concentrate, and who knows what? |
//! | [`analyzers`] | All of the above as one "codebase atlas" report. |
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod analyzers;
pub mod git;
pub mod lang;
pub mod patterns;
pub mod project;
pub mod syntax;

pub use analyzers::register;
