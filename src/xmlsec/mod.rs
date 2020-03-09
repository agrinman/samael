//!
//! Bindings for XmlSec1
//!
//! Modules reflect the header names of the bound xmlsec1 library
//!
#![deny(missing_docs)]

// imports


#[doc(hidden)]
pub use libxml::tree::node::Node as XmlNode;
#[doc(hidden)]
pub use libxml::tree::document::Document as XmlDocument;

// internals


mod keys;
mod error;
mod xmlsec;
mod xmldsig;

// exports
pub use self::keys::XmlSecKey;
pub use self::keys::XmlSecKeyFormat;

pub use self::error::XmlSecError;
pub use self::error::XmlSecResult;

pub use self::xmldsig::XmlSecSignatureContext;

pub use self::xmlsec::{ XmlSecContext};
