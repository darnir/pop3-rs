#[cfg(feature = "serde_derive")]
#[macro_use]
extern crate serde_derive;

use std::path::PathBuf;

#[cfg(feature = "serde_derive")]
include!("serde_types.in.rs");

#[cfg(feature = "serde_codegen")]
include!(concat!(env!("OUT_DIR"), "/serde_types.rs"));
