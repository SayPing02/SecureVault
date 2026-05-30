// Core logic modules - kept separate from the Tauri UI layer
// so we can test everything with cargo test

pub mod crypto;
pub mod error;
pub mod fragmenter;
pub mod gf256;
pub mod model;
pub mod sharing;
pub mod shamir;
pub mod storage;
