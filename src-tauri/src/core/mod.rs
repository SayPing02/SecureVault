// Core logic modules - kept separate from the Tauri UI layer
// so we can test everything with cargo test

<<<<<<< HEAD
=======
pub mod backup;
>>>>>>> origin/felix
pub mod crypto;
pub mod error;
pub mod fragmenter;
pub mod gf256;
<<<<<<< HEAD
pub mod model;
pub mod sharing;
pub mod shamir;
pub mod storage;
=======
pub mod large_fragment;
pub mod model;
pub mod op_control;
pub mod rotation;
pub mod sharing;
pub mod shamir;
pub mod storage;

#[cfg(test)]
mod password_roundtrip_tests;
>>>>>>> origin/felix
