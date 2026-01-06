//! Inbound - Monitor incoming network connections

mod error;
mod types;
mod capture;
mod detector;
mod attribution;

// Public API - Error types
pub use error::{InboundError, Result};

// Public API - Main types
pub use capture::PacketCapture;
pub use detector::{ScanDetector, ScanEvent};
pub use attribution::{Attributor, AttributedEvent};

// Public API - Data types
pub use types::{
    Packet,
    Connection,
    Protocol,
    TcpFlags,
    ScanType,
    Attribution,
    ThreatLevel,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");