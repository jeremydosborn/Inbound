//! Error types for the inbound library

use thiserror::Error;

#[derive(Error, Debug)]
pub enum InboundError {
    #[error("Failed to initialize packet capture: {0}")]
    CaptureInit(String),
    
    #[error("Failed to capture packet: {0}")]
    CapturePacket(String),
    
    #[error("Failed to parse packet: {0}")]
    Parse(String),
    
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    
    #[error("Permission denied - packet capture requires root privileges (try sudo)")]
    PermissionDenied,
    
    #[error("IP attribution failed: {0}")]
    Attribution(String),
}

pub type Result<T> = std::result::Result<T, InboundError>;

// Auto-convert pcap errors
impl From<pcap::Error> for InboundError {
    fn from(e: pcap::Error) -> Self {
        let msg = e.to_string();
        if msg.contains("permission") || msg.contains("Operation not permitted") {
            InboundError::PermissionDenied
        } else {
            InboundError::CaptureInit(msg)
        }
    }
}