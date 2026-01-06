//! Common types used across the library

use std::net::IpAddr;
use std::time::SystemTime;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: SystemTime,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub flags: TcpFlags,
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub src_ip: IpAddr,
    pub dst_port: u16,
    pub timestamp: SystemTime,
}

impl From<Packet> for Connection {
    fn from(p: Packet) -> Self {
        Connection {
            src_ip: p.src_ip,
            dst_port: p.dst_port,
            timestamp: p.timestamp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub rst: bool,
    pub fin: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ScanType {
    Vertical,
    FastScan,
    SlowScan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribution {
    pub ip: IpAddr,
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub reverse_dns: Option<String>,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}