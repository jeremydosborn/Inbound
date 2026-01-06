//! Packet capture functionality

use crate::types::{Packet, Protocol, TcpFlags};
use crate::error::{InboundError, Result};
use pcap::{Capture, Device};
use std::net::IpAddr;
use std::time::SystemTime;

pub struct PacketCapture {
    capture: Capture<pcap::Active>,
}

impl PacketCapture {
    pub fn new(interface: Option<&str>) -> Result<Self> {
        let device = match interface {
            Some(name) => Self::find_device(name)?,
            None => Device::lookup()
                .map_err(|e| InboundError::CaptureInit(e.to_string()))?
                .ok_or(InboundError::DeviceNotFound("no default device found".into()))?,
        };
        
        log::info!("Using interface: {}", device.name);
        
        let mut cap = Capture::from_device(device)?
            .promisc(true)
            .snaplen(96)
            .timeout(1000)
            .open()?;
        
        cap.filter(
            "tcp[tcpflags] & tcp-syn != 0 and not tcp[tcpflags] & tcp-ack != 0",
            true
        )?;
        
        log::info!("Packet capture initialized");
        
        Ok(PacketCapture { capture: cap })
    }
    
    pub fn next(&mut self) -> Result<Packet> {
        let raw_packet = self.capture.next_packet()
            .map_err(|e| InboundError::CapturePacket(e.to_string()))?;
        
        Self::parse_packet(raw_packet.data)
    }
    
    fn find_device(name: &str) -> Result<Device> {
        Device::list()
            .map_err(|e| InboundError::CaptureInit(e.to_string()))?
            .into_iter()
            .find(|d| d.name == name)
            .ok_or_else(|| InboundError::DeviceNotFound(name.to_string()))
    }
    
    fn parse_packet(data: &[u8]) -> Result<Packet> {
        if data.len() < 54 {
            return Err(InboundError::Parse("packet too short".into()));
        }
        
        let ip_data = &data[14..];
        
        let version = (ip_data[0] >> 4) & 0x0F;
        if version != 4 {
            return Err(InboundError::Parse("not IPv4".into()));
        }
        
        let ihl = (ip_data[0] & 0x0F) as usize * 4;
        let protocol = ip_data[9];
        
        if protocol != 6 {
            return Err(InboundError::Parse("not TCP".into()));
        }
        
        let src_ip = IpAddr::from([ip_data[12], ip_data[13], ip_data[14], ip_data[15]]);
        let dst_ip = IpAddr::from([ip_data[16], ip_data[17], ip_data[18], ip_data[19]]);
        
        let tcp_data = &ip_data[ihl..];
        if tcp_data.len() < 14 {
            return Err(InboundError::Parse("TCP header too short".into()));
        }
        
        let src_port = u16::from_be_bytes([tcp_data[0], tcp_data[1]]);
        let dst_port = u16::from_be_bytes([tcp_data[2], tcp_data[3]]);
        
        let flags_byte = tcp_data[13];
        let flags = TcpFlags {
            syn: (flags_byte & 0x02) != 0,
            ack: (flags_byte & 0x10) != 0,
            rst: (flags_byte & 0x04) != 0,
            fin: (flags_byte & 0x01) != 0,
        };
        
        Ok(Packet {
            timestamp: SystemTime::now(),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: Protocol::TCP,
            flags,
        })
    }
}