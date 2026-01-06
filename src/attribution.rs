//! IP address attribution

use crate::detector::ScanEvent;
use crate::types::{Attribution, ThreatLevel};
use crate::error::Result;
use std::net::IpAddr;

pub struct Attributor {}

#[derive(Debug, Clone)]
pub struct AttributedEvent {
    pub event: ScanEvent,
    pub attribution: Attribution,
}

impl Attributor {
    pub fn new() -> Result<Self> {
        Ok(Attributor {})
    }
    
    pub fn attribute(&self, event: ScanEvent) -> Result<AttributedEvent> {
        let attribution = self.lookup_ip(&event)?;
        
        Ok(AttributedEvent {
            event,
            attribution,
        })
    }
    
    fn lookup_ip(&self, event: &ScanEvent) -> Result<Attribution> {
        let ip = event.src_ip;
        
        let reverse_dns = self.reverse_dns_lookup(ip);
        let threat_level = self.assess_threat(event, &reverse_dns);
        
        Ok(Attribution {
            ip,
            country: None,
            city: None,
            asn: None,
            org: None,
            reverse_dns,
            threat_level,
        })
    }
    
    fn reverse_dns_lookup(&self, ip: IpAddr) -> Option<String> {
        use std::net::ToSocketAddrs;
        
        let addr = format!("{}:0", ip);
        addr.to_socket_addrs()
            .ok()?
            .next()
            .and_then(|socket_addr| {
                dns_lookup::lookup_addr(&socket_addr.ip()).ok()
            })
    }
    
    fn assess_threat(&self, event: &ScanEvent, reverse_dns: &Option<String>) -> ThreatLevel {
        if let Some(hostname) = reverse_dns {
            let hostname_lower = hostname.to_lowercase();
            
            if hostname_lower.contains("shodan") 
                || hostname_lower.contains("censys")
                || hostname_lower.contains("binaryedge") {
                return ThreatLevel::Low;
            }
            
            if hostname_lower.contains("tor-exit") {
                return ThreatLevel::High;
            }
        }
        
        match event.scan_type {
            crate::types::ScanType::FastScan => ThreatLevel::High,
            crate::types::ScanType::SlowScan => ThreatLevel::Medium,
            crate::types::ScanType::Vertical => {
                if event.ports.len() > 20 {
                    ThreatLevel::High
                } else if event.ports.len() > 10 {
                    ThreatLevel::Medium
                } else {
                    ThreatLevel::Low
                }
            }
        }
    }
}

impl Default for Attributor {
    fn default() -> Self {
        Self::new().unwrap()
    }
}