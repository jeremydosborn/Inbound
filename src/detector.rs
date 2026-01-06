//! Port scan detection

use crate::types::{Connection, ScanType};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

pub struct ScanDetector {
    connections: HashMap<IpAddr, Vec<ConnectionRecord>>,
    window: Duration,
    threshold: usize,
}

#[derive(Debug, Clone)]
pub struct ScanEvent {
    pub src_ip: IpAddr,
    pub ports: Vec<u16>,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub scan_type: ScanType,
}

#[derive(Clone)]
struct ConnectionRecord {
    port: u16,
    timestamp: SystemTime,
}

impl ScanDetector {
    pub fn new() -> Self {
        ScanDetector {
            connections: HashMap::new(),
            window: Duration::from_secs(60),
            threshold: 5,
        }
    }
    
    pub fn with_config(window_secs: u64, threshold: usize) -> Self {
        ScanDetector {
            connections: HashMap::new(),
            window: Duration::from_secs(window_secs),
            threshold,
        }
    }
    
    pub fn analyze(&mut self, conn: Connection) -> Option<ScanEvent> {
        let now = SystemTime::now();
        
        let records = self.connections
            .entry(conn.src_ip)
            .or_insert_with(Vec::new);
        
        records.push(ConnectionRecord {
            port: conn.dst_port,
            timestamp: conn.timestamp,
        });
        
        records.retain(|r| {
            now.duration_since(r.timestamp)
                .map(|d| d < self.window)
                .unwrap_or(false)
        });
        
        let unique_ports: std::collections::HashSet<u16> = 
            records.iter().map(|r| r.port).collect();
        
        if unique_ports.len() >= self.threshold {
            let ports: Vec<u16> = unique_ports.into_iter().collect();
            let scan_type = Self::classify_scan(records);
            
            // Extract timestamps BEFORE removing
            let first_seen = records.first()?.timestamp;
            let last_seen = records.last()?.timestamp;
            
            // Now safe to remove
            self.connections.remove(&conn.src_ip);
            
            Some(ScanEvent {
                src_ip: conn.src_ip,
                ports,
                first_seen,
                last_seen,
                scan_type,
            })
        } else {
            None
}
    }
    
    fn classify_scan(records: &[ConnectionRecord]) -> ScanType {
        if records.len() < 2 {
            return ScanType::Vertical;
        }
        
        let duration = records.last().unwrap().timestamp
            .duration_since(records.first().unwrap().timestamp)
            .unwrap_or(Duration::from_secs(1));
        
        let rate = records.len() as f64 / duration.as_secs_f64().max(0.1);
        
        if rate > 10.0 {
            ScanType::FastScan
        } else if rate < 0.5 {
            ScanType::SlowScan
        } else {
            ScanType::Vertical
        }
    }
}

impl Default for ScanDetector {
    fn default() -> Self {
        Self::new()
    }
}