//! Simple incoming connection monitor

use inbound::{PacketCapture, ScanDetector, Attributor, InboundError};
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    
    println!("╔════════════════════════════════════════╗");
    println!("║   Inbound Connection Monitor v{}    ║", inbound::VERSION);
    println!("╚════════════════════════════════════════╝");
    println!();
    
    let mut capture = match PacketCapture::new(Some("en0")) {
        Ok(c) => c,
        Err(InboundError::PermissionDenied) => {
            eprintln!("Error: Permission denied");
            eprintln!("Try: sudo cargo run --example monitor");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    
    let mut detector = ScanDetector::new();
    let attributor = Attributor::new()?;
    
    println!("Monitoring incoming connections...");
    println!("Press Ctrl+C to stop");
    println!();
    
    let mut packet_count = 0u64;
    let mut scan_count = 0u64;
    
    loop {
        match capture.next() {
            Ok(packet) => {
                packet_count += 1;
                
                if packet_count % 100 == 0 {
                    print!("\rPackets: {} | Scans: {}", packet_count, scan_count);
                    io::stdout().flush().ok();
                }
                
                if let Some(scan) = detector.analyze(packet.into()) {
                    scan_count += 1;
                    print!("\r{}\r", " ".repeat(60));
                    
                    match attributor.attribute(scan) {
                        Ok(attributed) => {
                            println!("╔════════════════════════════════════════╗");
                            println!("║  🚨 SCAN DETECTED                     ║");
                            println!("╚════════════════════════════════════════╝");
                            println!();
                            println!("  IP Address:    {}", attributed.attribution.ip);
                            
                            if let Some(hostname) = &attributed.attribution.reverse_dns {
                                println!("  Hostname:      {}", hostname);
                            }
                            
                            println!("  Ports Probed:  {:?}", attributed.event.ports);
                            println!("  Scan Type:     {:?}", attributed.event.scan_type);
                            println!("  Threat Level:  {:?}", attributed.attribution.threat_level);
                            
                            let duration = attributed.event.last_seen
                                .duration_since(attributed.event.first_seen)
                                .unwrap_or_default();
                            println!("  Duration:      {:.1}s", duration.as_secs_f64());
                            println!();
                        }
                        Err(e) => {
                            eprintln!("Attribution error: {}", e);
                        }
                    }
                }
            }
            Err(InboundError::CapturePacket(ref msg)) if msg.contains("timeout") => {
                continue;
            }
            Err(e) => {
                eprintln!("\nCapture error: {}", e);
            }
        }
    }
}