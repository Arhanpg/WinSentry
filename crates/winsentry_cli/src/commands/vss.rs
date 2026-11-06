//! VSS Command Handler
//!
//! Queries Volume Shadow Copy storage and outputs system restore advisories.

use scanner_core::classifier::query_vss_advisory;

pub fn execute_vss_advisory() {
    println!("\n=== WinSentry: Volume Shadow Copy (VSS) Advisory ===");
    match query_vss_advisory() {
        Ok(info) => {
            println!("Target Volume:      {}", info.volume_name);
            println!("Used Shadow Space:  {}", info.used_space);
            println!("Allocated Space:    {}", info.allocated_space);
            println!("Maximum Capacity:   {}", info.max_space);
            println!("\n{}", info.advisory_note);
        }
        Err(e) => {
            eprintln!("[ERROR] Could not query VSS storage: {}", e);
            println!("Ensure command prompt is run with administrative privileges if querying system volume shadow copies.");
        }
    }
}
