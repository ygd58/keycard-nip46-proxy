use std::io::{self, Write};

pub struct ApprovalPolicy {
    auto_approve: bool,
}

impl ApprovalPolicy {
    pub fn new(auto_approve: bool) -> Self {
        Self { auto_approve }
    }

    pub fn approve_sign(&self, event_json: &str) -> bool {
        if self.auto_approve {
            tracing::info!("Auto-approving signing request");
            return true;
        }

        println!("\n╔══════════════════════════════════════╗");
        println!("║        SIGNING REQUEST               ║");
        println!("╚══════════════════════════════════════╝");
        println!("{}", event_json);
        print!("\nApprove? [y/N]: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
    }
}
