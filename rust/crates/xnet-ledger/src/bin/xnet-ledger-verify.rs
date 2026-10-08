//! xnet-ledger-verify — CLI: replays a ledger, exit 0 on integrity,
//! exit 1 with the broken seq on stderr otherwise.
//! Usage: xnet-ledger-verify <path-to-ledger.jsonl>
use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: xnet-ledger-verify <ledger.jsonl>");
            return ExitCode::from(2);
        }
    };
    match xnet_ledger::Ledger::verify(&path) {
        Ok(n) => {
            println!("OK: {n} receipts, chain intact");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("CHAIN BROKEN: {e}");
            ExitCode::FAILURE
        }
    }
}
