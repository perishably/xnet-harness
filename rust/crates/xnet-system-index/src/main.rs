use serde::Deserialize;
use std::io::{self, Read};
use xnet_system_index::{Directory, Request};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope { directory: Directory, request: Request }

fn main() {
    let mut raw = Vec::new();
    let result = (|| -> Result<serde_json::Value, String> {
        io::stdin().take(4 * 1024 * 1024 + 1).read_to_end(&mut raw).map_err(|_| "stdin transport".to_string())?;
        if raw.len() > 4 * 1024 * 1024 { return Err("input bound".into()); }
        let envelope: Envelope = serde_json::from_slice(&raw).map_err(|_| "closed JSON envelope".to_string())?;
        xnet_system_index::handle_request(&envelope.directory, &envelope.request).map_err(|error| error.to_string())
    })();
    match result {
        Ok(value) => println!("{}", serde_json::to_string(&value).expect("JSON discovery response")),
        Err(_) => { eprintln!("xnet-system-index: discovery input refused"); std::process::exit(2); }
    }
}
