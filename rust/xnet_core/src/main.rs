use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use xnet_core::json::{obj, s, Json};
use xnet_core::Engine;

fn main() {
    if let Err(error) = serve() {
        eprintln!("xnet-core: {error}");
        std::process::exit(2);
    }
}

fn serve() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut data_dir: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data-dir" => {
                if data_dir.is_some() { return Err("--data-dir specified twice".into()); }
                data_dir = Some(PathBuf::from(args.next().ok_or_else(|| "--data-dir needs a path".to_string())?));
            }
            "--help" | "-h" => {
                eprintln!("Usage: xnet-core --data-dir <designated-XNET-directory> < commands.jsonl");
                return Ok(());
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    let data_dir = data_dir.ok_or_else(|| "--data-dir is required".to_string())?;
    let mut engine = Engine::open(data_dir)?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    for line in stdin.lock().lines() {
        let response = match line {
            Ok(line) if line.len() <= 8 * 1024 * 1024 => {
                match Json::parse(&line).and_then(|command| engine.handle(&command)) {
                    Ok(value) => value,
                    Err(error) => error_response(&error),
                }
            }
            Ok(_) => error_response("command exceeds 8 MiB"),
            Err(error) => error_response(&format!("read stdin: {error}")),
        };
        writeln!(output, "{}", response.encode()).map_err(|e| format!("write stdout: {e}"))?;
        output.flush().map_err(|e| format!("flush stdout: {e}"))?;
    }
    Ok(())
}

fn error_response(error: &str) -> Json {
    obj([
        ("ok".into(), Json::Bool(false)),
        ("error".into(), s(error)),
    ])
}
