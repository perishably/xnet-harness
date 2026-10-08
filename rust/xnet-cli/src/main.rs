use std::{io::{self,BufRead,Read,Write},path::PathBuf};
use xnet_fabric::{Operation,Response,MAX_FRAME};
fn main() {if let Err(e)=run(){eprintln!("xnet: {e}");std::process::exit(2);}}
fn run()->Result<(),String> {
    let args:Vec<String>=std::env::args().skip(1).collect();
    if args==["version"] {println!("{}",serde_json::json!({"application":"xnet","version":env!("CARGO_PKG_VERSION"),"api":xnet_fabric::API}));return Ok(());}
    if args.len()==3 && args[0]=="peer-health" && args[1]=="--port" {
        let port=args[2].parse::<u16>().map_err(|_|"invalid_port")?;
        let result=xnet_transport::LoopbackHealth::new(port)?.read()?;
        println!("{}",serde_json::to_string(&result).map_err(|_|"response_encode_failed")?); return Ok(());
    }
    if args.len()!=3 || args[1]!="--root" || !["daemon","health","sets","verify"].contains(&args[0].as_str()) {return Err("usage: xnet version | {daemon|health|sets|verify} --root ABSOLUTE_PATH".into());}
    let mut runtime=match xnet_runtime::Runtime::open(&PathBuf::from(&args[2])) {
        Ok(runtime)=>runtime,
        Err(error)=>{
            if args[0]=="daemon" {
                let response=Response::new("startup".into(),Err(error.clone()));
                println!("{}",serde_json::to_string(&response).map_err(|_|"response_encode_failed")?);
            }
            return Err(error);
        }
    };
    if args[0]!="daemon" {
        let op=match args[0].as_str(){"health"=>Operation::Health,"sets"=>Operation::Sets,_=>Operation::Verify};
        let response=Response::new("cli".into(),runtime.execute(op));
        println!("{}",serde_json::to_string(&response).map_err(|_|"response_encode_failed")?);
        return if response.ok {Ok(())} else {Err(response.error.unwrap_or_default())};
    }
    // Process daemon: private stdio only. EOF releases its own lease; no detached child, network or model.
    let stdin=io::stdin(); let mut reader=stdin.lock(); let stdout=io::stdout(); let mut writer=stdout.lock();
    loop {
        let mut line=Vec::new();
        let n=reader.by_ref().take((MAX_FRAME+2) as u64).read_until(b'\n',&mut line).map_err(|_|"input_failed")?;
        if n==0 {break;}
        if n>MAX_FRAME || line.last()!=Some(&b'\n') {return Err("invalid_or_oversize_frame".into());}
        let response=match xnet_fabric::parse_request(&line) {Ok(r)=>Response::new(r.id,runtime.execute(r.request)),Err(e)=>Response::new(xnet_fabric::rejected_request_id(&line),Err(e))};
        let bytes=serde_json::to_vec(&response).map_err(|_|"response_encode_failed")?;
        if bytes.len()>MAX_FRAME {return Err("response_too_large".into());}
        writer.write_all(&bytes).and_then(|_|writer.write_all(b"\n")).and_then(|_|writer.flush()).map_err(|_|"output_failed")?;
        if runtime.stopped(){break;}
    }
    Ok(())
}
