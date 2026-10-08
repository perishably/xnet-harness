//! Fixed loopback health transport for sibling services. No arbitrary URL, redirects or proxy.
use std::time::Duration;
pub struct LoopbackHealth { runtime:tokio::runtime::Runtime, client:reqwest::Client, port:u16 }
impl LoopbackHealth {
    pub fn new(port:u16)->Result<Self,String> {
        if port==0 {return Err("invalid_port".into());}
        let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_|"runtime_failed")?;
        let client=reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).connect_timeout(Duration::from_secs(2)).timeout(Duration::from_secs(5)).build().map_err(|_|"client_failed")?;
        Ok(Self{runtime,client,port})
    }
    pub fn read(&self)->Result<serde_json::Value,String> {
        self.runtime.block_on(async {
            let mut response=self.client.get(format!("http://127.0.0.1:{}/health",self.port)).send().await.map_err(|_|"health_unavailable")?;
            if !response.status().is_success() {return Err("health_http_failed".into());}
            if response.content_length().is_some_and(|n|n>65536) {return Err("health_too_large".into());}
            let mut bytes=Vec::new();
            while let Some(chunk)=response.chunk().await.map_err(|_|"health_read_failed")? {
                if bytes.len()+chunk.len()>65536 {return Err("health_too_large".into());} bytes.extend_from_slice(&chunk);
            }
            serde_json::from_slice(&bytes).map_err(|_|"invalid_health".into())
        })
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn no_redirect_and_bounded_body() {
        for (status,body,works) in [("200 OK","{\"healthy\":true}".to_owned(),true),("302 Found","".to_owned(),false),("200 OK","x".repeat(65537),false)] {
            let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap(); let port=listener.local_addr().unwrap().port();
            let h=std::thread::spawn(move || {use std::io::{Read,Write}; let (mut s,_)=listener.accept().unwrap(); s.set_read_timeout(Some(Duration::from_secs(5))).unwrap(); let mut b=[0;4096];s.read(&mut b).unwrap(); let data=format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nLocation: http://127.0.0.1:1/health\r\nConnection: close\r\n\r\n{body}",body.len()); let _=s.write_all(data.as_bytes());});
            assert_eq!(LoopbackHealth::new(port).unwrap().read().is_ok(),works);h.join().unwrap();
        }
    }
}
