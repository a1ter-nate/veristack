#[derive(Serialize)]
pub struct WirePacket {
    pub payload_len: usize,
}

pub fn hot_worker(items: &[u32]) {
    let (tx, _rx) = mpsc::channel();
    for item in items {
        let buf = Vec::new();
        let _ = (tx.send(*item), buf);
    }
    let _client = reqwest::Client::new();
}
