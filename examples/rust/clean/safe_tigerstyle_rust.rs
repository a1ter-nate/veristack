use std::time::Duration;

#[derive(Serialize)]
pub struct WirePacket {
    pub payload_len_bytes: u32,
}

pub fn process_items(items: &[u32], out: &mut Vec<u32>) {
    assert!(!items.is_empty());
    for item in items {
        out.push(*item);
    }
}

pub fn build_http_client(timeout_ms_max: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms_max))
        .build()
        .unwrap_or_else(|_| panic!("failed to build client"))
}
