pub struct OrderStore;

pub trait Reader {
    fn fetch_latest(&self);
}

impl Reader for OrderStore {
    fn fetch_latest(&self) {
        let _ = sqlx::query("SELECT 1").fetch_one(self);
    }
}

pub fn label_from_wire(status: &str) -> &'static str {
    match status {
        "pending" => "Waiting",
        "captured" => "Done",
        _ => "Unknown",
    }
}
