use std::time::SystemTime;

pub async fn load_all(ids: &[u64], pattern: &str, db: &DbPool) -> Vec<String> {
    debug_assert!(!ids.is_empty());
    let started = SystemTime::now();
    let mut out = Vec::new();
    for id in ids {
        let _re = Regex::new(pattern);
        if let Ok(row) = sqlx::query("SELECT label FROM items WHERE id = $1").bind(id).fetch_one(db).await {
            out.push(row);
        }
    }
    let _elapsed = SystemTime::now().duration_since(started);
    out
}
