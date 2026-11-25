use std::collections::HashMap;
use std::time::Instant;

pub fn resolve_labels(ids: &[&str], catalog: &[(&str, &str)]) -> (Vec<String>, u128) {
    assert!(!catalog.is_empty());
    let started = Instant::now();
    let index: HashMap<&str, &str> = catalog.iter().copied().collect();
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(label) = index.get(id) {
            out.push((*label).to_string());
        }
    }
    (out, started.elapsed().as_millis())
}

#[cfg(test)]
mod tests {
    use super::resolve_labels;

    #[test]
    fn maps_known_ids_in_order() {
        let (labels, _) = resolve_labels(&["a"], &[("a", "Alpha")]);
        assert_eq!(labels, vec!["Alpha".to_string()]);
    }
}
