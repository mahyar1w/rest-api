use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Deserialize, Validate)]
pub struct Page {
    pub page: Option<i64>,
    pub limit: Option<i64>,
}

/// Returns `(page, limit, offset)`. The values are clamped so nobody can ask for limit=1000000.
pub fn clamp(page: Option<i64>, limit: Option<i64>) -> (i64, i64, i64) {
    let limit = limit.unwrap_or(20).clamp(1, 100);
    let page = page.unwrap_or(1).clamp(1, 1_000_000);
    (page, limit, (page - 1) * limit)
}

#[derive(Serialize)]
pub struct Paged<T> {
    data: Vec<T>,
    meta: Meta,
}

#[derive(Serialize)]
struct Meta {
    page: i64,
    limit: i64,
    total: i64,
}

impl<T> Paged<T> {
    pub fn new(data: Vec<T>, page: i64, limit: i64, total: i64) -> Self {
        Self {
            data,
            meta: Meta { page, limit, total },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::clamp;

    #[test]
    fn defaults_and_clamping() {
        assert_eq!(clamp(None, None), (1, 20, 0));
        assert_eq!(clamp(Some(3), Some(10)), (3, 10, 20));
        assert_eq!(clamp(Some(-5), Some(1_000_000)), (1, 100, 0));
        assert_eq!(clamp(Some(2), Some(0)), (2, 1, 1));
    }
}
