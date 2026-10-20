use std::collections::HashMap;

#[derive(Clone, Copy, Debug)]
struct Bucket {
    window_start_us: u64,
    count: u32,
}

#[derive(Default)]
pub struct RateLimiter {
    buckets: HashMap<String, Bucket>,
}

impl RateLimiter {
    pub fn allow(&mut self, key: &str, timestamp_us: u64, max_hz: u32) -> bool {
        if max_hz == 0 {
            return false;
        }
        let bucket = self.buckets.entry(key.to_owned()).or_insert(Bucket {
            window_start_us: timestamp_us,
            count: 0,
        });
        if timestamp_us.saturating_sub(bucket.window_start_us) >= 1_000_000 {
            bucket.window_start_us = timestamp_us;
            bucket.count = 0;
        }
        if bucket.count >= max_hz {
            return false;
        }
        bucket.count += 1;
        true
    }

    #[must_use]
    pub fn tracked_keys(&self) -> usize {
        self.buckets.len()
    }
}
