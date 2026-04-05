//! Simple in-memory token bucket rate limiter for HTTP routes.
//!
//! Designed for single-instance deployments (Railway). Uses a per-IP
//! token bucket with configurable capacity and refill rate.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum tokens (requests) in the bucket.
    pub capacity: u32,
    /// Tokens refilled per second.
    pub refill_per_second: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            // 1000 req/min = ~16.67 req/sec
            capacity: 1000,
            refill_per_second: 1000.0 / 60.0,
        }
    }
}

/// A single bucket tracking tokens for one IP.
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(capacity: u32) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns the remaining tokens if successful.
    fn try_consume(&mut self, config: &RateLimitConfig) -> Option<u32> {
        // Refill tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens =
            (self.tokens + elapsed * config.refill_per_second).min(config.capacity as f64);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Some(self.tokens as u32)
        } else {
            None
        }
    }

    /// Seconds until the next token is available.
    fn retry_after(&self, config: &RateLimitConfig) -> u32 {
        let needed = 1.0 - self.tokens;
        if needed <= 0.0 {
            return 0;
        }
        (needed / config.refill_per_second).ceil() as u32
    }
}

/// Thread-safe rate limiter state shared across requests.
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Try to consume a token for the given IP.
    /// Returns `Ok(remaining)` or `Err(retry_after_secs)`.
    pub fn check(&self, ip: IpAddr) -> Result<u32, u32> {
        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets
            .entry(ip)
            .or_insert_with(|| Bucket::new(self.config.capacity));

        match bucket.try_consume(&self.config) {
            Some(remaining) => Ok(remaining),
            None => Err(bucket.retry_after(&self.config)),
        }
    }

    /// Get the configured capacity for rate limit headers.
    pub fn capacity(&self) -> u32 {
        self.config.capacity
    }

    /// Periodically clean up expired buckets (buckets that are full).
    /// Call this from a background task if needed.
    pub fn cleanup(&self) {
        let mut buckets = self.buckets.lock().unwrap();
        let config = &self.config;
        buckets.retain(|_, bucket| {
            let elapsed = bucket.last_refill.elapsed().as_secs_f64();
            let tokens = bucket.tokens + elapsed * config.refill_per_second;
            // Remove buckets that have been idle long enough to be full
            tokens < config.capacity as f64
        });
    }
}

/// JSON body for 429 responses.
#[derive(Serialize)]
struct RateLimitExceeded {
    error: String,
    message: String,
    retry_after: u32,
}

/// Extract client IP from the request, checking common proxy headers.
fn extract_client_ip(request: &Request) -> IpAddr {
    // Check X-Forwarded-For header (Railway sets this)
    if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            // Take the first IP (original client)
            if let Some(first) = value.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    // Check X-Real-IP
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            if let Ok(ip) = value.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // Fall back to connection info
    if let Some(connect_info) = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
    {
        return connect_info.0.ip();
    }

    // Last resort: localhost
    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}

/// Axum middleware that applies rate limiting per client IP.
///
/// Uses the `RateLimiter` from the request extensions. Set rate limit
/// headers on all responses, return 429 when exceeded.
pub async fn rate_limit_middleware(
    axum::extract::State(limiter): axum::extract::State<std::sync::Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let client_ip = extract_client_ip(&request);

    match limiter.check(client_ip) {
        Ok(remaining) => {
            let mut response = next.run(request).await;
            let headers = response.headers_mut();
            headers.insert(
                "x-ratelimit-limit",
                limiter.capacity().to_string().parse().unwrap(),
            );
            headers.insert(
                "x-ratelimit-remaining",
                remaining.to_string().parse().unwrap(),
            );
            response
        }
        Err(retry_after) => {
            let body = RateLimitExceeded {
                error: "rate_limit_exceeded".to_string(),
                message: format!(
                    "rate limit exceeded: {} requests per minute",
                    limiter.capacity()
                ),
                retry_after,
            };
            let mut response = (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
            let headers = response.headers_mut();
            headers.insert("retry-after", retry_after.to_string().parse().unwrap());
            headers.insert(
                "x-ratelimit-limit",
                limiter.capacity().to_string().parse().unwrap(),
            );
            headers.insert("x-ratelimit-remaining", "0".parse().unwrap());
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_up_to_capacity() {
        let config = RateLimitConfig {
            capacity: 3,
            refill_per_second: 1.0,
        };
        let mut bucket = Bucket::new(3);

        assert!(bucket.try_consume(&config).is_some()); // 2 left
        assert!(bucket.try_consume(&config).is_some()); // 1 left
        assert!(bucket.try_consume(&config).is_some()); // 0 left
        assert!(bucket.try_consume(&config).is_none()); // empty
    }

    #[test]
    fn rate_limiter_per_ip_isolation() {
        let limiter = RateLimiter::new(RateLimitConfig {
            capacity: 2,
            refill_per_second: 0.0, // No refill for testing
        });

        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();

        assert!(limiter.check(ip1).is_ok());
        assert!(limiter.check(ip1).is_ok());
        assert!(limiter.check(ip1).is_err()); // ip1 exhausted

        assert!(limiter.check(ip2).is_ok()); // ip2 still has tokens
    }

    #[test]
    fn retry_after_calculated() {
        let config = RateLimitConfig {
            capacity: 1,
            refill_per_second: 1.0,
        };
        let mut bucket = Bucket::new(1);

        bucket.try_consume(&config); // Consume the token
        let retry = bucket.retry_after(&config);
        assert!(retry >= 1, "should need at least 1 second");
    }
}
