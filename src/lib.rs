//! SimpleProxy - A local proxy tool that intercepts specific URLs
//! and replaces content or redirects based on configurable rules.

pub mod cert;
pub mod config;
pub mod proxy;
pub mod rule_engine;
pub mod system_proxy;
pub mod tun_proxy;
pub mod upstream;
pub mod web;
