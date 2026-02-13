use std::future::Future;

use anyhow::{Context, Result};

pub fn run_scan<F>(scan_future: F) -> Result<i32>
where
    F: Future<Output = Result<i32>>,
{
    let handle = tokio::runtime::Handle::try_current()
        .context("No active Tokio runtime available for watch scan")?;

    tokio::task::block_in_place(|| handle.block_on(scan_future))
}
