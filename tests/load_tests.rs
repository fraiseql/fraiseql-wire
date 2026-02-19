//! Load testing suite for fraiseql-wire
//!
//! Tests throughput, memory stability, and performance under sustained load.
//! These tests require a running Postgres instance with the test_staging schema.
//!
//! Run with: cargo test --test load_tests -- --ignored --nocapture

use fraiseql_wire::client::FraiseClient;
use futures::stream::StreamExt;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

/// Helper to connect to test database
async fn connect_test_db() -> fraiseql_wire::error::Result<FraiseClient> {
    let conn_string = format!(
        "postgres://{}:{}@{}/{}",
        std::env::var("POSTGRES_USER").unwrap_or_else(|_| "postgres".to_string()),
        std::env::var("POSTGRES_PASSWORD").unwrap_or_else(|_| "postgres".to_string()),
        std::env::var("POSTGRES_HOST").unwrap_or_else(|_| "localhost".to_string()),
        std::env::var("POSTGRES_DB").unwrap_or_else(|_| "fraiseql_test".to_string()),
    );

    FraiseClient::connect(&conn_string).await
}

/// Test streaming with moderate data volume
#[tokio::test]
#[ignore] // Requires Postgres running
async fn test_load_moderate_volume() {
    println!("Test: Moderate data volume streaming");

    let client = connect_test_db()
        .await
        .expect("failed to connect to test database");

    let start = Instant::now();
    let mut stream = client
        .query::<serde_json::Value>("projects")
        .execute()
        .await
        .expect("failed to execute query");

    let mut count = 0;
    while let Some(result) = stream.next().await {
        let _value = result.expect("failed to deserialize row");
        count += 1;
    }

    let elapsed = start.elapsed();
    let throughput = count as f64 / elapsed.as_secs_f64();

    println!("  Rows: {}", count);
    println!("  Time: {:?}", elapsed);
    println!("  Throughput: {:.0} rows/sec", throughput);

    assert!(count > 0, "should have received rows");
    assert!(throughput > 0.0, "throughput should be positive");
}

/// Test streaming with large data volume and custom chunk size
#[tokio::test]
#[ignore] // Requires Postgres running
async fn test_load_large_volume_custom_chunk() {
    println!("Test: Large volume with custom chunk size");

    let client = connect_test_db()
        .await
        .expect("failed to connect to test database");

    let start = Instant::now();
    let mut stream = client
        .query::<serde_json::Value>("tasks")
        .chunk_size(512) // Larger chunk for more rows per batch
        .execute()
        .await
        .expect("failed to execute query");

    let mut count = 0;
    while let Some(result) = stream.next().await {
        let _value = result.expect("failed to deserialize row");
        count += 1;
    }

    let elapsed = start.elapsed();
    let throughput = count as f64 / elapsed.as_secs_f64();

    println!("  Rows: {}", count);
    println!("  Chunk size: 512");
    println!("  Time: {:?}", elapsed);
    println!("  Throughput: {:.0} rows/sec", throughput);

    assert!(count > 0, "should have received rows");
}

/// Test streaming with WHERE predicate (reduces data volume)
#[tokio::test]
#[ignore] // Requires Postgres running
async fn test_load_with_sql_predicate() {
    println!("Test: With SQL predicate filtering");

    let client = connect_test_db()
        .await
        .expect("failed to connect to test database");

    let start = Instant::now();
    let mut stream = client
        .query::<serde_json::Value>("projects")
        .where_sql("data->>'status' = 'active'")
        .execute()
        .await
        .expect("failed to execute query");

    let mut count = 0;
    while let Some(result) = stream.next().await {
        let _value = result.expect("failed to deserialize row");
        count += 1;
    }

    let elapsed = start.elapsed();
    let throughput = count as f64 / elapsed.as_secs_f64();

    println!("  Rows: {}", count);
    println!("  Time: {:?}", elapsed);
    println!("  Throughput: {:.0} rows/sec", throughput);
    println!("  (Predicate filtering should reduce row count)");
}

/// Test streaming with Rust predicate (client-side filtering)
#[tokio::test]
#[ignore] // Requires Postgres running
async fn test_load_with_rust_predicate() {
    println!("Test: With Rust predicate filtering");

    let client = connect_test_db()
        .await
        .expect("failed to connect to test database");

    let start = Instant::now();
    let mut stream = client
        .query::<serde_json::Value>("users")
        .where_rust(|json| {
            // Only accept users with profile info
            json.get("profile").is_some()
        })
        .execute()
        .await
        .expect("failed to execute query");

    let mut count = 0;
    while let Some(result) = stream.next().await {
        let _value = result.expect("failed to deserialize row");
        count += 1;
    }

    let elapsed = start.elapsed();
    let throughput = count as f64 / elapsed.as_secs_f64();

    println!("  Rows: {}", count);
    println!("  Time: {:?}", elapsed);
    println!("  Throughput: {:.0} rows/sec", throughput);
}

/// Test streaming documents (large JSON objects)
#[tokio::test]
#[ignore] // Requires Postgres running
async fn test_load_large_json_objects() {
    println!("Test: Large JSON objects");

    let client = connect_test_db()
        .await
        .expect("failed to connect to test database");

    let start = Instant::now();
    let mut stream = client
        .query::<serde_json::Value>("documents")
        .chunk_size(32) // Small chunks for large objects
        .execute()
        .await
        .expect("failed to execute query");

    let mut count = 0;
    let mut total_size: usize = 0;

    while let Some(result) = stream.next().await {
        let value = result.expect("failed to deserialize row");
        let size = value.to_string().len();
        total_size += size;
        count += 1;
    }

    let elapsed = start.elapsed();
    let avg_size = total_size.checked_div(count).unwrap_or(0);

    println!("  Rows: {}", count);
    println!("  Total size: {} bytes", total_size);
    println!("  Average size: {} bytes", avg_size);
    println!("  Time: {:?}", elapsed);

    assert!(count > 0, "should have received at least one large object");
}

/// Test with ORDER BY (server-side sorting)
#[tokio::test]
#[ignore] // Requires Postgres running
async fn test_load_with_order_by() {
    println!("Test: With ORDER BY clause");

    let client = connect_test_db()
        .await
        .expect("failed to connect to test database");

    let start = Instant::now();
    let mut stream = client
        .query::<serde_json::Value>("projects")
        .order_by("data->>'name' ASC")
        .execute()
        .await
        .expect("failed to execute query");

    let mut count = 0;
    let mut prev_name: Option<String> = None;

    while let Some(result) = stream.next().await {
        let value = result.expect("failed to deserialize row");
        let name = value
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Verify ordering
        if let Some(ref pn) = prev_name {
            assert!(pn <= &name, "order violation: {} > {}", pn, name);
        }

        prev_name = Some(name);
        count += 1;
    }

    let elapsed = start.elapsed();

    println!("  Rows: {}", count);
    println!("  Time: {:?}", elapsed);
    println!("  Ordering verified: ✓");
}

/// Test multiple sequential connections (simulates concurrent workload)
#[tokio::test]
#[ignore] // Requires Postgres running
async fn test_load_multiple_sequential_connections() {
    println!("Test: Multiple sequential connections");

    let num_connections = 5;
    let mut total_rows = 0;

    for i in 0..num_connections {
        let client = connect_test_db().await.expect("failed to connect");

        let start = Instant::now();
        let mut stream = client
            .query::<serde_json::Value>("projects")
            .execute()
            .await
            .expect("failed to execute");

        let mut count = 0;
        while let Some(result) = stream.next().await {
            let _value = result.expect("failed to deserialize");
            count += 1;
        }

        let elapsed = start.elapsed();

        total_rows += count;
        println!("    Connection {}: {} rows in {:?}", i, count, elapsed);

        assert!(count > 0, "connection {} should have received rows", i);
    }

    println!("  Total connections: {}", num_connections);
    println!("  Total rows: {}", total_rows);
    println!("  Sequential streaming: ✓");
}

/// Test streaming stability over time (look for memory leaks)
#[tokio::test]
#[ignore] // Requires Postgres running - long running test
async fn test_load_sustained_streaming() {
    println!("Test: Sustained streaming (duration test)");

    let client = connect_test_db()
        .await
        .expect("failed to connect to test database");

    let duration = std::time::Duration::from_secs(30); // 30-second test
    let start = Instant::now();

    let mut stream = client
        .query::<serde_json::Value>("projects")
        .execute()
        .await
        .expect("failed to execute query");

    let mut count = 0;

    while let Some(result) = stream.next().await {
        let _value = result.expect("failed to deserialize row");
        count += 1;

        // Break if we've exceeded duration
        if start.elapsed() >= duration {
            break;
        }
    }

    let elapsed = start.elapsed();
    let throughput = count as f64 / elapsed.as_secs_f64();

    println!("  Duration: {:?}", elapsed);
    println!("  Rows: {}", count);
    println!("  Throughput: {:.0} rows/sec", throughput);
    println!("  Sustained streaming: ✓");
}

/// Benchmark different chunk sizes to find optimal throughput
#[tokio::test]
#[ignore] // Requires Postgres running
async fn test_load_chunk_size_comparison() {
    println!("Test: Chunk size performance comparison");

    let chunk_sizes = vec![16, 32, 64, 128, 256, 512];

    for chunk_size in chunk_sizes {
        let client = connect_test_db().await.expect("failed to connect");

        let start = Instant::now();
        let mut stream = client
            .query::<serde_json::Value>("projects")
            .chunk_size(chunk_size)
            .execute()
            .await
            .expect("failed to execute");

        let mut count = 0;
        while let Some(result) = stream.next().await {
            let _value = result.expect("failed to deserialize");
            count += 1;
        }

        let elapsed = start.elapsed();
        let throughput = count as f64 / elapsed.as_secs_f64();

        println!(
            "  Chunk {}: {:.0} rows/sec ({} rows in {:?})",
            chunk_size, throughput, count, elapsed
        );
    }
}

/// Test error recovery during streaming
#[tokio::test]
#[ignore] // Requires Postgres running
async fn test_load_partial_stream_drop() {
    println!("Test: Partial stream consumption and drop");

    let client = connect_test_db()
        .await
        .expect("failed to connect to test database");

    let mut stream = client
        .query::<serde_json::Value>("projects")
        .execute()
        .await
        .expect("failed to execute query");

    let mut count = 0;
    const LIMIT: usize = 2; // Only consume first 2 rows

    while let Some(result) = stream.next().await {
        let _value = result.expect("failed to deserialize row");
        count += 1;

        if count >= LIMIT {
            break; // Drop stream early
        }
    }

    println!("  Consumed: {} rows", count);
    println!("  Stream dropped early: ✓");
    // If we get here without panicking, cancellation worked

    // Now verify we can make another connection
    let client2 = connect_test_db()
        .await
        .expect("should be able to reconnect");

    let mut stream2 = client2
        .query::<serde_json::Value>("projects")
        .execute()
        .await
        .expect("failed to execute second query");

    let mut count2 = 0;
    while let Some(result) = stream2.next().await {
        let _value = result.expect("failed to deserialize row");
        count2 += 1;
        if count2 >= 1 {
            break; // Just get one row
        }
    }

    println!("  Reconnection: ✓");
    assert!(count2 > 0, "second connection should work");
}

// ---------------------------------------------------------------------------
// Concurrent connection tests
// ---------------------------------------------------------------------------

/// Spawn 20 connections simultaneously, each streaming projects to completion.
#[tokio::test]
#[ignore]
async fn test_load_concurrent_connection_storm() {
    println!("Test: Concurrent connection storm (20 connections)");

    let start = Instant::now();
    let mut set = JoinSet::new();

    for id in 0..20 {
        set.spawn(async move {
            let client = connect_test_db().await.expect("failed to connect");
            let mut stream = client
                .query::<serde_json::Value>("projects")
                .execute()
                .await
                .expect("failed to execute");

            let mut count: usize = 0;
            while let Some(result) = stream.next().await {
                let _value = result.expect("failed to deserialize");
                count += 1;
            }
            (id, count)
        });
    }

    let mut total_rows: usize = 0;
    while let Some(result) = set.join_next().await {
        let (id, count) = result.expect("task panicked");
        println!("    Connection {id}: {count} rows");
        assert!(count > 0, "connection {id} should have received rows");
        total_rows += count;
    }

    let elapsed = start.elapsed();
    println!("  Total rows: {total_rows}");
    println!("  Wall time: {elapsed:?}");
    println!("  Concurrent storm: ✓");
}

/// 50 rapid connect/query-one-row/drop cycles across 10 concurrent tasks.
#[tokio::test]
#[ignore]
async fn test_load_concurrent_connection_churn() {
    println!("Test: Concurrent connection churn (10 tasks × 5 cycles)");

    let start = Instant::now();
    let mut set = JoinSet::new();

    for task_id in 0..10 {
        set.spawn(async move {
            for cycle in 0..5 {
                let client = connect_test_db().await.unwrap_or_else(|e| {
                    panic!("task {task_id} cycle {cycle}: connect failed: {e}");
                });
                let mut stream = client
                    .query::<serde_json::Value>("projects")
                    .execute()
                    .await
                    .unwrap_or_else(|e| {
                        panic!("task {task_id} cycle {cycle}: execute failed: {e}");
                    });

                // Consume exactly one row then drop
                let row = stream.next().await.expect("expected at least one row");
                row.unwrap_or_else(|e| {
                    panic!("task {task_id} cycle {cycle}: deserialize failed: {e}");
                });
                drop(stream);
            }
            task_id
        });
    }

    let mut completed = 0;
    while let Some(result) = set.join_next().await {
        let _task_id = result.expect("task panicked");
        completed += 1;
    }

    let elapsed = start.elapsed();
    println!("  Completed: {completed} tasks (50 cycles total)");
    println!("  Wall time: {elapsed:?}");
    assert_eq!(completed, 10);
    println!("  Connection churn: ✓");
}

/// Spawn 5 concurrent tasks with different query shapes.
#[tokio::test]
#[ignore]
async fn test_load_concurrent_mixed_queries() {
    println!("Test: Concurrent mixed query shapes (5 tasks)");

    let start = Instant::now();
    let mut set = JoinSet::new();

    // Task 0: plain query
    set.spawn(async {
        let client = connect_test_db().await.expect("connect failed");
        let mut stream = client
            .query::<serde_json::Value>("projects")
            .execute()
            .await
            .expect("execute failed");
        let mut count: usize = 0;
        while let Some(r) = stream.next().await {
            r.expect("deser failed");
            count += 1;
        }
        ("plain", count)
    });

    // Task 1: with where_sql
    set.spawn(async {
        let client = connect_test_db().await.expect("connect failed");
        let mut stream = client
            .query::<serde_json::Value>("projects")
            .where_sql("data->>'status' = 'active'")
            .execute()
            .await
            .expect("execute failed");
        let mut count: usize = 0;
        while let Some(r) = stream.next().await {
            r.expect("deser failed");
            count += 1;
        }
        ("where_sql", count)
    });

    // Task 2: with order_by
    set.spawn(async {
        let client = connect_test_db().await.expect("connect failed");
        let mut stream = client
            .query::<serde_json::Value>("projects")
            .order_by("data->>'name' ASC")
            .execute()
            .await
            .expect("execute failed");
        let mut count: usize = 0;
        while let Some(r) = stream.next().await {
            r.expect("deser failed");
            count += 1;
        }
        ("order_by", count)
    });

    // Task 3: with where_rust
    set.spawn(async {
        let client = connect_test_db().await.expect("connect failed");
        let mut stream = client
            .query::<serde_json::Value>("projects")
            .where_rust(|json| json.get("name").is_some())
            .execute()
            .await
            .expect("execute failed");
        let mut count: usize = 0;
        while let Some(r) = stream.next().await {
            r.expect("deser failed");
            count += 1;
        }
        ("where_rust", count)
    });

    // Task 4: small chunk_size
    set.spawn(async {
        let client = connect_test_db().await.expect("connect failed");
        let mut stream = client
            .query::<serde_json::Value>("projects")
            .chunk_size(16)
            .execute()
            .await
            .expect("execute failed");
        let mut count: usize = 0;
        while let Some(r) = stream.next().await {
            r.expect("deser failed");
            count += 1;
        }
        ("chunk_16", count)
    });

    while let Some(result) = set.join_next().await {
        let (label, count) = result.expect("task panicked");
        println!("    {label}: {count} rows");
        assert!(count > 0, "{label} should have received rows");
    }

    let elapsed = start.elapsed();
    println!("  Wall time: {elapsed:?}");
    println!("  Mixed queries: ✓");
}

/// One slow consumer (50ms between rows) alongside 3 fast consumers.
#[tokio::test]
#[ignore]
async fn test_load_concurrent_slow_consumer() {
    println!("Test: Concurrent slow consumer with fast consumers");

    let start = Instant::now();
    let mut set = JoinSet::new();

    // Slow consumer
    set.spawn(async {
        let client = connect_test_db().await.expect("connect failed");
        let mut stream = client
            .query::<serde_json::Value>("projects")
            .execute()
            .await
            .expect("execute failed");
        let mut count: usize = 0;
        while let Some(r) = stream.next().await {
            r.expect("deser failed");
            count += 1;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        ("slow", count)
    });

    // 3 fast consumers
    for i in 0..3 {
        set.spawn(async move {
            let client = connect_test_db().await.expect("connect failed");
            let mut stream = client
                .query::<serde_json::Value>("projects")
                .execute()
                .await
                .expect("execute failed");
            let mut count: usize = 0;
            while let Some(r) = stream.next().await {
                r.expect("deser failed");
                count += 1;
            }
            let label: &str = match i {
                0 => "fast-0",
                1 => "fast-1",
                _ => "fast-2",
            };
            (label, count)
        });
    }

    while let Some(result) = set.join_next().await {
        let (label, count) = result.expect("task panicked");
        println!("    {label}: {count} rows");
        assert!(count > 0, "{label} should have received rows");
    }

    let elapsed = start.elapsed();
    println!("  Wall time: {elapsed:?}");
    println!("  Slow consumer: ✓");
}

/// 10 tasks each drop stream after consuming 2 rows, then verify a fresh connection works.
#[tokio::test]
#[ignore]
async fn test_load_concurrent_early_drop() {
    println!("Test: Concurrent early drop (10 tasks, 2 rows each)");

    let start = Instant::now();
    let mut set = JoinSet::new();

    for id in 0..10 {
        set.spawn(async move {
            let client = connect_test_db().await.expect("connect failed");
            let mut stream = client
                .query::<serde_json::Value>("projects")
                .execute()
                .await
                .expect("execute failed");

            let mut count: usize = 0;
            while let Some(r) = stream.next().await {
                r.expect("deser failed");
                count += 1;
                if count >= 2 {
                    break;
                }
            }
            drop(stream);
            (id, count)
        });
    }

    let mut completed = 0;
    while let Some(result) = set.join_next().await {
        let (id, count) = result.expect("task panicked");
        assert_eq!(count, 2, "task {id} should have consumed exactly 2 rows");
        completed += 1;
    }

    assert_eq!(completed, 10);
    println!("  All 10 tasks dropped early: ✓");

    // Verify server is still healthy
    let client = connect_test_db()
        .await
        .expect("fresh connection should succeed after drops");
    let mut stream = client
        .query::<serde_json::Value>("projects")
        .execute()
        .await
        .expect("execute failed");

    let mut count = 0;
    while let Some(r) = stream.next().await {
        r.expect("deser failed");
        count += 1;
    }

    let elapsed = start.elapsed();
    println!("  Fresh connection after drops: {count} rows");
    assert!(count > 0, "fresh connection should return rows");
    println!("  Wall time: {elapsed:?}");
    println!("  Early drop: ✓");
}

/// 5 concurrent connections streaming for 10 seconds, measuring aggregate throughput.
#[tokio::test]
#[ignore]
async fn test_load_concurrent_sustained_throughput() {
    println!("Test: Concurrent sustained throughput (5 connections, 10s)");

    let test_duration = Duration::from_secs(10);
    let start = Instant::now();
    let mut set = JoinSet::new();

    for id in 0..5 {
        let deadline = start + test_duration;
        set.spawn(async move {
            let mut total_rows: usize = 0;

            // Reconnect and re-stream until deadline
            while Instant::now() < deadline {
                let client = match connect_test_db().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let mut stream = match client
                    .query::<serde_json::Value>("projects")
                    .execute()
                    .await
                {
                    Ok(s) => s,
                    Err(_) => break,
                };

                while let Some(r) = stream.next().await {
                    if Instant::now() >= deadline {
                        break;
                    }
                    r.expect("deser failed");
                    total_rows += 1;
                }
            }
            (id, total_rows)
        });
    }

    let mut grand_total: usize = 0;
    while let Some(result) = set.join_next().await {
        let (id, rows) = result.expect("task panicked");
        println!("    Connection {id}: {rows} rows");
        grand_total += rows;
    }

    let elapsed = start.elapsed();
    let throughput = grand_total as f64 / elapsed.as_secs_f64();
    println!("  Total rows: {grand_total}");
    println!("  Wall time: {elapsed:?}");
    println!("  Aggregate throughput: {throughput:.0} rows/sec");
    assert!(grand_total > 0, "should have streamed some rows");
    println!("  Sustained throughput: ✓");
}
