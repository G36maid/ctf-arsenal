// Rust 多執行緒暴力破解模板
// Compile: rustc -O solve.rs
// Run: ./solve

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

fn brute_force(start: u64, end: u64, found: Arc<Mutex<Option<u64>>>) {
    for i in start..end {
        // 檢查是否已經找到
        if found.lock().unwrap().is_some() {
            return;
        }

        // === 你的驗證邏輯 ===
        // 例如: hash 比對、密碼驗證等
        if check_condition(i) {
            let mut result = found.lock().unwrap();
            *result = Some(i);
            println!("Found: {}", i);
            return;
        }

        // 進度顯示
        if i % 1000000 == 0 {
            println!("Progress: {}", i);
        }
    }
}

fn check_condition(n: u64) -> bool {
    // === 替換成你的條件 ===
    // 例如: n % 12345 == 67890
    n == 42 // 範例
}

fn main() {
    let start_time = Instant::now();
    let num_threads = 8;
    let range_size = 100_000_000u64;
    let chunk_size = range_size / num_threads as u64;

    let found = Arc::new(Mutex::new(None));
    let mut handles = vec![];

    for i in 0..num_threads {
        let start = i as u64 * chunk_size;
        let end = (i as u64 + 1) * chunk_size;
        let found_clone = Arc::clone(&found);

        let handle = thread::spawn(move || {
            brute_force(start, end, found_clone);
        });

        handles.push(handle);
    }

    // 等待所有執行緒完成
    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = start_time.elapsed();

    match *found.lock().unwrap() {
        Some(result) => println!("Result: {}", result),
        None => println!("Not found"),
    }

    println!("Time elapsed: {:?}", elapsed);
}
