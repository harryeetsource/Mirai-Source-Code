use std::thread;
use std::time::Duration;

fn main() {
    println!("REPORT {}:{}", "127.0.0.1", "80");

    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
