use std::env;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::mem;
use std::os::unix::io::AsRawFd;
use std::slice;
use memmap::MmapMut;
use elf::ElfHeader32;

fn main() -> io::Result<()> {
    println!(".: Elf corrupt :.");

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} file", args[0]);
        return Ok(());
    }

    let file_path = &args[1];
    let file = OpenOptions::new().read(true).write(true).open(file_path)?;

    // SAFETY: We use memmap crate to safely map the file into memory.
    let mut mmap = unsafe { MmapMut::map_mut(&file)? };

    // SAFETY: Transmute the first few bytes of the file to an Elf32_Ehdr.
    let header: &mut ElfHeader32 = unsafe { &mut *(mmap.as_mut_ptr() as *mut ElfHeader32) };

    println!("[*] Current header values:");
    println!("\te_shoff: {}\n\te_shnum: {}\n\te_shstrndx: {}",
             header.e_shoff, header.e_shnum, header.e_shstrndx);

    header.e_shoff = 0xffff;
    header.e_shnum = 0xffff;
    header.e_shstrndx = 0xffff;

    println!("[*] Patched header values:");
    println!("\te_shoff: {}\n\te_shnum: {}\n\te_shstrndx: {}",
             header.e_shoff, header.e_shnum, header.e_shstrndx);

    mmap.flush()?;
    println!("You should no more be able to run \"{}\" inside GDB", file_path);
    Ok(())
}
