use std::path::Path;
use std::env;

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap() + "/../../../cadence";
    let path = Path::new(&dir).display();
    let lib = "main";
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", path);
    println!("cargo:rustc-link-lib=dylib={}", lib);
    println!("cargo:rustc-link-search=native={}", path);
    
}