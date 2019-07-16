fn main() {
    use std::path::Path;

    let dir = std::env::var("OUT_DIR").unwrap();

    let src = Path::new("src").join("header.h");
    let dst = Path::new(&dir).join("header.rs");

    std::process::Command::new("bindgen")
        .arg(src)
        .arg("-o")
        .arg(dst)
        .output()
        .expect("failed to generate bindings from the header");
}
