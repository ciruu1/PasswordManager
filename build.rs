use std::io;
use winres::WindowsResource;

// for eg. this is my build script
// I've tested this on linux and windows with rust 1.64

fn main() -> io::Result<()> {
    if std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap() == "windows" {
        let mut res = WindowsResource::new();
        match std::env::var("CARGO_CFG_TARGET_ENV").unwrap().as_str() {
            "gnu" => {
                res.set_ar_path("x86_64-w64-mingw32-ar")
                    .set_windres_path("x86_64-w64-mingw32-windres");
            }
            "msvc" => {}
            _ => panic!("unsupported env"),
        };
        res.set_icon("./assets/icon.ico");
        res.compile()?;
    }
    Ok(())
}