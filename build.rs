fn main() {
    // Mensaje opcional durante la compilación
    println!("cargo:rerun-if-changed=build.rs");
}