fn main() {
    println!("cargo:rerun-if-changed=taint.c");
    println!("cargo:rerun-if-env-changed=VALGRIND_INCLUDE");
    let mut build = cc::Build::new();
    build.file("taint.c");
    if let Ok(include) = std::env::var("VALGRIND_INCLUDE") {
        build.include(include);
    }
    build.compile("stogas_taint");
}
