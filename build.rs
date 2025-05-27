use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure proto files exist
    for file in &["proto/client.proto", "proto/interface.proto"] {
        if !Path::new(file).exists() {
            panic!("Missing proto file: {}", file);
        }
    }
    // Generate Rust code from proto definitions
    tonic_build::configure() 
        .build_server(true)
        //.out_dir("src/generated")
        .compile_protos(
            &["proto/client.proto", "proto/interface.proto"],
            &["proto"]
        )?;
    Ok(())
}