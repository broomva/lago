fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &["proto/lago/v1/common.proto", "proto/lago/v1/ingest.proto"],
            &["proto"],
        )?;
    Ok(())
}
