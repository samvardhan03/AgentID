use std::path::Path;

fn main() {
    if std::env::var_os("CARGO_FEATURE_SERVER").is_some() {
        let proto = Path::new("proto/agentid.proto");
        if proto.exists() {
            tonic_build::configure()
                .build_client(true)
                .build_server(true)
                .compile(&[proto], &[Path::new("proto")])
                .expect("failed to compile agentid.proto");
            println!("cargo:rerun-if-changed=proto/agentid.proto");
        }
    }

    if std::env::var_os("CARGO_FEATURE_NAPI_BINDINGS").is_some() {
        napi_build::setup();
    }

    println!("cargo:rerun-if-changed=build.rs");
}
