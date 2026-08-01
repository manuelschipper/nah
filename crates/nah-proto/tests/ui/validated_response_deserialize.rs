use nah_proto::extension::ValidatedExtensionResponse;

fn main() {
    let _: ValidatedExtensionResponse = serde_json::from_str("{}").unwrap();
}
