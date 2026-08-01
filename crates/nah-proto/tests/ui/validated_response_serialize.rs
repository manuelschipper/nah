use nah_proto::extension::ValidatedExtensionResponse;

fn forbidden(value: &ValidatedExtensionResponse) {
    let _ = serde_json::to_string(value);
}

fn main() {}
