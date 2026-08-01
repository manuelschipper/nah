use nah_proto::extension::ValidatedExtensionResponse;

fn forbidden(value: ValidatedExtensionResponse) -> ValidatedExtensionResponse {
    ValidatedExtensionResponse { ..value }
}

fn main() {}
