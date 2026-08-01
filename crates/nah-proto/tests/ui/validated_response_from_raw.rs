use nah_proto::extension::{ExtensionResponse, ValidatedExtensionResponse};

fn forbidden(raw: ExtensionResponse) -> ValidatedExtensionResponse {
    raw.into()
}

fn main() {}
