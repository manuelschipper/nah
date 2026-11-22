//! Python decoders.
//! Modeled stream decoding and recovery of exact literal bytes are separate evidence.

use effinterp_proto::AttrValue;
use rustpython_parser::ast;
use rustpython_parser::ast::{Constant, Expr};
use rustpython_parser::text_size::TextRange;

use super::PythonWalker;
use super::model::ExactValue;
use super::resolve::str_literal;

/// The standard-library calls that return the decoded or decompressed bytes
/// of their operand: what `exec` or a shell would run as hidden content.
/// Recognize stream decoders independently of whether the operand's literal bytes are recoverable.
pub(super) fn is_python_stream_decoder(name: &str) -> bool {
    matches!(
        name,
        "base64.b64decode"
            | "base64.standard_b64decode"
            | "base64.urlsafe_b64decode"
            | "base64.b32decode"
            | "base64.b32hexdecode"
            | "base64.b16decode"
            | "base64.b85decode"
            | "base64.a85decode"
            | "base64.z85decode"
            | "base64.decodebytes"
            | "binascii.a2b_base64"
            | "binascii.a2b_hex"
            | "binascii.unhexlify"
            | "binascii.a2b_uu"
            | "binascii.a2b_qp"
            | "bytes.fromhex"
            | "codecs.decode"
            | "quopri.decodestring"
            | "zlib.decompress"
            | "gzip.decompress"
            | "bz2.decompress"
            | "lzma.decompress"
    )
}

impl PythonWalker<'_, '_> {
    /// The bytes a decoder returns for a literal operand: base64 through
    /// `base64` and `binascii`, hex through `bytes.fromhex` and `binascii`,
    /// and either through `codecs.decode`. A literal that does not decode
    /// raises, so it yields nothing.
    pub(super) fn decoded_literal_bytes(&self, call: &ast::ExprCall) -> Option<Vec<u8>> {
        // `bytes.fromhex` is a method of the builtin type, not an import.
        let name = match (self.imports.resolve_callee(&call.func), call.func.as_ref()) {
            (Some(name), _) => name,
            (None, Expr::Attribute(method))
                if method.attr.as_str() == "fromhex"
                    && self.imports.resolve_callee(&method.value).as_deref() == Some("bytes") =>
            {
                "bytes.fromhex".to_string()
            }
            _ => return None,
        };
        let name = name.strip_prefix("builtins.").unwrap_or(&name);
        let codec = match call.args.as_slice() {
            [_] if call.keywords.is_empty() => None,
            [_, codec] if call.keywords.is_empty() && name == "codecs.decode" => {
                Some(str_literal(codec)?)
            }
            _ => return None,
        };
        let encoded = match &call.args[0] {
            Expr::Constant(constant) => match &constant.value {
                Constant::Str(text) => text.as_bytes().to_vec(),
                Constant::Bytes(bytes) => bytes.clone(),
                _ => return None,
            },
            _ => return None,
        };
        use crate::embedded_archive::{decode_base64, decode_hex};
        match (name, codec.as_deref()) {
            (
                "base64.b64decode"
                | "base64.standard_b64decode"
                | "base64.decodebytes"
                | "binascii.a2b_base64",
                None,
            )
            | ("codecs.decode", Some("base64" | "base_64" | "base64_codec")) => {
                decode_base64(&encoded, false)
            }
            ("base64.urlsafe_b64decode", None) => decode_base64(&encoded, true),
            ("bytes.fromhex" | "binascii.unhexlify" | "binascii.a2b_hex", None)
            | ("codecs.decode", Some("hex" | "hex_codec")) => decode_hex(&encoded),
            _ => None,
        }
    }

    /// A decoder or decompressor runs inside the interpreter executing this
    /// source, so that interpreter process performs the transform. The
    /// transform is exact; whether the operand is valid input is not asserted.
    pub(super) fn stream_decode(&mut self, span: TextRange, name: &str) {
        let node = self.span_node(span);
        let resource = self.interpreter_resource();
        let model = if name.starts_with("base64.") {
            "python/base64@v0"
        } else {
            "python/decoders@v0"
        };
        self.emit_request(
            "process.stream_transform",
            resource,
            std::collections::BTreeMap::from([(
                "transform".to_string(),
                AttrValue::String("decode".to_string()),
            )]),
            node,
            Some(model),
        );
    }

    /// The text a shell receives from a base64 decoder applied to a literal,
    /// optionally followed by `.decode()`. A literal that does not decode
    /// raises before any shell starts, so it yields no command.
    pub(super) fn decoded_literal_shell_text(&self, expr: &Expr) -> Option<String> {
        let Expr::Call(call) = expr else {
            return None;
        };
        if let Expr::Attribute(attr) = call.func.as_ref()
            && attr.attr.as_str() == "decode"
        {
            return (self.safe_method_result(call, 0) == Some(ExactValue::Text))
                .then(|| self.decoded_literal_shell_text(&attr.value))
                .flatten();
        }
        let urlsafe = match self.imports.resolve_callee(&call.func)?.as_str() {
            "base64.b64decode" | "base64.standard_b64decode" => false,
            "base64.urlsafe_b64decode" => true,
            _ => return None,
        };
        let [operand] = call.args.as_slice() else {
            return None;
        };
        if !call.keywords.is_empty() {
            return None;
        }
        let encoded = match operand {
            Expr::Constant(constant) => match &constant.value {
                Constant::Str(text) => text.as_bytes().to_vec(),
                Constant::Bytes(bytes) => bytes.clone(),
                _ => return None,
            },
            _ => return None,
        };
        String::from_utf8(crate::embedded_archive::decode_base64(&encoded, urlsafe)?).ok()
    }
}
