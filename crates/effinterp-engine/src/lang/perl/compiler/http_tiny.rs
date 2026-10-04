//! HTTP::Tiny in the Perl compiler: the request a method call sends, its
//! options hash, and the tracked slots whose bytes its payload carries.

use crate::resource_transfer::TransferBinding;

use super::{Compiler, Pending, PendingEffect, PerlObject, matching_brace};
use crate::lang::perl::PerlFailure;
use crate::lang::perl::token_shapes::{
    balanced, is_literal_data, perl_literal_text, split_list_items,
};
use crate::lang::perl::tokenize::PerlToken;

impl Compiler<'_, '_> {
    /// One HTTP::Tiny method call on `receiver`.
    pub(super) fn http_tiny_method_call(
        &mut self,
        receiver: &PerlObject,
        name: &str,
        arguments: &[PerlToken],
    ) -> Result<PerlObject, PerlFailure> {
        let arguments = split_list_items(arguments);
        let refused = || -> PerlFailure {
            format!(
                "Perl {name} method call or argument shape is outside the bounded literal grammar"
            )
            .into()
        };
        if *receiver == PerlObject::Class && name == "new" {
            return if arguments.iter().all(|argument| is_literal_data(argument)) {
                Ok(PerlObject::Client)
            } else {
                Err(refused())
            };
        }
        if *receiver != PerlObject::Client {
            return Err(refused());
        }
        // `request` names its method first; the others are the method.
        let (verb, arguments) = match (name, arguments.as_slice()) {
            ("request", [verb, rest @ ..]) => (
                perl_literal_text(verb, &self.variables, self.budget)?.to_ascii_lowercase(),
                rest,
            ),
            (_, arguments) => (name.to_string(), arguments),
        };
        let [url, rest @ ..] = arguments else {
            return Err(refused());
        };
        let url = perl_literal_text(url, &self.variables, self.budget)?;
        if verb == "mirror" {
            let [file, options @ ..] = rest else {
                return Err(refused());
            };
            let file = perl_literal_text(file, &self.variables, self.budget)?;
            self.http_tiny_request_options(options, false)?;
            let download = self.pending.len() as u32;
            self.pending.push(Pending::Request {
                operation: "network.download",
                url,
            });
            let mut write = PendingEffect::new("filesystem.write", file);
            write.disclosure = Some("contents");
            self.pending.push(Pending::Effect(write));
            self.transfers
                .push(TransferBinding::exact(download, download + 1));
            return Ok(PerlObject::Opaque);
        }
        // What the request sends: `None` when it has no body.
        let sent = match verb.as_str() {
            "get" | "head" | "delete" | "options" => {
                self.http_tiny_request_options(rest, false)?;
                None
            }
            "post" | "put" | "patch" => self.http_tiny_request_options(rest, true)?,
            "post_form" => {
                let [form, options @ ..] = rest else {
                    return Err(refused());
                };
                let sources = self.request_payload_slots(form)?;
                self.http_tiny_request_options(options, false)?;
                Some(sources)
            }
            _ => return Err(refused()),
        };
        let request = self.pending.len() as u32;
        self.pending.push(Pending::Request {
            operation: "network.request",
            url: url.clone(),
        });
        if let Some(sources) = sent {
            for source in sources {
                self.transfers
                    .push(TransferBinding::new(source, request + 1));
            }
            self.pending.push(Pending::Request {
                operation: "network.upload",
                url,
            });
        }
        Ok(PerlObject::Response(request))
    }

    /// A request's trailing options hash. With `body`, the slots whose bytes
    /// its `content` entry sends, or `None` when it has no such entry.
    fn http_tiny_request_options(
        &mut self,
        options: &[&[PerlToken]],
        body: bool,
    ) -> Result<Option<Vec<u32>>, PerlFailure> {
        let entries = match options {
            [] => return Ok(None),
            [[PerlToken::Punct('{'), entries @ .., PerlToken::Punct('}')]]
                if matching_brace(options[0]) == Ok(options[0].len() - 1) =>
            {
                split_list_items(entries)
            }
            [option] => {
                // Options built elsewhere may carry a body or a callback.
                self.refuse_unestablished_request_data(option);
                return Ok(body.then(Vec::new));
            }
            _ => return Err("Perl HTTP::Tiny call has more arguments than it takes".into()),
        };
        let mut sent = None;
        for entry in entries {
            match entry {
                [
                    PerlToken::Name(key) | PerlToken::Text(key),
                    PerlToken::Punct('='),
                    PerlToken::Punct('>'),
                    value @ ..,
                ] if body && key == "content" => {
                    sent = Some(self.request_payload_slots(value)?);
                }
                entry if is_literal_data(entry) => {}
                entry => self.refuse_unestablished_request_data(entry),
            }
        }
        Ok(sent)
    }

    /// The slots whose bytes `tokens` carries into a request: a tracked
    /// value, or the values of a literal hash or array.
    fn request_payload_slots(&mut self, tokens: &[PerlToken]) -> Result<Vec<u32>, PerlFailure> {
        if is_literal_data(tokens) {
            return Ok(Vec::new());
        }
        match perl_literal_text(tokens, &self.variables, self.budget) {
            Ok(_) => return Ok(Vec::new()),
            Err(PerlFailure::Refused(_)) => {}
            Err(failure) => return Err(failure),
        }
        if self.is_tracked_value(tokens) {
            return Ok(match self.tracked_value(tokens)? {
                PerlObject::FileData(slot) | PerlObject::Content(slot) => vec![slot],
                _ => Vec::new(),
            });
        }
        if let [
            PerlToken::Punct('{' | '['),
            entries @ ..,
            PerlToken::Punct('}' | ']'),
        ] = tokens
            && balanced(entries)
        {
            let mut sources = Vec::new();
            for entry in split_list_items(entries) {
                let value = match entry {
                    [_, PerlToken::Punct('='), PerlToken::Punct('>'), value @ ..] => value,
                    value => value,
                };
                sources.extend(self.request_payload_slots(value)?);
            }
            return Ok(sources);
        }
        self.refuse_unestablished_request_data(tokens);
        Ok(Vec::new())
    }

    /// Record request data the grammar cannot establish. The request itself
    /// is kept. Only a plain variable is known to change nothing else; any
    /// other expression may, so nothing after it is compiled.
    fn refuse_unestablished_request_data(&mut self, tokens: &[PerlToken]) {
        self.refusals
            .insert("Perl HTTP::Tiny request data is not established".into());
        if !matches!(tokens, [PerlToken::Variable(_)]) {
            self.halted = true;
        }
    }
}
