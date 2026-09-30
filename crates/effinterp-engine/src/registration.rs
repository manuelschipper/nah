pub use effinterp_proto::{Registration, RegistrationKind};

/// Bounded declaration scan, before the repository chooses reachable module roots.
/// Source bytes bound storage; lexer tokens conservatively bound scan work and AST nodes.
pub fn registrations(
    source: &str,
    lang: crate::Lang,
    file: &str,
    limits: &effinterp_proto::Limits,
) -> Result<Vec<Registration>, &'static str> {
    if source.len() as u64 > limits["max_source_bytes"] {
        return Err("max_source_bytes");
    }
    if source.len() as u64 > limits["max_analysis_bytes"] {
        return Err("max_analysis_bytes");
    }
    let node_limit = crate::SummaryBudget::limit_name(lang);
    let mut steps = 0_u64;
    let mut charge = || {
        steps += 1;
        for limit in ["max_analysis_steps", node_limit] {
            if steps > limits[limit] {
                return Err(limit);
            }
        }
        Ok(())
    };
    match lang {
        crate::Lang::Python => {
            for token in rustpython_parser::lexer::lex(source, rustpython_parser::Mode::Module) {
                token.map_err(|_| "parse_error: registration scan")?;
                charge()?;
            }
        }
        crate::Lang::Go => {
            for _ in gosyn::tokenize_source(source).map_err(|_| "parse_error: registration scan")? {
                charge()?;
            }
        }
        _ => return Ok(Vec::new()),
    }
    match lang {
        crate::Lang::Python => {
            crate::python::registrations(source, file, limits["max_analysis_bytes"])
        }
        crate::Lang::Go => {
            crate::lang::go::registrations(source, file, limits["max_analysis_bytes"])
        }
        _ => Ok(Vec::new()),
    }
}

pub(crate) fn charge_registration(
    bytes_left: &mut u64,
    registration: &Registration,
) -> Result<(), &'static str> {
    let bytes = effinterp_proto::canonical_json(registration).len() as u64 + 128;
    *bytes_left = bytes_left.checked_sub(bytes).ok_or("max_analysis_bytes")?;
    Ok(())
}
