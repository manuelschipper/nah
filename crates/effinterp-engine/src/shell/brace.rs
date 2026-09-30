use super::lex::{Seg, Span, WordTok};

pub(super) enum BraceExpansion {
    /// One element when nothing expands.
    Words(Vec<WordTok>),
    Unsupported(Span),
    /// The count is computed before expanded words are allocated.
    Overflow {
        produced: usize,
    },
}

enum Node {
    Atom(Seg),
    Concat(Vec<usize>),
    List(Vec<usize>),
    Sequence {
        start: i128,
        step: i128,
        width: usize,
        letters: bool,
    },
}

struct Tree {
    nodes: Vec<Node>,
    sizes: Vec<usize>,
}

impl Tree {
    fn add(&mut self, node: Node) -> usize {
        let size = match &node {
            Node::Atom(_) => 1,
            Node::Concat(parts) => parts
                .iter()
                .fold(1usize, |n, &p| n.saturating_mul(self.sizes[p])),
            Node::List(parts) => parts
                .iter()
                .fold(0usize, |n, &p| n.saturating_add(self.sizes[p])),
            Node::Sequence { .. } => unreachable!(),
        };
        let id = self.nodes.len();
        self.nodes.push(node);
        self.sizes.push(size);
        id
    }
}

fn literal(text: impl Into<String>) -> Seg {
    Seg::Literal {
        text: text.into(),
        quoted: false,
    }
}

fn character(seg: &Seg) -> Option<char> {
    match seg {
        Seg::Literal {
            text,
            quoted: false,
        } if text.len() == 1 => text.chars().next(),
        _ => None,
    }
}

fn sequence(body: &[Seg]) -> Result<Option<(Node, usize)>, ()> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i + 1 < body.len() {
        if character(&body[i]) == Some('.') && character(&body[i + 1]) == Some('.') {
            fields.push(&body[start..i]);
            i += 2;
            start = i;
        } else {
            i += 1;
        }
    }
    fields.push(&body[start..]);
    if !(2..=3).contains(&fields.len()) {
        return Ok(None);
    }
    if fields
        .iter()
        .any(|field| field.iter().any(|seg| !matches!(seg, Seg::Literal { .. })))
    {
        return Err(());
    }
    let Some(fields) = fields
        .iter()
        .map(|field| field.iter().map(character).collect::<Option<String>>())
        .collect::<Option<Vec<_>>>()
    else {
        return Ok(None);
    };
    let step = if fields.len() == 3 {
        let Ok(step) = fields[2].parse::<i64>() else {
            return Ok(None);
        };
        i128::from(step).abs().max(1)
    } else {
        1
    };
    let (start, end, width, letters) = match (fields[0].parse::<i64>(), fields[1].parse::<i64>()) {
        (Ok(start), Ok(end)) => {
            let padded = fields[..2].iter().any(|field| {
                let digits = field.trim_start_matches('-');
                digits.len() > 1 && digits.starts_with('0')
            });
            let width = if padded {
                fields[0].len().max(fields[1].len())
            } else {
                0
            };
            (i128::from(start), i128::from(end), width, false)
        }
        _ if fields[..2]
            .iter()
            .all(|field| field.len() == 1 && field.as_bytes()[0].is_ascii_alphabetic()) =>
        {
            (
                i128::from(fields[0].as_bytes()[0]),
                i128::from(fields[1].as_bytes()[0]),
                0,
                true,
            )
        }
        _ => return Ok(None),
    };
    let size = usize::try_from((end - start).abs() / step + 1).unwrap_or(usize::MAX);
    Ok(Some((
        Node::Sequence {
            start,
            step: if end < start { -step } else { step },
            width,
            letters,
        },
        size,
    )))
}

/// Expand unquoted brace syntax before parameter expansion, preserving source spans.
/// The flat tree and explicit work stack also bound stack use for deeply nested input.
pub(super) fn expand(tok: &WordTok, cap: usize) -> BraceExpansion {
    if !tok
        .segs
        .iter()
        .any(|seg| matches!(seg, Seg::Literal { text, quoted: false } if text.contains('{')))
    {
        return BraceExpansion::Words(vec![tok.clone()]);
    }
    let mut atoms = Vec::new();
    for seg in &tok.segs {
        match seg {
            Seg::Literal {
                text,
                quoted: false,
            } => atoms.extend(text.chars().map(|c| literal(c.to_string()))),
            _ => atoms.push(seg.clone()),
        }
    }
    let mut matching = vec![false; atoms.len()];
    let mut opens = Vec::new();
    for (i, atom) in atoms.iter().enumerate() {
        match character(atom) {
            Some('{') => opens.push(i),
            Some('}') => {
                if let Some(open) = opens.pop() {
                    matching[open] = true;
                    matching[i] = true;
                }
            }
            _ => {}
        }
    }
    let mut tree = Tree {
        nodes: Vec::new(),
        sizes: Vec::new(),
    };
    let mut frames = vec![(0, vec![Vec::new()])];
    for (i, atom) in atoms.iter().enumerate() {
        let node = match character(atom) {
            Some('{') if matching[i] => {
                frames.push((i, vec![Vec::new()]));
                continue;
            }
            Some(',') if frames.len() > 1 => {
                frames.last_mut().unwrap().1.push(Vec::new());
                continue;
            }
            Some('}') if matching[i] => {
                let (open, parts) = frames.pop().unwrap();
                if parts.len() > 1 {
                    let alternatives = parts
                        .into_iter()
                        .map(|part| tree.add(Node::Concat(part)))
                        .collect();
                    tree.add(Node::List(alternatives))
                } else {
                    let sequence = if parts[0]
                        .iter()
                        .all(|&id| matches!(tree.nodes[id], Node::Atom(_)))
                    {
                        sequence(&atoms[open + 1..i])
                    } else {
                        Ok(None)
                    };
                    match sequence {
                        Err(()) => return BraceExpansion::Unsupported(tok.span),
                        Ok(Some((node, size))) => {
                            let id = tree.nodes.len();
                            tree.nodes.push(node);
                            tree.sizes.push(size);
                            id
                        }
                        Ok(None) => {
                            let mut parts = parts.into_iter().next().unwrap();
                            let nested = parts
                                .iter()
                                .any(|&id| !matches!(tree.nodes[id], Node::Atom(_)));
                            let sequence_shaped = parts.windows(3).any(|window| {
                                window[..2].iter().all(|&id| {
                                    matches!(&tree.nodes[id], Node::Atom(seg) if character(seg) == Some('.'))
                                })
                            });
                            if nested && sequence_shaped {
                                // Bash selects this outer group as a sequence, then checks
                                // for commas anywhere in its body. A nested comma makes it
                                // a list; without one, the failed sequence stays wholly literal.
                                if atoms[open + 1..i]
                                    .iter()
                                    .any(|seg| character(seg) == Some(','))
                                {
                                    tree.add(Node::Concat(parts))
                                } else {
                                    let literal_parts = atoms[open..=i]
                                        .iter()
                                        .map(|seg| tree.add(Node::Atom(seg.clone())))
                                        .collect();
                                    tree.add(Node::Concat(literal_parts))
                                }
                            } else {
                                parts.insert(0, tree.add(Node::Atom(literal("{"))));
                                parts.push(tree.add(Node::Atom(literal("}"))));
                                tree.add(Node::Concat(parts))
                            }
                        }
                    }
                }
            }
            _ => tree.add(Node::Atom(atom.clone())),
        };
        frames.last_mut().unwrap().1.last_mut().unwrap().push(node);
    }
    let root = tree.add(Node::Concat(frames.pop().unwrap().1.pop().unwrap()));
    let produced = tree.sizes[root];
    if produced > cap {
        return BraceExpansion::Overflow { produced };
    }

    let mut words = Vec::with_capacity(produced);
    let mut work = vec![(vec![root], Vec::<Seg>::new())];
    while let Some((mut pending, mut segs)) = work.pop() {
        while let Some(id) = pending.pop() {
            match &tree.nodes[id] {
                Node::Atom(seg) => segs.push(seg.clone()),
                Node::Concat(parts) => pending.extend(parts.iter().rev()),
                Node::List(parts) => {
                    for &part in parts.iter().skip(1).rev() {
                        let mut branch = pending.clone();
                        branch.push(part);
                        work.push((branch, segs.clone()));
                    }
                    pending.push(parts[0]);
                }
                Node::Sequence {
                    start,
                    step,
                    width,
                    letters,
                } => {
                    let value = |index: usize| {
                        let value = start + step * index as i128;
                        // Bash retains an empty quoted word for the backslash in a letter range.
                        if *letters && value == i128::from(b'\\') {
                            return Seg::Literal {
                                text: String::new(),
                                quoted: true,
                            };
                        }
                        literal(if *letters {
                            (value as u8 as char).to_string()
                        } else {
                            format!("{value:0width$}")
                        })
                    };
                    for index in (1..tree.sizes[id]).rev() {
                        let mut branch = segs.clone();
                        branch.push(value(index));
                        work.push((pending.clone(), branch));
                    }
                    segs.push(value(0));
                }
            }
        }
        let mut merged = Vec::new();
        for seg in segs {
            match (merged.last_mut(), seg) {
                (
                    Some(Seg::Literal { text, quoted }),
                    Seg::Literal {
                        text: next,
                        quoted: next_quoted,
                    },
                ) if *quoted == next_quoted => text.push_str(&next),
                (_, seg) => merged.push(seg),
            }
        }
        words.push(WordTok {
            segs: merged,
            span: tok.span,
        });
    }
    BraceExpansion::Words(words)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::lex::{Tok, lex};

    fn token(source: &str) -> WordTok {
        let output = lex(source);
        assert!(output.error.is_none());
        let [Tok::Word(tok)] = output.toks.as_slice() else {
            panic!("{source}")
        };
        tok.clone()
    }

    #[test]
    fn brace_grammar_and_cap() {
        for (source, expected) in [
            ("x{a,b}", vec!["xa", "xb"]),
            ("{a,{b,c}}", vec!["a", "b", "c"]),
            ("{a,b}{c,d}", vec!["ac", "ad", "bc", "bd"]),
            ("/{,}", vec!["/", "/"]),
            ("{1..3}", vec!["1", "2", "3"]),
            ("{5..1..-2}", vec!["5", "3", "1"]),
            ("{01..03}", vec!["01", "02", "03"]),
            ("{-02..1}", vec!["-02", "-01", "000", "001"]),
            ("{a..e..2}", vec!["a", "c", "e"]),
            ("{c..a..0}", vec!["c", "b", "a"]),
            ("{Z..a}", vec!["Z", "[", "", "]", "^", "_", "`", "a"]),
            ("{!..#}", vec!["{!..#}"]),
            ("{a}", vec!["{a}"]),
            ("{a,b", vec!["{a,b"]),
            ("{1.5..3}", vec!["{1.5..3}"]),
            ("'{a,b}'", vec!["{a,b}"]),
            (r"\{a,b\}", vec!["{a,b}"]),
            ("{1..'3'}", vec!["{1..3}"]),
            ("{{a,b}}", vec!["{a}", "{b}"]),
            ("{{etc,var}..bak}", vec!["etc..bak", "var..bak"]),
            ("{{1..3}..old}", vec!["{{1..3}..old}"]),
            ("{{1,2}..3}", vec!["1..3", "2..3"]),
            ("{{a,b}..{c,d}}", vec!["a..c", "a..d", "b..c", "b..d"]),
            ("{{1..2}..3}", vec!["{{1..2}..3}"]),
            ("{{a,b}..3}", vec!["a..3", "b..3"]),
            ("{x{1,2}y..z}", vec!["x1y..z", "x2y..z"]),
            ("{{a,b}..{1..2}}", vec!["a..1", "a..2", "b..1", "b..2"]),
            ("{{1..2}..{a,b}}", vec!["1..a", "1..b", "2..a", "2..b"]),
            ("{{1..2}..3}{x,y}", vec!["{{1..2}..3}x", "{{1..2}..3}y"]),
            ("{{1..100000}..old}", vec!["{{1..100000}..old}"]),
            ("{{a,b}..}", vec!["{a..}", "{b..}"]),
            ("{{a,b}..x..y..z}", vec!["a..x..y..z", "b..x..y..z"]),
        ] {
            let tok = token(source);
            let BraceExpansion::Words(words) = expand(&tok, 256) else {
                panic!("{source}")
            };
            let actual: Vec<String> = words
                .iter()
                .map(|word| {
                    assert_eq!(word.span, tok.span);
                    word.segs
                        .iter()
                        .map(|seg| match seg {
                            Seg::Literal { text, .. } => text.as_str(),
                            _ => panic!("{source}"),
                        })
                        .collect()
                })
                .collect();
            assert_eq!(actual, expected, "{source}");
        }
        let tok = token("{$X,var}");
        let BraceExpansion::Words(words) = expand(&tok, 256) else {
            panic!()
        };
        assert!(
            matches!(words[0].segs.as_slice(), [Seg::Env { name, quoted: false }] if name == "X")
        );
        for source in ["{1..$N}", "{$A..$B}", "{1..$(n)}"] {
            assert!(matches!(
                expand(&token(source), 256),
                BraceExpansion::Unsupported(_)
            ));
        }
        for (source, produced) in [
            ("{1..100000}".to_string(), 100000),
            ("{a,b}".repeat(20), 1 << 20),
            ("{1..16}{1..17}".to_string(), 272),
        ] {
            assert!(
                matches!(expand(&token(&source), 256), BraceExpansion::Overflow { produced: n } if n == produced)
            );
        }
        assert!(
            matches!(expand(&token("{1..256}"), 256), BraceExpansion::Words(words) if words.len() == 256)
        );
    }
}
