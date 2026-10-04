//! PowerShell cmdlet parameter binding: the parameter table of each modeled
//! cmdlet, and how one invocation's arguments bind to it.

use effinterp_proto::ProvenanceRef;

use crate::builder::PlanBuilder;

use super::powershell_boundary;
use super::ps_words::PsWord;

/// The declared parameter a written `-Name` resolves to.
enum Parameter {
    Switch(&'static str),
    Valued(&'static str),
}

/// One cmdlet's parameters: its switches, its value parameters, and the value
/// parameters its positional arguments bind, in position order.
pub(super) struct Cmdlet {
    pub(super) name: &'static str,
    switches: &'static [&'static str],
    values: &'static [&'static str],
    pub(super) positions: &'static [&'static str],
}

/// A cmdlet whose whole effect is one filesystem access to each path it
/// binds. Its first position names that path.
pub(super) struct FileCmdlet {
    pub(super) cmdlet: Cmdlet,
    pub(super) operation: &'static str,
    pub(super) model: &'static str,
}

/// The common parameters every cmdlet binds (about_CommonParameters), with
/// the risk-mitigation switches.
const COMMON_SWITCHES: &[&str] = &["WhatIf", "Confirm", "Verbose", "Debug"];
const COMMON_VALUES: &[&str] = &[
    "ErrorAction",
    "WarningAction",
    "InformationAction",
    "ProgressAction",
    "ErrorVariable",
    "WarningVariable",
    "InformationVariable",
    "OutVariable",
    "OutBuffer",
    "PipelineVariable",
];

const ITEM_PATHS: &[&str] = &[
    "Path",
    "LiteralPath",
    "Filter",
    "Include",
    "Exclude",
    "Stream",
    "Credential",
];

pub(super) const REMOVE_ITEM: Cmdlet = Cmdlet {
    name: "Remove-Item",
    switches: &["Recurse", "Force"],
    values: ITEM_PATHS,
    positions: &["Path"],
};

const CONTENT_VALUES: &[&str] = &[
    "Path",
    "LiteralPath",
    "Value",
    "Encoding",
    "Filter",
    "Include",
    "Exclude",
    "Stream",
    "Credential",
];

pub(super) const FILE_CMDLETS: &[FileCmdlet] = &[
    FileCmdlet {
        cmdlet: Cmdlet {
            name: "Clear-Content",
            switches: &["Force", "NoNewline"],
            values: ITEM_PATHS,
            positions: &["Path"],
        },
        operation: "filesystem.write",
        model: "powershell/clear-content@v1",
    },
    FileCmdlet {
        cmdlet: Cmdlet {
            name: "Set-Content",
            switches: &["Force", "NoNewline", "PassThru", "AsByteStream"],
            values: CONTENT_VALUES,
            positions: &["Path", "Value"],
        },
        operation: "filesystem.write",
        model: "powershell/set-content@v1",
    },
    FileCmdlet {
        cmdlet: Cmdlet {
            name: "Add-Content",
            switches: &["Force", "NoNewline", "PassThru", "AsByteStream"],
            values: CONTENT_VALUES,
            positions: &["Path", "Value"],
        },
        operation: "filesystem.write",
        model: "powershell/add-content@v1",
    },
    FileCmdlet {
        cmdlet: Cmdlet {
            name: "Get-Content",
            switches: &["Force", "Raw", "Wait", "AsByteStream"],
            values: &[
                "Path",
                "LiteralPath",
                "ReadCount",
                "TotalCount",
                "Tail",
                "Delimiter",
                "Encoding",
                "Filter",
                "Include",
                "Exclude",
                "Stream",
                "Credential",
            ],
            positions: &["Path"],
        },
        operation: "filesystem.read",
        model: "powershell/get-content@v1",
    },
    FileCmdlet {
        cmdlet: Cmdlet {
            name: "Out-File",
            switches: &["Append", "Force", "NoClobber", "NoNewline"],
            values: &[
                "FilePath",
                "LiteralPath",
                "Encoding",
                "Width",
                "InputObject",
            ],
            positions: &["FilePath", "Encoding"],
        },
        operation: "filesystem.write",
        model: "powershell/out-file@v1",
    },
];

pub(super) const COPY_ITEM: Cmdlet = Cmdlet {
    name: "Copy-Item",
    switches: &["Container", "Force", "PassThru", "Recurse"],
    values: &[
        "Path",
        "LiteralPath",
        "Destination",
        "Filter",
        "Include",
        "Exclude",
        "Credential",
    ],
    positions: &["Path", "Destination"],
};

pub(super) const MOVE_ITEM: Cmdlet = Cmdlet {
    name: "Move-Item",
    switches: &["Force", "PassThru"],
    values: &[
        "Path",
        "LiteralPath",
        "Destination",
        "Filter",
        "Include",
        "Exclude",
        "Credential",
    ],
    positions: &["Path", "Destination"],
};

pub(super) const RENAME_ITEM: Cmdlet = Cmdlet {
    name: "Rename-Item",
    switches: &["Force", "PassThru"],
    values: &["Path", "LiteralPath", "NewName", "Credential"],
    positions: &["Path", "NewName"],
};

pub(super) const NEW_ITEM: Cmdlet = Cmdlet {
    name: "New-Item",
    switches: &["Force"],
    values: &["Path", "ItemType", "Value", "Target", "Credential"],
    positions: &["Path"],
};

pub(super) const WEB_REQUEST: Cmdlet = Cmdlet {
    name: "Invoke-WebRequest",
    switches: &["UseBasicParsing", "PassThru"],
    values: &["Uri", "OutFile", "Method", "Body", "InFile"],
    positions: &["Uri"],
};

pub(super) const WRITE_OUTPUT: Cmdlet = Cmdlet {
    name: "Write-Output",
    switches: &["NoEnumerate"],
    values: &["InputObject"],
    positions: &["InputObject"],
};

pub(super) const WRITE_HOST: Cmdlet = Cmdlet {
    name: "Write-Host",
    switches: &["NoNewline"],
    values: &["Object", "Separator", "ForegroundColor", "BackgroundColor"],
    positions: &["Object"],
};

pub(super) const SET_LOCATION: Cmdlet = Cmdlet {
    name: "Set-Location",
    switches: &["PassThru"],
    values: &["Path", "LiteralPath", "StackName"],
    positions: &["Path"],
};

pub(super) const START_PROCESS: Cmdlet = Cmdlet {
    name: "Start-Process",
    switches: &["Wait", "NoNewWindow", "PassThru"],
    values: &["FilePath", "ArgumentList"],
    positions: &["FilePath", "ArgumentList"],
};

pub(super) const SET_ALIAS: Cmdlet = Cmdlet {
    name: "Set-Alias",
    switches: &["Force", "PassThru"],
    values: &["Name", "Value", "Description", "Option", "Scope"],
    positions: &["Name", "Value"],
};

/// The parameters one invocation bound.
#[derive(Default)]
pub(super) struct PsBoundParameters {
    switches: Vec<(&'static str, bool)>,
    values: Vec<(&'static str, Vec<String>)>,
    /// The argument word each value parameter bound, where its value is a
    /// word of its own rather than attached as `-Name:value`.
    words: Vec<(&'static str, usize)>,
    /// Positional arguments no positional parameter was left to bind.
    pub(super) unbound: usize,
}

impl PsBoundParameters {
    /// Whether the invocation bound the parameter `name`, as a switch or a value.
    pub(super) fn bound(&self, name: &str) -> bool {
        self.switches.iter().any(|(bound, _)| *bound == name)
            || self.values.iter().any(|(bound, _)| *bound == name)
    }

    /// Whether the switch `name` is on: bound, and not written `-Name:$false`.
    pub(super) fn switch(&self, name: &str) -> bool {
        self.switches
            .iter()
            .any(|(bound, value)| *bound == name && *value)
    }

    /// The index of the argument word that the value parameter `name` bound.
    pub(super) fn word(&self, name: &str) -> Option<usize> {
        self.words
            .iter()
            .find(|(bound, _)| *bound == name)
            .map(|(_, index)| *index)
    }

    /// Every value the parameter `name` bound: one, or a comma collection.
    pub(super) fn values(&self, name: &str) -> Option<&[String]> {
        self.values
            .iter()
            .find(|(bound, _)| *bound == name)
            .map(|(_, values)| values.as_slice())
    }

    /// The single value the parameter `name` bound. A collection is an error.
    pub(super) fn value(&self, name: &str) -> Result<Option<&str>, &'static str> {
        match self.values(name) {
            None => Ok(None),
            Some([value]) => Ok(Some(value)),
            Some(_) => Err("PowerShell parameter binds a collection"),
        }
    }

    /// The paths the wildcard path parameter or `-LiteralPath` binds, and
    /// whether they expand wildcards. The two belong to different parameter
    /// sets, so binding both is an error PowerShell raises before running.
    pub(super) fn paths(&self, parameter: &str) -> Result<Option<(&[String], bool)>, &'static str> {
        match (self.values(parameter), self.values("LiteralPath")) {
            (Some(_), Some(_)) => Err("PowerShell binds a path and a literal path"),
            (Some(paths), None) => Ok(Some((paths, true))),
            (None, Some(paths)) => Ok(Some((paths, false))),
            (None, None) => Ok(None),
        }
    }

    /// Raise the boundary for positional arguments nothing bound, and return
    /// whether there were none.
    pub(super) fn complete(
        &self,
        builder: &mut PlanBuilder,
        node: ProvenanceRef,
        command: &str,
    ) -> bool {
        if self.unbound > 0 {
            powershell_boundary(
                builder,
                node,
                &format!("PowerShell {command} has an unbound operand"),
            );
            return false;
        }
        true
    }
}

/// Bind one cmdlet's arguments as PowerShell does: named parameters first,
/// including `-Name:value` with the value attached, then positional arguments
/// in position order. An argument that fails to bind stops the cmdlet from
/// running, so it is an error rather than a partial binding.
pub(super) fn bind_cmdlet_parameters(
    arguments: &[PsWord],
    cmdlet: &Cmdlet,
) -> Result<PsBoundParameters, &'static str> {
    let mut bound = PsBoundParameters::default();
    let mut positional = Vec::new();
    let mut arguments = arguments.iter().enumerate();
    while let Some((index, argument)) = arguments.next() {
        let name = match argument.text.strip_prefix('-') {
            Some(name)
                if !name.is_empty()
                    && (!argument.quoted || !argument.leading_quote && name.contains(':')) =>
            {
                name
            }
            _ => {
                positional.push((index, argument));
                continue;
            }
        };
        let (name, attached) = match name.split_once(':') {
            Some((name, value)) => (name, Some(value)),
            None => (name, None),
        };
        match parameter(name, cmdlet)? {
            Parameter::Switch(name) => {
                let value = match attached {
                    None => true,
                    // `-Name:'$true'` passes a string, which PowerShell
                    // refuses to bind to a switch.
                    Some(_) if argument.quoted => {
                        return Err("PowerShell switch value is not a literal boolean");
                    }
                    Some(value) if value.eq_ignore_ascii_case("$true") => true,
                    Some(value) if value.eq_ignore_ascii_case("$false") => false,
                    Some(_) => return Err("PowerShell switch value is not a literal boolean"),
                };
                if bound.bound(name) {
                    return Err("PowerShell parameter is bound more than once");
                }
                bound.switches.push((name, value));
            }
            Parameter::Valued(name) => {
                let values = match attached {
                    Some(value) if !value.is_empty() => vec![value.to_string()],
                    _ => {
                        let (index, value) = arguments
                            .next()
                            .ok_or("PowerShell parameter has no value")?;
                        bound.words.push((name, index));
                        value.values()
                    }
                };
                if bound.bound(name) {
                    return Err("PowerShell parameter is bound more than once");
                }
                bound.values.push((name, values));
            }
        }
    }
    let positions = cmdlet
        .positions
        .iter()
        .copied()
        // -LiteralPath takes the place of the wildcard path parameter in its
        // own parameter set, so no positional argument binds that one.
        .filter(|name| {
            !(bound.bound(name)
                || bound.bound("LiteralPath") && matches!(*name, "Path" | "FilePath"))
        })
        .collect::<Vec<_>>();
    for (position, (index, argument)) in positional.into_iter().enumerate() {
        match positions.get(position) {
            Some(name) => {
                bound.values.push((name, argument.values()));
                bound.words.push((name, index));
            }
            None => bound.unbound += 1,
        }
    }
    Ok(bound)
}

/// The parameter a written name binds. PowerShell accepts any prefix that
/// names exactly one of the cmdlet's parameters.
fn parameter(name: &str, cmdlet: &Cmdlet) -> Result<Parameter, &'static str> {
    let candidates = cmdlet
        .switches
        .iter()
        .chain(COMMON_SWITCHES)
        .map(|candidate| (true, *candidate))
        .chain(
            cmdlet
                .values
                .iter()
                .chain(COMMON_VALUES)
                .map(|candidate| (false, *candidate)),
        );
    let parameter = |(switch, candidate): (bool, &'static str)| {
        if switch {
            Parameter::Switch(candidate)
        } else {
            Parameter::Valued(candidate)
        }
    };
    if let Some(exact) = candidates
        .clone()
        .find(|(_, candidate)| candidate.eq_ignore_ascii_case(name))
    {
        return Ok(parameter(exact));
    }
    let mut prefixed = candidates.filter(|(_, candidate)| {
        candidate.len() > name.len() && candidate[..name.len()].eq_ignore_ascii_case(name)
    });
    match (prefixed.next(), prefixed.next()) {
        (Some(candidate), None) => Ok(parameter(candidate)),
        (Some(_), Some(_)) => Err("PowerShell parameter name is ambiguous"),
        _ => Err("PowerShell parameter name is unknown"),
    }
}
