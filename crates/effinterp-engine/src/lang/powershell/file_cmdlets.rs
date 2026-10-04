//! PowerShell cmdlets whose whole effect is one filesystem access to each
//! path they bind (`Get-Content`, `Set-Content`, `Out-File`), and `New-Item`.

use effinterp_proto::ProvenanceRef;

use crate::builder::PlanBuilder;
use crate::nest::Nest;
use crate::resource_transfer::TransferBinding;

use super::cmdlet_parameters::{FileCmdlet, NEW_ITEM, bind_cmdlet_parameters};
use super::path_resolution::{binds_single_path, filesystem_effect, resolved_path};
use super::powershell_boundary;
use super::ps_words::PsWord;

/// A cmdlet whose whole effect is one access to each path it binds, and the
/// effect slots it recorded. An `assigned` Get-Content stores the content in
/// a variable rather than writing it to the output.
pub(super) fn file_cmdlet(
    builder: &mut PlanBuilder,
    nest: &Nest,
    arguments: &[PsWord],
    location: Option<&str>,
    node: ProvenanceRef,
    file: &FileCmdlet,
    assigned: bool,
) -> (bool, Vec<u32>) {
    let cmdlet = &file.cmdlet;
    let bound = match bind_cmdlet_parameters(arguments, cmdlet) {
        Ok(bound) => bound,
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return (false, Vec::new());
        }
    };
    let path_parameter = cmdlet.positions[0];
    let (paths, wildcards) = match bound.paths(path_parameter) {
        Ok(Some(paths)) => paths,
        Ok(None) => {
            powershell_boundary(
                builder,
                node,
                &format!("PowerShell {} has no literal path", cmdlet.name),
            );
            return (false, Vec::new());
        }
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return (false, Vec::new());
        }
    };
    if bound.switch("WhatIf") {
        return (bound.complete(builder, node, cmdlet.name), Vec::new());
    }
    let mut complete =
        bound.complete(builder, node, cmdlet.name) & binds_single_path(builder, node, paths);
    let mut attributes = crate::models::common::Attrs::new();
    if cmdlet.name.eq_ignore_ascii_case("Add-Content") || bound.switch("Append") {
        attributes.insert("append".into(), effinterp_proto::AttrValue::Bool(true));
    }
    // Get-Content writes the file's contents to its output.
    if file.operation == "filesystem.read" && !assigned {
        attributes.extend(crate::models::common::program_output_attrs());
    }
    // Out-File's -FilePath names one file; it does not expand wildcards.
    let wildcards = wildcards && path_parameter == "Path";
    let mut slots = Vec::new();
    for path in paths {
        let Some(resource) =
            resolved_path(builder, nest, path, wildcards, location, node, cmdlet.name)
        else {
            complete = false;
            continue;
        };
        slots.extend(filesystem_effect(
            builder,
            file.operation,
            resource,
            attributes.clone(),
            node,
            file.model,
        ));
    }
    (complete, slots)
}

/// `New-Item -ItemType HardLink` gives the target's file a second name, so
/// writing through the created entry changes the target.
pub(super) fn new_item(
    builder: &mut PlanBuilder,
    nest: &Nest,
    arguments: &[PsWord],
    location: Option<&str>,
    node: ProvenanceRef,
) -> bool {
    let bound = match bind_cmdlet_parameters(arguments, &NEW_ITEM) {
        Ok(bound) => bound,
        Err(detail) => {
            powershell_boundary(builder, node, detail);
            return false;
        }
    };
    let hard_link =
        matches!(bound.value("ItemType"), Ok(Some(kind)) if kind.eq_ignore_ascii_case("HardLink"));
    // -Target is an alias of -Value.
    let target = match (bound.value("Target"), bound.value("Value")) {
        (Ok(Some(target)), Ok(None)) | (Ok(None), Ok(Some(target))) => Some(target),
        _ => None,
    };
    let (Some(target), Ok(Some(link)), true) = (target, bound.value("Path"), hard_link) else {
        powershell_boundary(
            builder,
            node,
            "PowerShell New-Item is outside the modeled hard-link grammar",
        );
        return false;
    };
    if bound.switch("WhatIf") {
        return bound.complete(builder, node, "New-Item");
    }
    let complete = bound.complete(builder, node, "New-Item");
    let (Some(target), Some(link)) = (
        resolved_path(builder, nest, target, false, location, node, "New-Item"),
        resolved_path(builder, nest, link, false, location, node, "New-Item"),
    ) else {
        return false;
    };
    let source = filesystem_effect(
        builder,
        "filesystem.read",
        target,
        [("metadata".into(), effinterp_proto::AttrValue::Bool(true))].into(),
        node,
        "powershell/new-item-hardlink@v1",
    );
    let created = filesystem_effect(
        builder,
        "filesystem.create",
        link,
        [("symlink".into(), effinterp_proto::AttrValue::Bool(false))].into(),
        node,
        "powershell/new-item-hardlink@v1",
    );
    if let (Some(source), Some(created)) = (source, created) {
        builder.transfer_binding(TransferBinding::exact(source, created));
    }
    complete
}
