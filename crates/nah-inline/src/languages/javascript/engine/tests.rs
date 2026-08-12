use super::*;

fn analysis_for(program: &str, code: &str) -> LanguageAnalysis {
    let profile = super::super::profile(program).unwrap();
    interpret(
        profile,
        &InlineInput {
            program,
            code,
            home: "/home/dev",
            platform: Platform::Linux,
        },
        0,
    )
}

fn analysis(code: &str) -> LanguageAnalysis {
    analysis_for("node", code)
}

fn report(code: &str) -> InlineReport {
    analysis(code).into_report()
}

fn requested_for(program: &str, code: &str, target: &str) -> bool {
    analysis_for(program, code)
        .draft()
        .calls()
        .iter()
        .any(|call| {
            call.filesystems()
                .iter()
                .any(|filesystem| filesystem.requested() == Some(target))
        })
}

fn root_for(program: &str, code: &str) -> bool {
    requested_for(program, code, "/")
}

fn root(code: &str) -> bool {
    root_for("node", code)
}

fn assert_inert(code: &str) {
    let analysis = analysis(code);
    assert_eq!(analysis.report(), &InlineReport::default(), "{code}");
    assert!(analysis.draft().calls().is_empty(), "{code}");
}

#[test]
fn require_imports_and_exact_values_reach_owned_sinks() {
    assert!(root(
        "const fs=require('fs'); const target=`${'/'}`; fs.rmSync(target, {recursive:true})"
    ));
    assert!(root(
        "import * as files from 'node:fs'; files.rmSync('/', {recursive:true})"
    ));
    assert!(root(
        "import {rmSync as remove} from 'fs'; remove('/', {recursive:true})"
    ));
    assert!(root(
        "const files=require('fs'); eval(\"files.rmSync('/', {recursive:true})\")"
    ));
    assert_eq!(
        report("const {spawn}=require('child_process'); spawn('nah', ['nap'])").nested_executions(),
        [crate::NestedExecution::Command {
            argv: vec!["nah".into(), "nap".into()],
            cwd: crate::NestedExecutionCwd::Inherited,
            stdout_inherited: false,
        }]
    );
}

#[test]
fn dormant_code_getters_builders_and_dynamic_construction_are_inert() {
    let dangerous = "require('child_process').execSync('rm -rf /')";
    for code in [
        format!("function dormant(){{{dangerous}}}"),
        format!("setTimeout(()=>{dangerous}, 0)"),
        format!("const value={{get danger(){{{dangerous}}}}}"),
        format!("builder({dangerous:?})"),
        format!("new Function({dangerous:?})"),
    ] {
        assert_inert(&code);
    }
    assert_eq!(
        report(&format!("new Function({dangerous:?})()"))
            .nested_executions()
            .len(),
        1
    );
}

#[test]
fn lexical_shadowing_and_branch_local_ownership_do_not_escape() {
    for code in [
        "{ const require=safe; require('fs').rmSync('/', {recursive:true}) }",
        "if (true) { const fs=require('fs'); } fs.rmSync('/', {recursive:true})",
        "function safe(require) { require('fs').rmSync('/', {recursive:true}) } safe(other)",
        "try { throw 1 } catch (require) { require('fs').rmSync('/', {recursive:true}) }",
        "const fs=require('fs'); function make(){const fs=safe; return ()=>fs.rmSync('/', {recursive:true})} make()()",
    ] {
        assert_inert(code);
    }
}

#[test]
fn monkey_patches_and_unknown_module_consumers_remove_ownership() {
    for code in [
        "const fs=require('fs'); fs.rmSync=safe; fs.rmSync('/', {recursive:true})",
        "require('fs').rmSync=safe; require('fs').rmSync('/', {recursive:true})",
        "const cp=require('child_process'); Object.defineProperty(cp, 'exec', {value:safe}); cp.exec('rm -rf /')",
        "const fs=require('fs'); plugin(fs); fs.rmSync('/', {recursive:true})",
        "const fs=require('fs'); if (flag) { fs.rmSync=safe } fs.rmSync('/', {recursive:true})",
        "const fs=require('fs'); switch (flag) { default: break } fs.rmSync('/', {recursive:true})",
        "const options={recursive:true}; options.recursive=false; require('fs').rmSync('/', options)",
        "const options={recursive:true}; const alias=options; alias.recursive=false; require('fs').rmSync('/', options)",
        "const options={recursive:true}; Object.defineProperty(options, 'recursive', {value:false}); require('fs').rmSync('/', options)",
        "const options={constructor:require('module'),recursive:true}; options.recursive=false; require('fs').rmSync('/', options)",
        "process.env.HOME='/tmp/safe'; require('fs').rmSync(process.env.HOME, {recursive:true})",
        "const env=process.env; env.HOME='/tmp/safe'; require('fs').rmSync(process.env.HOME, {recursive:true})",
        "eval('require=safe'); require('fs').rmSync('/', {recursive:true})",
        "eval(\"require('fs').rmSync=safe\"); require('fs').rmSync('/', {recursive:true})",
    ] {
        assert!(!root(code), "{code}");
    }
    assert!(
        report(
            "const args=['-rf','/']; args.push('safe'); require('child_process').spawn('rm', args)"
        )
        .nested_executions()
        .is_empty()
    );
}

#[test]
fn direct_node_module_loader_changes_remove_module_ownership() {
    for code in [
        "require('module')._load=safe; require('fs').rmSync('/', {recursive:true})",
        "const Module=require('module'); Module._load=safe; require('fs').rmSync('/', {recursive:true})",
        "const Module=require('node:module'); delete Module.createRequire; require('fs').rmSync('/', {recursive:true})",
        "const Module=require('module'); plugin(Module._load); require('fs').rmSync('/', {recursive:true})",
        "const Module=require('module'); sink.loader=Module._load; require('fs').rmSync('/', {recursive:true})",
        "const Module=require('node:module'); Module.createRequire('/tmp/plugin.js'); require('fs').rmSync('/', {recursive:true})",
        "const Module=require('node:module'); Module.isBuiltin=undefined; Module.isBuiltin('fs'); require('fs').rmSync('/', {recursive:true})",
        "const Module=require('node:module').Module; Module._load=safe; require('fs').rmSync('/', {recursive:true})",
        "const Module=module.constructor; Module._load=safe; require('fs').rmSync('/', {recursive:true})",
        "require('module').prototype.constructor._load=safe; require('fs').rmSync('/', {recursive:true})",
        "module.require=safe; require('fs').rmSync('/', {recursive:true})",
        "Object.defineProperty(module, 'require', {value:safe}); require('fs').rmSync('/', {recursive:true})",
        "require('module').prototype.require=safe; require('fs').rmSync('/', {recursive:true})",
        "Object.defineProperty(require('module').prototype, 'require', {value:safe}); require('fs').rmSync('/', {recursive:true})",
        "const box=[require('module')]; box[0]._load=safe; require('fs').rmSync('/', {recursive:true})",
        "const Module=require('module'); sink.loader=[Module._load]; require('fs').rmSync('/', {recursive:true})",
    ] {
        assert!(!root(code), "{code}");
    }
    assert!(
        report("const Module=require('module'); Module._load('fs'); require('child_process').spawn('rm', ['-rf', '/'])")
            .nested_executions()
            .is_empty()
    );
}

#[test]
fn rebound_node_properties_do_not_reuse_stale_provenance() {
    for code in [
        "const {rmSync}=require('fs'); const M=require('module'); M._load=undefined; M._load('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); M.isBuiltin=undefined; M.isBuiltin('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); module.require=undefined; module.require('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); M.Module=undefined; M.Module.isBuiltin('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); Object.defineProperty(module,'constructor',{value:undefined}); module.constructor.isBuiltin('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',null); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{set(value){}}); M._load('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{get:undefined}); M._load('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); delete M._load; M._load('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); delete M.isBuiltin; M.isBuiltin('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); delete M.Module; M.Module.isBuiltin('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); M._load+=1; M._load('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{get:()=>undefined}); M._load('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); M.prototype.require=undefined; module.require('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M.prototype,'require',{value:undefined}); module.require('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); delete M.prototype.require; module.require('fs'); rmSync('/',{recursive:true})",
        "const M=require('module'); M._load('fs').rmSync=()=>{}; M._load('fs').rmSync('/',{recursive:true})",
        "const M=require('module'),fs=M._load('fs'); require('fs').rmSync=()=>{}; fs.rmSync('/',{recursive:true})",
        "const M=require('module'); M._load-={}; M._load('fs').rmSync('/',{recursive:true})",
        "const M=require('module'); M._load+=process.env.TAG; M._load('fs').rmSync('/',{recursive:true})",
    ] {
        assert!(analysis(code).draft().calls().is_empty(), "{code}");
    }
}

#[test]
fn node_property_barriers_preserve_reachable_tail_effects() {
    for code in [
        "const {rmSync}=require('fs'); module.constructor=undefined; module.constructor._load('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); delete M._load; M._load('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{writable:false}); M._load=undefined; M._load('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const F=require('module').constructor; F.isBuiltin=()=>true; F.isBuiltin('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); M.constructor=undefined; delete M.constructor; M.constructor(''); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); M._load+=1; M._load.toString(); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); try { M._load+=null.x } catch {} M._load('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{configurable:false})._load('fs'); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'),M=require('module'); plugin(M); M._load=undefined; M._load('fs'); rmSync('/',{recursive:true})",
        "const M=require('module'); module.constructor=M._load; require('fs').rmSync('/',{recursive:true})",
    ] {
        assert!(root(code), "{code}");
    }
}

#[test]
fn node_descriptor_flags_keep_exact_loader_ownership() {
    for code in [
        "const M=require('module'); Object.defineProperty(M,'_load',{writable:false}); M._load=safe; require('fs').rmSync('/',{recursive:true})",
        "const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); delete M._load; require('fs').rmSync('/',{recursive:true})",
        "const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); Object.defineProperty(M,'_load',{enumerable:true}); require('fs').rmSync('/',{recursive:true})",
        "const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); Object.defineProperty(M,'_load',{value:M._load}); require('fs').rmSync('/',{recursive:true})",
    ] {
        assert!(root(code), "{code}");
    }
    for code in [
        "const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); M._load=safe; require('fs').rmSync('/',{recursive:true})",
        "const M=require('module'); Object.defineProperty(M,'_load',{writable:false}); delete M._load; require('fs').rmSync('/',{recursive:true})",
        "const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); Object.defineProperty(M,'_load',{enumerable:false}); require('fs').rmSync('/',{recursive:true})",
        "const M=require('module'); Object.defineProperty(M,'_load',{configurable:false}); Object.defineProperty(M,'_load',{get(){return M._load}}); require('fs').rmSync('/',{recursive:true})",
    ] {
        assert!(!root(code), "{code}");
    }
}

#[test]
fn invalid_property_descriptors_stop_before_tail() {
    for code in [
        "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{value:safe,get(){}}); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{get:1}); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M,'_load',{set:'x'}); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); const M=require('module'); Object.defineProperty(M.prototype,'constructor',{value:undefined}); rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'),M=require('module'); Object.defineProperty(M,'_load',{get(){return ()=>{}},set(value){},configurable:false}); Object.defineProperty(M,'_load',{value:undefined}); rmSync('/',{recursive:true})",
    ] {
        assert!(!root(code), "{code}");
    }
}

#[test]
fn javascript_runtime_order_preserves_reachable_loader_effects() {
    for code in [
        "const M=require('module'); M._load ||= null.x; M._load('fs').rmSync('/',{recursive:true})",
        "const M=require('module'); M._load ??= null.x; M._load('fs').rmSync('/',{recursive:true})",
        "const M=require('module'); try{M._load-={valueOf(){throw 1}}}catch{} M._load('fs').rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'); Object.defineProperty({},'x',{get get(){return ()=>1}}); rmSync('/',{recursive:true})",
        "const M=require('module');const d={get value(){return M._load}};Object.defineProperty(M,'_load',d);M._load('fs').rmSync('/',{recursive:true})",
        "Object.defineProperty({},'x',{get value(){require('fs').rmSync('/',{recursive:true});return 1}})",
    ] {
        assert!(root(code), "{code}");
    }
}

#[test]
fn strict_writes_deletes_and_invalid_targets_stop_unreachable_tails() {
    for code in [
        "Object.defineProperty(null,'x',{}); require('fs').rmSync('/',{recursive:true})",
        "Object.defineProperty(1,'x',{}); require('fs').rmSync('/',{recursive:true})",
        "'use strict'; const M=require('module');Object.defineProperty(M,'_load',{writable:false});M._load=undefined;require('fs').rmSync('/',{recursive:true})",
        "'use strict';module.constructor=undefined;require('fs').rmSync('/',{recursive:true})",
        "function f(){'use strict';module.constructor=undefined}f();require('fs').rmSync('/',{recursive:true})",
        "export {};const M=require('module');Object.defineProperty(M,'_load',{writable:false});M._load=undefined;require('fs').rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'),M=require('module');if(delete M.prototype)rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'),M=require('module');Object.defineProperty(M,'_load',{configurable:false});if(delete M._load)rmSync('/',{recursive:true})",
        "'use strict';const {rmSync}=require('fs'),M=require('module');delete M.prototype;rmSync('/',{recursive:true})",
        "'use strict';const {rmSync}=require('fs'),M=require('module');Object.defineProperty(M,'_load',{writable:false});[M._load]=[undefined];rmSync('/',{recursive:true})",
    ] {
        assert!(!root(code), "{code}");
    }
    for code in [
        "'\\x75se strict';module.constructor=undefined;require('fs').rmSync('/',{recursive:true})",
        "const M=require('module');Object.defineProperty(M,'_load',{writable:false});M._load=undefined;require('fs').rmSync('/',{recursive:true})",
        "const {rmSync}=require('fs'),M=require('module');delete M.prototype;rmSync('/',{recursive:true})",
    ] {
        assert!(root(code), "{code}");
    }
}

#[test]
fn aliased_node_module_loader_changes_remove_module_ownership() {
    for code in [
        "const Module=require('module'); const alias=Module; alias._load=safe; require('fs').rmSync('/', {recursive:true})",
        "const {_load:load}=require('node:module'); load('fs'); require('fs').rmSync('/', {recursive:true})",
        "const {Module}=require('node:module'); Module._load=safe; require('fs').rmSync('/', {recursive:true})",
        "import {createRequire as makeRequire} from 'node:module'; makeRequire('/tmp/plugin.js'); require('fs').rmSync('/', {recursive:true})",
        "import {Module} from 'node:module'; Module._load=safe; require('fs').rmSync('/', {recursive:true})",
    ] {
        assert!(!root(code), "{code}");
    }
    assert!(!root_for(
        "bun-js",
        "const Module=require('node:module'); const alias=Module; alias._load=safe; require('fs').rmSync('/', {recursive:true})",
    ));
    assert!(!root_for(
        "tsx",
        "import {Module} from 'node:module'; Module._load=safe; require('fs').rmSync('/', {recursive:true})",
    ));
}

#[test]
fn unrelated_node_module_reads_preserve_module_ownership() {
    for code in [
        "const Module=require('module'); const names=Module.builtinModules; require('fs').rmSync('project-relative', {recursive:true})",
        "const Module=require('node:module'); Module.isBuiltin('fs'); require('fs').rmSync('project-relative', {recursive:true})",
        "const Module=require('module'); const alias=Module; alias.builtinModules; require('fs').rmSync('project-relative', {recursive:true})",
        "const box={loader:require('module'),x:0}; box.x=1; require('fs').rmSync('project-relative', {recursive:true})",
        "const box=[require('module'),0]; box[1]=1; require('fs').rmSync('project-relative', {recursive:true})",
        "const box={loader:require('module'),x:0}; Object.defineProperty(box,'x',{value:1}); require('fs').rmSync('project-relative', {recursive:true})",
        "const box=[require('module'),0]; Object.defineProperty(box,'1',{value:1}); require('fs').rmSync('project-relative', {recursive:true})",
        "const M=require('module'); const box={}; box.check=M.isBuiltin; require('fs').rmSync('project-relative', {recursive:true})",
        "const M=require('module'); M.isBuiltin=()=>false; require('fs').rmSync('project-relative', {recursive:true})",
        "const M=require('module'); M.Module=undefined; require('fs').rmSync('project-relative', {recursive:true})",
        "const M=require('module'); M.constructor=undefined; require('fs').rmSync('project-relative', {recursive:true})",
        "const M=require('module'); M.prototype=undefined; require('fs').rmSync('project-relative', {recursive:true})",
        "module.constructor=undefined; require('fs').rmSync('project-relative', {recursive:true})",
        "const M=require('module'); delete M.Module; require('fs').rmSync('project-relative', {recursive:true})",
    ] {
        assert!(requested_for("node", code, "project-relative"), "{code}");
    }

    assert!(!root(
        "const arr=[null, require('fs')]; arr['01'].rmSync('/', {recursive:true})"
    ));
    for code in [
        "const M=require('module'); plugin(M.isBuiltin); require('fs').rmSync('/', {recursive:true})",
        "const M=require('module'); plugin([M.isBuiltin]); require('fs').rmSync('/', {recursive:true})",
    ] {
        assert!(root(code), "{code}");
    }
}

#[test]
fn only_real_node_prototype_hooks_remove_loader_ownership() {
    for code in [
        "require('module').constructor._load=safe; require('fs').rmSync('/', {recursive:true})",
        "require('module').prototype._load=safe; require('fs').rmSync('/', {recursive:true})",
        "require('module').prototype.createRequire=safe; require('fs').rmSync('/', {recursive:true})",
        "const Module=require('module'); Object.defineProperty(Module, 'unrelated', {value:1}); require('fs').rmSync('/', {recursive:true})",
        "const Module=require('module'); Module.require=safe; require('fs').rmSync('/', {recursive:true})",
        "const Module=require('module'); Object.defineProperty(Module, 'require', {value:safe}); require('fs').rmSync('/', {recursive:true})",
        "module.exports=safe; require('fs').rmSync('/', {recursive:true})",
        "Object.defineProperty(module, 'exports', {value:safe}); require('fs').rmSync('/', {recursive:true})",
        "const Module=require('module'); Object.defineProperty(Module.prototype, '_load', {value:safe}); require('fs').rmSync('/', {recursive:true})",
        "const {rmSync}=require('fs'); const Module=require('module'); Object.defineProperty(Module, '_load', {}); Module._load('fs'); rmSync('/', {recursive:true})",
        "const {rmSync}=require('fs'); delete module.require; module.require('fs'); rmSync('/', {recursive:true})",
    ] {
        assert!(root(code), "{code}");
    }
    assert!(!root(
        "require('module').prototype.isBuiltin('fs'); require('fs').rmSync('/', {recursive:true})"
    ));
    assert!(root(
        "require('module').constructor.isBuiltin('fs'); require('fs').rmSync('/', {recursive:true})"
    ));
}

#[test]
fn var_hoisting_short_circuits_and_divergence_preserve_reachability() {
    for code in [
        "if (false) { var require=safe } require('fs').rmSync('/', {recursive:true})",
        "var fs=require('fs'); if (true) { var fs=safe } fs.rmSync('/', {recursive:true})",
        "true || require('fs').rmSync('/', {recursive:true})",
        "while (true) {} require('fs').rmSync('/', {recursive:true})",
    ] {
        assert_inert(code);
    }
    assert!(root("false || require('fs').rmSync('/', {recursive:true})"));
}

#[test]
fn uncertain_function_returns_do_not_choose_one_branch() {
    assert_eq!(
        report(
            "function target(){if(flag){return '/tmp/safe'}else{return '/'}} require('fs').rmSync(target(), {recursive:true})"
        ),
        InlineReport::default()
    );
    assert!(root(
        "function target(){if(flag){return '/'}else{return '/'}} require('fs').rmSync(target(), {recursive:true})"
    ));
}

#[test]
fn unsupported_and_malformed_regions_do_not_execute_nested_text() {
    let dangerous = "require('child_process').execSync('rm -rf /')";
    for code in [
        format!("switch (value) {{ case 1: {dangerous} }}"),
        format!("class Hidden {{ static run() {{ {dangerous} }} }}"),
        format!("const broken = ; {dangerous}"),
    ] {
        assert_inert(&code);
    }
}
