//! Typed instance flow for Python composition: method dispatch through class
//! inheritance (`Cls.m()` / `self.m()` resolving into an imported base),
//! classmethod `cls` dispatch back to the calling subclass, instances carried
//! through constructor arguments into `self.<attr>`, and locals typed by a
//! followed call's returned instance. Dispatch fires only on unambiguous
//! constructor provenance — the negative cases pin that down.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use effinterp_proto::{ResolutionAssurance, ResourceExpr, ResourceIdentity};
use effinterp_repo::{IndexLimits, build_index, effects_of};
use effinterp_testkit::repo_fixture::repo_test_fixture;

use super::origin_effects;
use crate::support::deletes;

/// The deletes on the entry's merged surface, as (resource, origin) pairs.
const LOADER: &str =
    "import shutil\nclass Loader:\n    def load(self, p):\n        shutil.rmtree(p)\n";

/// `App.method(...)` where `App` inherits the method from an imported base:
/// the call resolves through the declared base into the base's file.
#[test]
fn inherited_method_resolves_through_imported_base() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-inherit",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom base import Base\nclass App(Base):\n    pass\nApp.boom(\"/inh\")\n",
            ),
            (
                "base.py",
                "import shutil\nclass Base:\n    def boom(self, p):\n        shutil.rmtree(p)\n",
            ),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("/inh") && o == "base.py"),
        "inherited method composes from the base's file: {got:?}"
    );
}

#[test]
fn unresolved_inherited_method_keeps_callable_argument_reach() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-inherited-callback",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom parser import Parser\ndef load_default(value):\n    return open('/defaults.json').read()\nparser = Parser()\nparser.add_argument('--config', type=load_default)\n",
            ),
            (
                "parser.py",
                "import argparse\nclass Parser(argparse.ArgumentParser):\n    pass\n",
            ),
        ],
    );
    let report =
        effects_of(&build_index(&root, IndexLimits::default()), "app.py").expect("entry analyzed");
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.as_str() == "filesystem.read"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        == "fs:/defaults.json"
            })
    );
}

/// A constructor call to a class whose `__init__` is inherited enters the
/// base's `__init__` (the ansible `NonInheritableFieldAttribute` shape).
#[test]
fn inherited_init_resolves_through_base() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-inhinit",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom attr import NonInh\nNonInh(\"/inhinit\")\n",
            ),
            (
                "attr.py",
                "import shutil\nclass Attribute:\n    def __init__(self, p):\n        shutil.rmtree(p)\nclass NonInh(Attribute):\n    pass\n",
            ),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("/inhinit") && o == "attr.py"),
        "inherited __init__ composes: {got:?}"
    );
}

#[test]
fn class_without_init_uses_implicit_constructor() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-implicit-init",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom worker import Worker\nWorker().go()\n",
            ),
            (
                "worker.py",
                "import os\nclass Worker:\n    def go(self): os.remove('/implicit-init')\n",
            ),
        ],
    );
    let report =
        effects_of(&build_index(&root, IndexLimits::default()), "app.py").expect("entry analyzed");
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.as_str() == "filesystem.delete"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        == "fs:/implicit-init"
            })
    );
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "unresolved_call")
    );
    assert_eq!(
        report
            .payload
            .as_effects()
            .unwrap()
            .coverage
            .get("filesystem")
            .map(|claim| claim.level),
        Some(effinterp_proto::CoverageLevel::Partial)
    );
}

#[test]
fn external_base_types_instances_and_class_methods() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-external-base",
        &[
            (
                "backend/app/initial_data.py",
                "#!/usr/bin/env python\nfrom app.core.db import init_db\ninit_db(None)\n",
            ),
            ("backend/app/__init__.py", ""),
            (
                "backend/app/models.py",
                "from sqlmodel import SQLModel\nclass UserBase(SQLModel): pass\nclass UserCreate(UserBase): pass\nclass User(SQLModel): pass\n",
            ),
            (
                "backend/app/crud.py",
                "import os\nfrom app.models import User\ndef create_user(*, session, user_create):\n    user_in = User.model_validate(user_create)\n    os.unlink('/created-marker')\n    return user_in\n",
            ),
            ("backend/app/core/__init__.py", ""),
            (
                "backend/app/core/db.py",
                "from app import crud\nfrom app.models import UserCreate\ndef init_db(session):\n    user_create = UserCreate()\n    return crud.create_user(session=session, user_create=user_create)\n",
            ),
        ],
    );
    let index = build_index(&root, IndexLimits::default());
    let report = effects_of(&index, "backend/app/initial_data.py")
        .expect("entry analyzed")
        .payload
        .into_effects()
        .unwrap();
    let delete = report
        .effects
        .iter()
        .find(|effect| {
            effect.operation.as_str() == "filesystem.delete"
                && effinterp_proto::display_resource_with_scope(&effect.resource)
                    == "fs:/created-marker"
        })
        .expect("create_user delete composes");
    assert_eq!(delete.assurance, Some(ResolutionAssurance::Exact));
    assert!(report.boundaries.iter().all(|boundary| {
        boundary
            .detail
            .as_deref()
            .is_none_or(|detail| !detail.contains("call to unmodeled app.crud.create_user"))
    }));
    assert!(report.boundaries.iter().all(|boundary| {
        boundary
            .detail
            .as_deref()
            .is_none_or(|detail| !detail.contains("UserCreate not found"))
    }));
    let details = report
        .boundaries
        .iter()
        .filter_map(|boundary| boundary.detail.as_deref())
        .collect::<Vec<_>>();
    assert_eq!(
        details
            .iter()
            .filter(|detail| detail.contains("sqlmodel.SQLModel.__init__"))
            .count(),
        1,
        "external inherited constructor is bounded once: {details:?}"
    );
    assert_eq!(
        details
            .iter()
            .filter(|detail| detail.contains("sqlmodel.SQLModel.model_validate"))
            .count(),
        1,
        "external inherited classmethod is bounded once: {details:?}"
    );
    let composition = index
        .composition("backend/app/initial_data.py")
        .expect("entry composes");
    assert!(composition.resolved_calls.iter().any(|call| {
        call.source_file == "backend/app/core/db.py"
            && call.callee.module == "app.models"
            && call.callee.symbol == "UserCreate"
    }));
    assert!(composition.resolved_calls.iter().any(|call| {
        call.source_file == "backend/app/crud.py"
            && call.callee.module == "app.models.User"
            && call.callee.symbol == "model_validate"
    }));
    assert_eq!(
        report.coverage.get("filesystem").map(|claim| claim.level),
        Some(effinterp_proto::CoverageLevel::Partial)
    );
    assert!(
        origin_effects(&index, "backend/app/crud.py", None)
            .iter()
            .any(|effect| {
                effect.operation.as_str() == "filesystem.delete"
                    && effinterp_proto::display_resource_with_scope(&effect.resource)
                        == "fs:/created-marker"
            })
    );
}

#[test]
fn optparse_subclass_inherited_method_is_external() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-optparse-base",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nimport os\nfrom parser import P\nargs = P().parse_args()\nos.unlink(args[0])\n",
            ),
            (
                "parser.py",
                "import optparse\nclass P(optparse.OptionParser): pass\n",
            ),
        ],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "app.py")
        .expect("entry analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(
        report
            .effects
            .iter()
            .any(|effect| { effect.operation.as_str() == "filesystem.delete" })
    );
    assert!(report.boundaries.iter().any(|boundary| {
        boundary
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("optparse.OptionParser.parse_args"))
    }));
    assert!(report.boundaries.iter().all(|boundary| {
        boundary.detail.as_deref().is_none_or(|detail| {
            !detail.contains("parse_args not found on exact repository receiver")
        })
    }));
}

#[test]
fn object_base_missing_method_stays_on_exact_repository_receiver() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-object-base",
        &[(
            "app.py",
            "#!/usr/bin/env python\nclass Worker(object):\n    def __init__(self): pass\nWorker().missing()\n",
        )],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "app.py")
        .expect("entry analyzed")
        .payload
        .into_effects()
        .unwrap();
    assert!(report.boundaries.iter().any(|boundary| {
        boundary
            .detail
            .as_deref()
            .is_some_and(|detail| detail == "missing not found on exact repository receiver")
    }));
}

/// The classmethod-driver pattern (ansible's `cli_executor`): a base
/// classmethod does `obj = cls(); obj.run()`, and `Sub.execute()` dispatches
/// `run` back to the calling subclass's override.
#[test]
fn classmethod_cls_dispatch_reaches_subclass_override() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-cls",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nimport shutil\nfrom base import Base\nclass App(Base):\n    def run(self):\n        shutil.rmtree(\"/clsdisp\")\nApp.execute()\n",
            ),
            (
                "base.py",
                "class Base:\n    @classmethod\n    def execute(cls):\n        obj = cls()\n        obj.run()\n    def run(self):\n        pass\n",
            ),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("/clsdisp") && o == "app.py"),
        "cls() dispatch reaches the subclass override: {got:?}"
    );
}

/// An instance passed as a constructor argument, stored by `__init__` on
/// `self`, then dispatched through the attribute in another method (the
/// DataLoader-through-PlaybookExecutor shape).
#[test]
fn instance_through_init_attribute_dispatches() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-attr",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom loader import Loader\nfrom executor import Executor\nldr = Loader()\nex = Executor(loader=ldr)\nex.run()\n",
            ),
            ("loader.py", LOADER),
            (
                "executor.py",
                "class Executor:\n    def __init__(self, loader):\n        self._loader = loader\n    def run(self):\n        self._loader.load(\"/attr\")\n",
            ),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("/attr") && o == "loader.py"),
        "self._loader dispatch composes from the instance's class: {got:?}"
    );
}

#[test]
fn parameter_value_relays_resource_and_object_meaning() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-parameter-relay",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom executor import Executor\nfrom loader import Loader\nfrom relay import run\nrun(Loader(), Executor(Loader()))\n",
            ),
            (
                "executor.py",
                "class Executor:\n    def __init__(self, loader): self.loader = loader\n    def run(self): self.loader.load('/relay-attr')\n",
            ),
            ("loader.py", LOADER),
            (
                "relay.py",
                "def run(loader, executor):\n    forward(loader, executor)\ndef forward(loader, executor):\n    loader.load('/relay')\n    executor.run()\n",
            ),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        got.iter()
            .any(|(resource, origin)| resource.contains("/relay") && origin == "loader.py"),
        "parameter relay preserves object dispatch: {got:?}"
    );
    assert!(
        got.iter().any(|(resource, origin)| {
            resource.contains("/relay-attr") && origin == "loader.py"
        }),
        "parameter relay preserves object properties: {got:?}"
    );
}

#[test]
fn returned_loader_survives_executor_and_static_load_chain() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-loader-chain",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom cli import CLI\nCLI().run()\n",
            ),
            (
                "cli.py",
                "from executor import Executor\nfrom loader import Loader\nclass CLI:\n    def prereq(self):\n        loader = Loader()\n        return loader, None, None\n    def run(self):\n        loader, inventory, manager = self.prereq()\n        executor = Executor(loader=loader)\n        executor.run()\n",
            ),
            (
                "executor.py",
                "from playbook import Playbook\nclass Executor:\n    def __init__(self, loader): self._loader = loader\n    def run(self): Playbook.load('site.yml', loader=self._loader)\n",
            ),
            ("loader.py", LOADER),
            (
                "playbook.py",
                "class Playbook:\n    def __init__(self, loader): self._loader = loader\n    @staticmethod\n    def load(file_name, loader=None):\n        playbook = Playbook(loader=loader)\n        return playbook._load(file_name)\n    def _load(self, file_name):\n        return self._loader.load(file_name)\n",
            ),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        got.iter()
            .any(|(resource, origin)| resource.contains("site.yml") && origin == "loader.py"),
        "loader reaches the static load chain: {got:?}"
    );
}

/// A local bound from a cross-file call is typed by the callee's returned
/// instance — tuple unpacking included (the `_play_prereqs` shape).
#[test]
fn returned_instance_types_the_bound_local() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-ret",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom helpers import make\nl, n = make()\nl.load(\"/ret\")\n",
            ),
            (
                "helpers.py",
                "from loader import Loader\ndef make():\n    ldr = Loader()\n    return ldr, 1\n",
            ),
            ("loader.py", LOADER),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        got.iter()
            .any(|(r, o)| r.contains("/ret") && o == "loader.py"),
        "returned-instance typing composes the method call: {got:?}"
    );
}

#[test]
fn module_tuple_results_keep_distinct_returned_instances() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-module-tuple-results",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom helpers import make_two\na, b = make_two()\na.go()\nb.go()\n",
            ),
            (
                "helpers.py",
                "import os\nclass A:\n    def go(self): os.environ.get('A_GO')\nclass B:\n    def go(self): os.environ.get('B_GO')\ndef make_two():\n    a = A()\n    b = B()\n    return a, b\n",
            ),
        ],
    );
    let report =
        effects_of(&build_index(&root, IndexLimits::default()), "app.py").expect("entry analyzed");
    let environment_reads: Vec<_> = report
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "environment.read")
        .map(|effect| effinterp_proto::display_resource_with_scope(&effect.resource))
        .collect();
    assert!(
        environment_reads
            .iter()
            .any(|resource| resource.contains("A_GO")),
        "first returned instance dispatches independently: {environment_reads:?}"
    );
    assert!(
        environment_reads
            .iter()
            .any(|resource| resource.contains("B_GO")),
        "second returned instance dispatches independently: {environment_reads:?}"
    );
}

/// Negative: a receiver with ambiguous provenance never dispatches, even when
/// some repo class defines a method of that name.
#[test]
fn ambiguous_receiver_does_not_dispatch() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-neg",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nimport loader\n\ndef get_loader():\n    return object()\n\nx = get_loader()\nx.load(\"/neg\")\n",
            ),
            ("loader.py", LOADER),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        got.is_empty(),
        "an untyped receiver must not resolve by method name alone: {got:?}"
    );
}

/// Negative: reassignment drops constructor typing — the stale class must not
/// keep dispatching.
#[test]
fn reassignment_drops_constructor_typing() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-reassign",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom loader import Loader\n\ndef unknown():\n    return object()\n\nldr = Loader()\nldr = unknown()\nldr.load(\"/stale\")\n",
            ),
            ("loader.py", LOADER),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        !got.iter().any(|(r, _)| r.contains("/stale")),
        "a reassigned receiver must not dispatch on its old class: {got:?}"
    );
}

#[test]
fn explicit_method_argument_wins_over_same_named_receiver_attribute() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-argument-precedence",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom lib import C\nc = C('/attr.txt')\nc.save_to('/arg.txt')\n",
            ),
            (
                "lib.py",
                "from pathlib import Path\nclass C:\n    def __init__(self, path): self.path = Path(path)\n    def save_to(self, path): Path(path).write_text('data')\n",
            ),
        ],
    );
    let report =
        effects_of(&build_index(&root, IndexLimits::default()), "app.py").expect("entry analyzed");
    let writes: Vec<_> = report
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.write")
        .collect();
    assert!(writes.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if path == "/arg.txt"
    )));
    assert!(writes.iter().all(|effect| !matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if path == "/attr.txt"
    )));
}

#[test]
fn method_result_without_instance_evidence_does_not_alias_receiver() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-method-result",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom lib import C\nc = C()\nd = c.build()\nd.go()\n",
            ),
            (
                "lib.py",
                "import os\nclass C:\n    def build(self): return {'k': 1}\n    def go(self): os.remove('/danger')\n",
            ),
        ],
    );
    let got = deletes(&root, "app.py");
    assert!(
        got.is_empty(),
        "a method result with no instance evidence must not inherit its receiver: {got:?}"
    );
}

#[test]
fn omitted_method_parameter_is_not_filled_from_receiver_attribute() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-omitted-parameter",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom lib import C\nC('/attr.txt').go()\n",
            ),
            (
                "lib.py",
                "from pathlib import Path\nclass C:\n    def __init__(self, path): self.path = Path(path)\n    def go(self, path='/default.txt'): Path(path).write_text('data')\n",
            ),
        ],
    );
    let report =
        effects_of(&build_index(&root, IndexLimits::default()), "app.py").expect("entry analyzed");
    let writes: Vec<_> = report
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == "filesystem.write")
        .collect();
    assert!(!writes.is_empty(), "the method write remains reachable");
    assert!(writes.iter().all(|effect| !matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if path == "/attr.txt"
    )));
}

#[test]
fn external_instance_methods_bind_keyword_arguments() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-external-keywords",
        &[
            (
                "app.py",
                "#!/usr/bin/env python\nfrom lib import Client\nClient('/output.txt').write()\n",
            ),
            (
                "lib.py",
                "from pathlib import Path\nclass Client:\n    def __init__(self, path): self.path = Path(path)\n    def write(self): self.path.open(mode='w')\n",
            ),
        ],
    );
    let report =
        effects_of(&build_index(&root, IndexLimits::default()), "app.py").expect("entry analyzed");
    let filesystem: Vec<_> = report
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str().starts_with("filesystem."))
        .collect();
    assert!(filesystem.iter().any(|effect| {
        effect.operation.as_str() == "filesystem.write"
            && matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::FsPath { path },
                } if path == "/output.txt"
            )
    }));
    assert!(
        filesystem
            .iter()
            .all(|effect| effect.operation.as_str() != "filesystem.read")
    );
}

#[test]
fn httpie_callback_and_instance_chain_reaches_core_effects() {
    let root = repo_test_fixture(
        Path::new(env!("CARGO_TARGET_TMPDIR")),
        "pydisp-httpie-core",
        &[
            (
                "__main__.py",
                "#!/usr/bin/env python\nfrom core import main\nmain()\n",
            ),
            (
                "core.py",
                r#"import os
import requests
from cli_definition import parser
from config import Config
from downloads import Downloader
from sessions import get_session
from transport import build_session
from update import check_updates

def raw_main(parser, main_program):
    args = parser.parse_args()
    return main_program(args)

def main():
    return raw_main(parser=parser, main_program=program)

def program(args):
    config = Config('/cfg/config.json')
    config.load()
    config.save()
    session = None
    if args.session:
        session = get_session('/cfg/session.json')
    if session:
        session.save()
    requests_session = build_session()
    request = requests.Request('GET', 'https://api.example.test/items').prepare()
    requests_session.send(request)
    Downloader().start()
    with open('/upload.bin', 'rb'):
        pass
    os.environ.get('HTTPIE_TOKEN')
    check_updates()
"#,
            ),
            (
                "cli_definition.py",
                r#"from argparser import HTTPieArgumentParser

def to_argparse(parser_type=HTTPieArgumentParser):
    concrete_parser = parser_type()
    return concrete_parser

parser = to_argparse()
"#,
            ),
            (
                "argparser.py",
                r#"import argparse
import os

class HTTPieArgumentParser(argparse.ArgumentParser):
    def parse_args(self):
        os.environ.get('HTTPIE_PARSE')
        return super().parse_args()
"#,
            ),
            (
                "config.py",
                r#"from pathlib import Path

class BaseConfig:
    def __init__(self, path):
        self.path = Path(path)
    def load(self):
        self.path.open()
    def save(self):
        self.path.write_text('config')

class Config(BaseConfig):
    pass
"#,
            ),
            (
                "sessions.py",
                r#"from pathlib import Path
from config import BaseConfig

def get_session(path):
    session = Session(path)
    session.load()
    return session

class Session(BaseConfig):
    def __init__(self, path):
        super().__init__(path=Path(path))
"#,
            ),
            (
                "transport.py",
                r#"import requests

def build_session():
    session = requests.Session()
    return session
"#,
            ),
            (
                "downloads.py",
                r#"class Downloader:
    def start(self):
        return self._open_output()
    @staticmethod
    def _open_output():
        return open('/download.bin', 'a+b')
"#,
            ),
            (
                "update.py",
                "import subprocess\ndef update_checker(func):\n    def wrapper():\n        func()\n        subprocess.Popen(['python', '-m', 'update'])\n    return wrapper\n@update_checker\ndef check_updates():\n    pass\n",
            ),
        ],
    );
    let report = effects_of(&build_index(&root, IndexLimits::default()), "__main__.py")
        .expect("entry analyzed");
    let effects: Vec<_> = report
        .payload
        .as_effects()
        .unwrap()
        .effects
        .iter()
        .map(|effect| {
            (
                effect.operation.as_str(),
                effinterp_proto::display_resource_with_scope(&effect.resource),
                effect.modality.as_str(),
                effect
                    .origin
                    .as_ref()
                    .expect("effect origin")
                    .source_file
                    .as_str(),
            )
        })
        .collect();
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .any(|effect| {
                effect.operation.as_str() == "network.request"
                    && matches!(
                        &effect.resource,
                        ResourceExpr::Unresolved { family } if family.0 == "network"
                    )
                    && effect.modality.as_str() == "may"
                    && !effect
                        .origin
                        .as_ref()
                        .expect("effect origin")
                        .source_file
                        .is_empty()
            })
    );
    for (operation, resource) in [
        ("filesystem.read", "/cfg/config.json"),
        ("filesystem.write", "/cfg/config.json"),
        ("filesystem.read", "/cfg/session.json"),
        ("filesystem.write", "/cfg/session.json"),
        ("filesystem.write", "/download.bin"),
        ("filesystem.read", "/upload.bin"),
        ("environment.read", "HTTPIE_PARSE"),
        ("environment.read", "HTTPIE_TOKEN"),
    ] {
        assert!(
            effects.iter().any(|effect| {
                effect.0 == operation
                    && effect.1.contains(resource)
                    && effect.2 == "may"
                    && !effect.3.is_empty()
            }),
            "missing {operation} {resource}: {effects:?}"
        );
    }
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .effects
            .iter()
            .all(|effect| effect.operation.as_str() != "process.exec")
    );
    assert!(
        report
            .payload
            .as_effects()
            .unwrap()
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == "unresolved_decorator")
    );
    assert!(
        report
            .boundaries
            .iter()
            .all(|boundary| boundary.reason != "lifecycle_unbound")
    );
}
