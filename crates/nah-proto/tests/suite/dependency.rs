//! The lookalike classifier and the dependency text it reads
//! (`nah_proto::labels::dependency`).

use nah_proto::labels::dependency::{
    Ecosystem, Manifest, install_operand, lookalike, normalized_name, one_edit_apart, same_version,
};

/// Real package pairs one edit apart among the 5,000 most downloaded PyPI
/// projects (hugovk.github.io/top-pypi-packages, 1 November 2026) that the
/// classifier leaves alone: a short segment or trailing digits. The other 80
/// such PyPI pairs stay lookalikes, quiet at core only while their versions
/// differ.
const PYPI_EVERYDAY_PAIRS: &[(&str, &str)] = &[
    ("boto", "boto3"),
    ("six", "svix"),
    ("six", "sox"),
    ("httpx", "httpx2"),
    ("httpcore", "httpcore2"),
    ("yarl", "yarg"),
    ("pip", "pipx"),
    ("pip", "pin"),
    ("pytz", "pyte"),
    ("lml", "lxml"),
    ("lxml", "lkml"),
    ("mcp", "scp"),
    ("mcp", "mcap"),
    ("mcp", "mcpo"),
    ("toml", "tomli"),
    ("psycopg-binary", "psycopg2-binary"),
    ("mako", "marko"),
    ("psycopg", "psycopg2"),
    ("h2", "h3"),
    ("h2", "jh2"),
    ("pypdf", "pypdf2"),
    ("msal", "isal"),
    ("uv", "av"),
    ("uv", "us"),
    ("toml", "rtoml"),
    ("pyee", "pyte"),
    ("markdown", "markdown2"),
    ("nest-asyncio", "nest-asyncio2"),
    (
        "opentelemetry-instrumentation-asgi",
        "opentelemetry-instrumentation-wsgi",
    ),
    ("cbor", "cbor2"),
    ("cssselect", "cssselect2"),
    ("amqp", "pamqp"),
    ("amqp", "uamqp"),
    ("ty", "py"),
    ("ty", "ta"),
    ("moto", "motor"),
    ("moto", "boto"),
    ("py", "ply"),
    ("py", "bpy"),
    ("py", "ipy"),
    ("trio", "trino"),
    ("h3", "nh3"),
    ("nh3", "qh3"),
    ("dask", "dash"),
    ("nvidia-nccl-cu12", "nvidia-nccl-cu13"),
    (
        "opentelemetry-instrumentation-psycopg",
        "opentelemetry-instrumentation-psycopg2",
    ),
    (
        "opentelemetry-instrumentation-urllib",
        "opentelemetry-instrumentation-urllib3",
    ),
    ("ply", "sly"),
    ("nvidia-cudnn-cu13", "nvidia-cudnn-cu12"),
    ("nvidia-cudnn-cu13", "nvidia-cudnn-cu11"),
    ("pytimeparse", "pytimeparse2"),
    ("nvidia-nvshmem-cu13", "nvidia-nvshmem-cu12"),
    ("nvidia-cusparselt-cu13", "nvidia-cusparselt-cu12"),
    ("retry", "retry2"),
    ("rfc3986", "rfc3987"),
    ("pybase64", "pybase62"),
    ("fpdf", "fpdf2"),
    ("nvidia-cudnn-cu12", "nvidia-cudnn-cu11"),
    ("nvidia-cublas-cu12", "nvidia-cublas-cu11"),
    ("py-cpuinfo", "py-cpuinfo2"),
    ("pbr", "pdbr"),
    ("wand", "wandb"),
    ("nvidia-cuda-nvrtc-cu12", "nvidia-cuda-nvrtc-cu11"),
    ("nvidia-cufft-cu12", "nvidia-cufft-cu11"),
    ("nvidia-cusparse-cu12", "nvidia-cusparse-cu11"),
    ("nvidia-cusolver-cu12", "nvidia-cusolver-cu11"),
    ("pytest-httpx", "pytest-httpx2"),
    ("tox", "pox"),
    ("tox", "nox"),
    ("tox", "sox"),
    ("nvidia-cuda-runtime-cu12", "nvidia-cuda-runtime-cu11"),
    ("nvidia-curand-cu12", "nvidia-curand-cu11"),
    ("nvidia-cuda-cupti-cu12", "nvidia-cuda-cupti-cu11"),
    ("h3", "qh3"),
    ("google-ads", "google-adk"),
    ("sox", "soxr"),
    ("mypy-boto3-sqs", "mypy-boto3-sts"),
    ("mypy-boto3-sqs", "mypy-boto3-sns"),
    ("mypy-boto3-sqs", "mypy-boto3-ses"),
    ("rq", "jq"),
    ("rq", "arq"),
    ("rq", "yq"),
    ("rq", "rx"),
    ("pox", "pex"),
    ("pox", "nox"),
    ("pox", "sox"),
    ("ppft", "peft"),
    ("uuid6", "uuid7"),
    ("uuid", "uuid6"),
    ("types-boto", "types-boto3"),
    ("uuid", "uuid7"),
    ("path", "dpath"),
    ("scp", "scs"),
    ("mypy-boto3-ec2", "mypy-boto3-ecs"),
    ("mypy-boto3-ec2", "mypy-boto3-ecr"),
    ("mypy-boto3-sts", "mypy-boto3-sns"),
    ("mypy-boto3-sts", "mypy-boto3-ses"),
    ("pin", "pint"),
    ("pint", "cint"),
    ("jq", "yq"),
    ("furl", "furo"),
    ("dlt", "ddt"),
    (
        "apache-airflow-providers-smtp",
        "apache-airflow-providers-sftp",
    ),
    ("pex", "pem"),
    ("scs", "svcs"),
    ("scs", "jcs"),
    ("pulumi-aws", "pulumi-awsx"),
    ("pathlib", "pathlib2"),
    ("arq", "art"),
    ("nox", "sox"),
    ("mypy-boto3-ecs", "mypy-boto3-ecr"),
    ("mypy-boto3-ecs", "mypy-boto3-eks"),
    ("mypy-boto3-ecs", "mypy-boto3-efs"),
    (
        "nvidia-cutlass-dsl-libs-cu12",
        "nvidia-cutlass-dsl-libs-cu13",
    ),
    ("mypy-boto3-sns", "mypy-boto3-ses"),
    ("databricks-pypi1", "databricks-pypi2"),
    ("types-boto3-ses", "types-boto3-sqs"),
    ("types-boto3-ses", "types-boto3-sts"),
    ("types-aiobotocore-sqs", "types-aiobotocore-sts"),
    ("types-aiobotocore-sqs", "types-aiobotocore-sns"),
    ("lit", "flit"),
    ("bpy", "ipy"),
    (
        "apache-airflow-providers-ftp",
        "apache-airflow-providers-sftp",
    ),
    ("betterproto", "betterproto2"),
    ("us", "fs"),
    ("python-xlib", "python3-xlib"),
    ("pyod", "pyocd"),
    ("uuid", "cuid"),
    (
        "comfyui-workflow-templates-media-assets-02",
        "comfyui-workflow-templates-media-assets-01",
    ),
    ("types-boto3-sqs", "types-boto3-sts"),
    ("sqlalchemy-stubs", "sqlalchemy2-stubs"),
    ("pystac-ext-sar", "pystac-ext-sat"),
    ("avro-gen", "avro-gen3"),
    ("requests-unixsocket", "requests-unixsocket2"),
    ("pyqt5", "pyqt6"),
    ("pyqt5-sip", "pyqt6-sip"),
    ("polling", "polling2"),
    ("types-aiobotocore-sts", "types-aiobotocore-sns"),
    ("path", "pathy"),
    ("path", "patch"),
    ("cuid", "cuid2"),
    ("pdm", "pem"),
    ("srt", "art"),
    ("types-aiobotocore-ec2", "types-aiobotocore-ecs"),
    ("types-aiobotocore-ec2", "types-aiobotocore-ecr"),
    ("argh", "arch"),
    ("mypy-boto3-eks", "mypy-boto3-efs"),
    ("htmlmin", "htmlmin2"),
    ("lml", "lkml"),
    ("types-aiobotocore-ecs", "types-aiobotocore-ecr"),
    ("httpx-auth", "httpx-oauth"),
    ("pem", "cem"),
    ("jsonasobj", "jsonasobj2"),
];

/// The same for the 5,000 most downloaded npm packages (the `topDownload`
/// list of github.com/wooorm/npm-high-impact, November 2026): one scope, a
/// short segment or trailing digits. 53 other such pairs stay lookalikes.
const NPM_EVERYDAY_PAIRS: &[(&str, &str)] = &[
    ("ms", "ws"),
    ("ms", "qs"),
    ("ms", "mz"),
    ("ms", "msw"),
    ("ms", "mv"),
    ("safe-buffer", "safer-buffer"),
    ("uid", "uuid"),
    ("uuid", "ulid"),
    ("ws", "qs"),
    ("ws", "jws"),
    ("http-proxy-agent", "https-proxy-agent"),
    ("q", "qs"),
    ("eventemitter3", "eventemitter2"),
    ("levn", "leven"),
    ("get-proto", "set-proto"),
    ("send", "pend"),
    ("opn", "open"),
    ("ini", "ink"),
    ("merge", "merge2"),
    ("clsx", "xlsx"),
    ("path", "pathe"),
    ("tar", "tarn"),
    ("eta", "etag"),
    ("is-regex", "ip-regex"),
    ("npm", "pnpm"),
    ("jest-diff", "just-diff"),
    ("tmp", "tmpl"),
    ("tmp", "temp"),
    ("mz", "mv"),
    ("d3-time", "d3-timer"),
    ("xmlbuilder", "xmlbuilder2"),
    ("jwa", "jws"),
    ("@types/d3-time", "@types/d3-timer"),
    ("split", "split2"),
    ("@types/ws", "@types/ms"),
    ("@types/ws", "@types/qs"),
    ("@types/ms", "@types/qs"),
    (
        "babel-plugin-polyfill-corejs3",
        "babel-plugin-polyfill-corejs2",
    ),
    ("@types/q", "@types/qs"),
    ("csso", "cssom"),
    ("lie", "lit"),
    ("through", "through2"),
    ("@aws-sdk/client-sso", "@aws-sdk/client-ssm"),
    ("util", "utila"),
    ("pg-types", "pkg-types"),
    ("co", "coa"),
    ("co", "c8"),
    ("he", "h3"),
    ("cac", "crc"),
    ("@webassemblyjs/wasm-parser", "@webassemblyjs/wast-parser"),
    ("@tsconfig/node12", "@tsconfig/node14"),
    ("@tsconfig/node12", "@tsconfig/node10"),
    ("@tsconfig/node12", "@tsconfig/node16"),
    ("@tsconfig/node14", "@tsconfig/node10"),
    ("@tsconfig/node14", "@tsconfig/node16"),
    ("rc", "rw"),
    ("rc", "rc9"),
    ("rc", "crc"),
    ("@tsconfig/node10", "@tsconfig/node16"),
    ("ext", "exit"),
    (
        "@babel/plugin-transform-modules-amd",
        "@babel/plugin-transform-modules-umd",
    ),
    ("obug", "obuf"),
    ("css", "csso"),
    ("bare-fs", "bare-os"),
    ("cli-table", "cli-table3"),
    ("duplexer", "duplexer2"),
    ("duplexer", "duplexer3"),
    ("simple-get", "simple-git"),
    (
        "@opentelemetry/instrumentation-mysql",
        "@opentelemetry/instrumentation-mysql2",
    ),
    ("path", "upath"),
    ("h3", "d3"),
    ("@aws-crypto/crc32", "@aws-crypto/crc32c"),
    ("obuf", "wbuf"),
    ("duplexer2", "duplexer3"),
    ("set-value", "get-value"),
    ("@aws-sdk/client-sts", "@aws-sdk/client-sqs"),
    ("@types/cookie", "@types/cookies"),
    ("safe-regex", "safe-regex2"),
    ("temp", "tempy"),
    ("tlds", "tldts"),
    ("npm", "nypm"),
    ("arch", "archy"),
    ("q", "d"),
    ("d", "d3"),
    ("ext", "next"),
    ("ext", "ent"),
    ("browserify-aes", "browserify-des"),
    ("aws-sdk", "aws-cdk"),
    ("from", "from2"),
    ("yarn", "tarn"),
    ("uid", "ulid"),
    ("uid", "uid2"),
    ("nx", "ox"),
    ("@octokit/auth-app", "@octokit/oauth-app"),
    ("sade", "sane"),
    ("path", "xpath"),
    ("koa", "coa"),
    ("stream-combiner", "stream-combiner2"),
    ("@scure/bip39", "@scure/bip32"),
    ("js-md4", "js-md5"),
    ("path", "mpath"),
    ("xss", "css"),
    ("detective-sass", "detective-scss"),
];

#[test]
fn slips_from_installed_names_are_lookalikes_and_everyday_neighbours_are_not() {
    for (ecosystem, requested, installed) in [
        (Ecosystem::Python, "matplotib", "matplotlib"),
        (Ecosystem::Python, "reqeusts", "requests"),
        (Ecosystem::Python, "python-dateutl", "python-dateutil"),
        (Ecosystem::Node, "lodahs", "lodash"),
        (Ecosystem::Node, "crossenv", "cross-env"),
        (Ecosystem::Node, "expresss", "express"),
    ] {
        assert!(
            lookalike(ecosystem, requested, installed),
            "{requested} imitates {installed}"
        );
    }
    // The pairs the corpus rows and the rule's record name, beside the
    // ecosystems' everyday pairs.
    let named = [
        (Ecosystem::Python, "requests2", "requests"),
        (Ecosystem::Python, "psycopg", "psycopg2"),
        (Ecosystem::Python, "boto", "boto3"),
        (Ecosystem::Python, "nox", "tox"),
        (Ecosystem::Python, "mypy-boto3-sns", "mypy-boto3-sqs"),
        (Ecosystem::Python, "types-requests", "requests"),
        (Ecosystem::Python, "requests-stubs", "requests"),
        (Ecosystem::Python, "matplotlib", "matplotlib"),
        (Ecosystem::Node, "@types/qs", "@types/ms"),
        (
            Ecosystem::Node,
            "@aws-sdk/client-ssm",
            "@aws-sdk/client-sso",
        ),
        (Ecosystem::Node, "lodash-es", "lodash"),
        (Ecosystem::Node, "@types/lodash", "lodash"),
    ];
    let everyday = PYPI_EVERYDAY_PAIRS
        .iter()
        .map(|pair| (Ecosystem::Python, pair.0, pair.1))
        .chain(
            NPM_EVERYDAY_PAIRS
                .iter()
                .map(|pair| (Ecosystem::Node, pair.0, pair.1)),
        );
    for (ecosystem, a, b) in named.into_iter().chain(everyday) {
        assert!(
            !lookalike(ecosystem, a, b) && !lookalike(ecosystem, b, a),
            "{a} and {b} are everyday neighbours"
        );
    }
    // A swap of two letters is one edit; two separate changes are not.
    assert!(one_edit_apart("lodash", "lodahs"));
    assert!(!one_edit_apart("lodash", "ldoahs"));
    assert_eq!(
        normalized_name(Ecosystem::Python, "Ruamel.YAML__clib"),
        "ruamel-yaml-clib"
    );
}

#[test]
fn manifests_and_install_operands_name_registry_requirements() {
    let read = |requirements: Vec<nah_proto::labels::dependency::Requirement>| {
        requirements
            .into_iter()
            .map(|requirement| (requirement.name, requirement.version))
            .collect::<Vec<_>>()
    };
    let pinned = |name: &str, version: &str| (name.to_owned(), Some(version.to_owned()));
    let unpinned = |name: &str| (name.to_owned(), None);
    // A requirements line is a requirement wherever it sits, so a fragment
    // reads as the whole file does.
    assert_eq!(
        read(Manifest::Requirements.requirements(
            "# pinned\n-r base.txt\n--hash=sha256:00\nMatplotLib==3.8.3 ; python_version > \"3.8\"\n\
             requests[socks]!=2.0,==2.31.0  # why\n-e ./local\nflask \\\n  ==3.0.0\n\
             numpy (>=1.26.4, <2)\nurllib3~=2.2.1\nidna>2\n\
             ./wheels/x-1.0-py3-none-any.whl\nlocal @ file:///src\n",
            false,
        )),
        [
            pinned("matplotlib", "3.8.3"),
            pinned("requests", "2.31.0"),
            pinned("flask", "3.0.0"),
            pinned("numpy", "1.26.4"),
            pinned("urllib3", "2.2.1"),
            unpinned("idna"),
        ]
    );
    let package = "{\"name\": \"demo\", \"version\": \"1.0.0\", \"config\": {\"lodahs\": \"4.17.21\"},\n\
                   \"dependencies\": {\"lodash\": \"^4.17.21\", \"local\": \"file:../local\"},\n\
                   \"devDependencies\": {\"jest\": \"latest\", \"react\": \">=18.2.0 <19\", \"vue\": \"^2 || ^3\"}}";
    assert_eq!(
        read(Manifest::PackageJson.requirements(package, true)),
        [
            pinned("lodash", "4.17.21"),
            unpinned("jest"),
            pinned("react", "18.2.0"),
            unpinned("vue"),
        ]
    );
    // Where a fragment of a structured manifest sits is unknown, and a file
    // that does not parse is read by no tool.
    for (manifest, text) in [
        (Manifest::PackageJson, "\"lodahs\": \"^4.17.21\","),
        (Manifest::PyProject, "  \"matplotib==3.8.3\","),
    ] {
        assert_eq!(read(manifest.requirements(text, false)), []);
        assert_eq!(read(manifest.requirements(text, true)), []);
    }
    let pyproject = "[build-system]\nrequires = [\"hatchling==1.21.1\"]\n\
                     [project]\nname = \"demo\"\ndescription = \"matplotib==3.8.3\"\nkeywords = [\"cli\"]\n\
                     dependencies = [\n  \"matplotlib==3.8.3\",\n  # \"matplotib==3.8.3\",\n  \"requests>=2\",\n]\n\
                     optional-dependencies.docs = [\"sphinx==7.2.6\"]\n\
                     [dependency-groups]\ndev = [\"ruff\", {include-group = \"test\"}]\n\
                     [tool.poetry.dependencies]\npython = \"^3.11\"\nnumpy = \"^1.26.4\"\n\
                     pandas = { version = \"2.2.1\", optional = true }\nlocal = { path = \"../local\" }\n\
                     [tool.poetry.group.test.dependencies]\npytest = \">=8.1.1,<9\"\n";
    assert_eq!(
        read(Manifest::PyProject.requirements(pyproject, true)),
        [
            pinned("matplotlib", "3.8.3"),
            pinned("requests", "2"),
            pinned("hatchling", "1.21.1"),
            pinned("sphinx", "7.2.6"),
            unpinned("ruff"),
            pinned("numpy", "1.26.4"),
            pinned("pandas", "2.2.1"),
            pinned("pytest", "8.1.1"),
        ]
    );
    let operand = |ecosystem, operand| {
        install_operand(ecosystem, operand)
            .map(|requirement| (requirement.name, requirement.version))
    };
    assert_eq!(
        operand(Ecosystem::Python, "matplotib[qt]==3.8.3"),
        Some(pinned("matplotib", "3.8.3"))
    );
    assert_eq!(
        operand(Ecosystem::Python, "matplotib (==3.8.3)"),
        Some(pinned("matplotib", "3.8.3"))
    );
    assert_eq!(operand(Ecosystem::Python, "./dist/demo.tar.gz"), None);
    assert_eq!(
        operand(Ecosystem::Python, "git+https://example.com/repo"),
        None
    );
    assert_eq!(
        operand(Ecosystem::Node, "@scope/lodahs@4.17.21"),
        Some(pinned("@scope/lodahs", "4.17.21"))
    );
    assert_eq!(
        operand(Ecosystem::Node, "lodahs@~4.17.21"),
        Some(pinned("lodahs", "4.17.21"))
    );
    assert_eq!(operand(Ecosystem::Node, "lodahs"), Some(unpinned("lodahs")));
    assert_eq!(
        operand(Ecosystem::Node, "lodahs@4.x"),
        Some(unpinned("lodahs"))
    );
    assert_eq!(operand(Ecosystem::Node, "lodash@npm:lodahs@4.17.21"), None);
    assert_eq!(operand(Ecosystem::Node, "user/repo"), None);
    assert_eq!(
        Manifest::of_path("/p/requirements-dev.txt"),
        Some(Manifest::Requirements)
    );
    assert_eq!(Manifest::of_path("/p/package-lock.json"), None);
    // PyPI compares versions as PEP 440 does; npm compares them exactly.
    assert!(same_version(Ecosystem::Python, "3.8.3.0", "3.8.3"));
    assert!(same_version(Ecosystem::Python, "v1.0", "1"));
    assert!(!same_version(Ecosystem::Python, "3.8.3", "3.8.30"));
    assert!(!same_version(Ecosystem::Python, "3.8.3rc1", "3.8.3"));
    assert!(same_version(Ecosystem::Node, "v4.17.21", "4.17.21"));
    assert!(!same_version(Ecosystem::Node, "4.17.21-beta", "4.17.21"));
}
