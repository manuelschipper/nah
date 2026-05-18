{
  lib,
  python3,
}:
let
  project = builtins.fromTOML (builtins.readFile ./pyproject.toml);
  projectMeta = project.project;
in

python3.pkgs.buildPythonApplication {
  pname = projectMeta.name;
  version = projectMeta.version;
  pyproject = true;

  src = ./.;

  build-system = [
    python3.pkgs.hatchling
  ];

  optional-dependencies = with python3.pkgs; {
    config = [
      pyyaml
    ];
    dev = [
      pytest
    ];
    docs = [
      mkdocs-material
    ];
    keys = [
      keyring
    ];
  };

  pythonImportsCheck = [
    "nah"
  ];

  meta = {
    description = projectMeta.description;
    homepage = "https://github.com/manuelschipper/nah";
    changelog = "https://github.com/manuelschipper/nah/blob/main/CHANGELOG.md";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ ];
    mainProgram = "nah";
  };
}
