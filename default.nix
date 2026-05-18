{
  lib,
  python3Packages,
  withConfig ? true,
  withKeys ? true,
  pname ? "nah",
}:

let
  pyproject = builtins.fromTOML (builtins.readFile ./pyproject.toml);

  cleanSrc = lib.cleanSourceWith {
    src = ./.;
    filter =
      path: type:
      let
        base = builtins.baseNameOf path;
        rel = lib.removePrefix ((toString ./.) + "/") (toString path);
      in
      !(
        base == ".git"
        || base == "result"
        || base == "dist"
        || base == "build"
        || base == "_build"
        || base == ".pytest_cache"
        || base == "__pycache__"
        || rel == ".molds"
        || rel == ".worktrees"
        || lib.hasPrefix ".molds/" rel
        || lib.hasPrefix ".worktrees/" rel
      );
  };
in
python3Packages.buildPythonApplication {
  inherit pname;
  version = pyproject.project.version;
  pyproject = true;
  src = cleanSrc;

  build-system = [
    python3Packages.hatchling
  ];

  dependencies =
    lib.optionals withConfig [
      python3Packages.pyyaml
    ]
    ++ lib.optionals withKeys [
      python3Packages.keyring
    ];

  pythonImportsCheck = [ "nah" ];

  meta = {
    description = pyproject.project.description;
    homepage = pyproject.project.urls.Homepage;
    license = lib.licenses.mit;
    mainProgram = "nah";
  };
}
