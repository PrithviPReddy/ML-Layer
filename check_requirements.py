import argparse
import ast
import json
import sys
from importlib.metadata import PackageNotFoundError, distribution, packages_distributions
from pathlib import Path

SKIP_DIRECTORIES = {".venv", "venv", "__pycache__", ".git", "node_modules", "build", "dist"}


def iter_source_files(root):
    for path in root.rglob("*.py"):
        if any(part in SKIP_DIRECTORIES for part in path.parts):
            continue
        yield path


def top_level_imports(path):
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError):
        return set()

    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


def parse_requirements(path):
    pinned = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for separator in ("==", ">=", "~=", "<="):
            if separator in line:
                name = line.split(separator)[0].strip()
                version = line.split(separator)[1].strip()
                name = name.split("[")[0]
                pinned[name.lower().replace("_", "-")] = version
                break
    return pinned


def main():
    parser = argparse.ArgumentParser(
        description="Check that every third party import is covered by requirements.txt."
    )
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--requirements", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    requirements_path = args.requirements or (args.repo / "requirements.txt")
    pinned = parse_requirements(requirements_path)

    imported = set()
    per_file = {}
    for path in iter_source_files(args.repo):
        names = top_level_imports(path)
        if names:
            per_file[str(path.relative_to(args.repo))] = sorted(names)
        imported |= names

    stdlib = set(sys.stdlib_module_names)
    local_modules = {p.stem for p in args.repo.glob("*.py")}
    local_modules |= {p.name for p in args.repo.iterdir() if p.is_dir() and (p / "__init__.py").exists()}

    module_to_distributions = packages_distributions()

    third_party = sorted(imported - stdlib - local_modules)
    covered = []
    uncovered = []
    for module in third_party:
        distributions = module_to_distributions.get(module, [])
        normalised = {d.lower().replace("_", "-") for d in distributions}
        if normalised & set(pinned):
            covered.append({"module": module, "distributions": sorted(normalised)})
        else:
            installed_version = None
            for candidate in distributions:
                try:
                    installed_version = distribution(candidate).version
                    break
                except PackageNotFoundError:
                    continue
            uncovered.append(
                {
                    "module": module,
                    "distributions": sorted(normalised),
                    "installed_version": installed_version,
                }
            )

    result = {
        "repo": str(args.repo),
        "requirements": str(requirements_path),
        "pinned_count": len(pinned),
        "third_party_modules": third_party,
        "covered": covered,
        "uncovered": uncovered,
        "imports_by_file": per_file,
    }

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"wrote {args.output}")

    print(f"repo: {args.repo}")
    print(f"pinned distributions: {len(pinned)}")
    print(f"third party modules imported: {len(third_party)}")
    for entry in covered:
        print(f"  covered   {entry['module']} -> {', '.join(entry['distributions'])}")
    for entry in uncovered:
        print(f"  UNCOVERED {entry['module']} (installed: {entry['installed_version']})")

    if uncovered:
        raise SystemExit(1)
    print("all third party imports are covered by requirements.txt")


if __name__ == "__main__":
    main()
