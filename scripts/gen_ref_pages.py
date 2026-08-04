from pathlib import Path

import mkdocs_gen_files

src = Path("src")

for path in sorted(src.rglob("*.py")):
    module = path.relative_to(src).with_suffix("")
    parts = list(module.parts)

    if parts[-1] == "__main__":
        continue

    if parts[-1] == "__init__":
        parts = parts[:-1]

    doc_path = Path("reference", *parts).with_suffix(".md")

    with mkdocs_gen_files.open(doc_path, "w") as fd:
        identifier = ".".join(parts)
        fd.write(f"# {identifier}\n\n")
        fd.write(f"::: {identifier}\n")
