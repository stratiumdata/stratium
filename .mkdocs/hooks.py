"""Rewrite links that leave the published site into GitHub links.

The docs link freely into the rest of the repository (../../example/, the
Python SDK README, docs/superpowers specs). Those targets are not part of the
site, so on GitHub they work and on the site they would 404. This hook points
each one at the same path on GitHub instead.
"""

import os
import posixpath
import re

REPO = "https://github.com/stratiumdata/stratium"
BRANCH = "main"
EXCLUDED = ("superpowers/", "validation-journeys.md")  # keep in sync with mkdocs.yml exclude_docs

# [text](target), and ![alt](src) alike.
LINK = re.compile(r"(\]\()([^)\s]+)(\))")
EXTERNAL = re.compile(r"^([a-z][a-z0-9+.-]*:|#|/)", re.IGNORECASE)


def _github_url(page_src: str, target: str, repo_root: str) -> str | None:
    path, _, anchor = target.partition("#")
    resolved = posixpath.normpath(posixpath.join("docs", posixpath.dirname(page_src), path))
    if resolved.startswith(".."):
        return None  # escapes the repository itself; leave it for the validator
    inside_docs = resolved.startswith("docs/")
    in_excluded = inside_docs and resolved[len("docs/"):].startswith(EXCLUDED)
    if inside_docs and not in_excluded:
        return None  # a page on this site; MkDocs resolves it
    kind = "tree" if path.endswith("/") or os.path.isdir(os.path.join(repo_root, resolved)) else "blob"
    return f"{REPO}/{kind}/{BRANCH}/{resolved}" + (f"#{anchor}" if anchor else "")


def rewrite(markdown: str, page_src: str, repo_root: str) -> str:
    def sub(m: re.Match) -> str:
        target = m.group(2)
        if EXTERNAL.match(target):
            return m.group(0)
        url = _github_url(page_src, target, repo_root)
        return m.group(0) if url is None else f"{m.group(1)}{url}{m.group(3)}"

    return LINK.sub(sub, markdown)


def on_page_markdown(markdown: str, page, config, files) -> str:  # noqa: ANN001 (MkDocs objects)
    repo_root = os.path.dirname(config["config_file_path"])
    return rewrite(markdown, page.file.src_uri, repo_root)


if __name__ == "__main__":
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cases = {
        ("pep/README.md", "[sdk](../../sdk/python/README.md)"):
            f"[sdk]({REPO}/blob/main/sdk/python/README.md)",
        ("pep/hook.md", "[ex](../../example/hook/)"):
            f"[ex]({REPO}/tree/main/example/hook)",
        ("validation-journeys.md", "[s](superpowers/specs/x.md#a)"):
            f"[s]({REPO}/blob/main/docs/superpowers/specs/x.md#a)",
        ("pep/hook.md", "[p](../pep.md)"): "[p](../pep.md)",
        ("default-posture.md", "[v](validation-journeys.md)"):
            f"[v]({REPO}/blob/main/docs/validation-journeys.md)",
        ("concepts.md", "[a](architecture.md#x)"): "[a](architecture.md#x)",
        ("concepts.md", "[w](https://example.com)"): "[w](https://example.com)",
        ("concepts.md", "[h](#here)"): "[h](#here)",
    }
    for (src, md), want in cases.items():
        got = rewrite(md, src, root)
        assert got == want, f"{src}: {md!r} -> {got!r}, want {want!r}"
    print(f"ok: {len(cases)} cases")
