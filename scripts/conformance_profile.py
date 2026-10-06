#!/usr/bin/env python3
"""Generate (or verify) the machine-readable conformance profile.

`conformance.json` maps every requirement this suite tests to the fixture
that tests it and the pinned expected outcome. The requirement entries are
DERIVED from the fixtures themselves (each fixture carries its spec
references and expected block), so the profile cannot drift from the fixture
set: regeneration is deterministic and CI verifies the committed file matches.

`--check` also verifies the human-readable counterpart: the README's
"What this suite verifies" table must have exactly one row for every fixture
in `fixtures/` and name no fixture that does not exist. It also requires every
tracked file at the repository root to be named in the README, as a backticked
name or a link target, except the files git and npm read by convention, so no
root file is left unexplained. Where git cannot list the tracked files (a
source archive, a temporary copy, or a checkout where git is missing or fails)
the root files that the root `.gitignore` does not exclude stand in for them.

Usage:
    python3 scripts/conformance_profile.py            # (re)write conformance.json
    python3 scripts/conformance_profile.py --check    # exit 1 if conformance.json, the README table or a root file is stale
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "conformance.json"
README = REPO_ROOT / "README.md"
README_TABLE_MARKER = "What this suite verifies:"
README_FIXTURE_REF = re.compile(r"`(fixtures/[A-Za-z0-9._-]+\.json)`")
# Root files that git or npm read by convention; every other tracked root file
# must be named in the README.
ROOT_CONVENTION_FILES = {".gitignore", "LICENSE", "README.md", "package.json", "package-lock.json"}
# Variables that point git at a particular repository, as `git rev-parse
# --local-env-vars` lists them. Git exports some of them to hooks (GIT_DIR and
# GIT_INDEX_FILE in a linked worktree); they are dropped before calling git so
# that git reads the checkout this script runs in.
GIT_LOCAL_ENV = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_DIR",
        "GIT_GRAFT_FILE",
        "GIT_IMPLICIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_OBJECT_DIRECTORY",
        "GIT_PREFIX",
        "GIT_REPLACE_REF_BASE",
        "GIT_SHALLOW_FILE",
        "GIT_WORK_TREE",
    }
)
# Character classes of git's wildmatch, as byte ranges (git's own ctype, so
# [:space:] is tab, newline, carriage return and space).
WILDMATCH_CLASSES = {
    b"alnum": rb"0-9A-Za-z",
    b"alpha": rb"A-Za-z",
    b"blank": rb"\t ",
    b"cntrl": rb"\x00-\x1f\x7f",
    b"digit": rb"0-9",
    b"graph": rb"!-~",
    b"lower": rb"a-z",
    b"print": rb" -~",
    b"punct": rb"!-/:-@\[-`{-~",
    b"space": rb"\t\n\r ",
    b"upper": rb"A-Z",
    b"xdigit": rb"0-9A-Fa-f",
}
# A .gitignore line without its trailing spaces, unless a backslash escapes them.
GITIGNORE_LINE = re.compile(rb"((?:\\.|[^\\])*?) *", re.S)

# --- suite metadata (hand-maintained; everything under `requirements` is derived) ---
SUITE = {
    "$schema": "https://specs.opena2a.org/schemas/conformance-profile-v1.json",
    "suite": "aap-conformance",
    "spec": {
        "id": "AAP",
        "name": "Agent Authorization Protocol",
        "version": "0.5.0-draft",
        "ref": "https://github.com/opena2a-standards/agent-authorization-protocol/blob/main/AAP-SPEC.md",
    },
    "fixtureManifest": "MANIFEST.sha256",
    "verifiers": [
        {
            "language": "node",
            "path": "verifiers/node",
            "coverage": "full fixture set; exercises the same primitives the TypeScript reference broker (Secretless) mints with — node:crypto Ed25519 plus @noble/post-quantum ML-DSA-65 (RFC 9964)",
        },
        {
            "language": "python",
            "path": "verifiers/python",
            "coverage": "full fixture set; mirrors the spec repo's Python fixture generator from the verification side (cryptography Ed25519 plus dilithium-py ML-DSA-65)",
        },
    ],
    "notCovered": [
        {
            "specSection": "§8.2 key exchange (hybrid X25519 + ML-KEM-768)",
            "reason": "transport key negotiation, not token wire form; ML-KEM has no final JOSE registration, so that row of §8.2 remains reserved",
        },
        {
            "specSection": "§7 cross-organizational federation and broker-profile runtime behavior (CPI endpoints, grant references, revocation propagation)",
            "reason": "runtime protocol flows, not token wire form; grant-reference-v1 is validated against the broker-profile ABNF in the spec repo's own CI",
        },
        {
            "specSection": "§8.3 intent verification and the optional-to-ignore CGT members (intent_verified, context_required, the deprecated fga_constraints and max_uses)",
            "reason": "optional-to-ignore per the broker profile; the v1 reference does not mint them — the schemas accept them, but no fixture pins their semantics",
        },
        {
            "specSection": "§4.4 narrowing rule between authorization_details and the scope string",
            "reason": "the mapping from an OAuth scope string to the locations and actions it permits is deployment-defined, so the intersection is not mechanical from the token alone; the suite pins the §5.4 attenuation relation, which is mechanical",
        },
        {
            "specSection": "§4.6 presentation bindings other than the signed challenge (local socket peer credentials, RFC 9421 HTTP message signatures), and the channel properties of the signed challenge itself",
            "reason": "the OS and HTTP bindings of broker profile §6.8 are runtime channel properties; the suite models the A2A/MCP signed-challenge row deterministically and pins cnf against it (key binding by RFC 7638 thumbprint and the signature over the challenge); channel binding, freshness and single use of the challenge are broker state and not exercised",
        },
        {
            "specSection": "§7.3 grant revocation list",
            "reason": "broker runtime state (a local list checked at resolution), not token wire form",
        },
        {
            "specSection": "§4.5 producer rule: aap_crit MUST NOT name a §4.2 baseline claim",
            "reason": "a producer MUST NOT with no verifier MUST; the verifiers reject such a name only as a name they do not implement, and no fixture pins the producer rule",
        },
        {
            "specSection": "§5.4 a DA that omits authorization_details while its delegator carries some",
            "reason": "the spec's mechanical text quantifies over the entries a DA carries and is vacuous over an absent claim, so the verifiers pass it; §4.4 reads a token without the claim as an unconstrained baseline token, which would carry more than the delegator's grant — a spec text gap, pending a spec sentence before a fixture pins it",
        },
        {
            "specSection": "§5.4 member kinds and §4.4.1 entry types no fixture exercises (identity, deny set, bound incl. spend/rate/tokenCap, restriction flags, constraint objects; mcp_tool, skill, peer_agent, model, network incl. *. destination coverage)",
            "reason": "implemented in both verifiers, not pinned; what IS exercised is the allow set member kind on a data entry (fieldsAllowed, rejected when widened), the §5.5 data and budget entries accepted as narrower than the §4.7 grant, and max_depth",
        },
        {
            "specSection": "§5.4 start-of-window ordering (DA iat vs delegator iat)",
            "reason": "not stated by the spec; bounded only by the family clock-skew bound (ATP §10.2 via broker profile §6 step 2), so it is not a verifier rule here — only the end of the window (exp) is checked and pinned",
        },
    ],
}


def build() -> dict:
    requirements = []
    for path in sorted((REPO_ROOT / "fixtures").glob("*.json")):
        fx = json.loads(path.read_text())
        expected = fx["expected"]
        outcome = expected["verifyResult"]
        if expected.get("rejectCategory"):
            outcome = f"REJECT[{expected['rejectCategory']}]"
        requirements.append(
            {
                "fixture": f"fixtures/{path.name}",
                "name": fx["name"],
                "fixtureType": fx["fixtureType"],
                "tokenForm": fx["tokenForm"],
                "level": "MUST",
                "specRefs": fx["spec"],
                "expected": outcome,
                "description": fx["description"],
            }
        )
    profile = dict(SUITE)
    profile["requirements"] = requirements
    return profile


def readme_table_fixtures(readme: str) -> list[str] | None:
    """Fixture paths named in the "What this suite verifies" table of README text `readme`.

    One entry per table row that names the fixture, so a fixture named in two
    rows appears twice. Returns None when the table cannot be found.
    """
    lines = readme.splitlines()
    if README_TABLE_MARKER not in lines:
        return None
    named: list[str] = []
    in_table = False
    for line in lines[lines.index(README_TABLE_MARKER) + 1 :]:
        if line.startswith("|"):
            in_table = True
            named += dict.fromkeys(README_FIXTURE_REF.findall(line))
        elif in_table or line.strip():
            break
    return named if in_table else None


def check_readme_table(profile: dict, readme: str) -> list[str]:
    named = readme_table_fixtures(readme)
    if named is None:
        return [f'README.md: no table after "{README_TABLE_MARKER}"']
    fixtures = {req["fixture"] for req in profile["requirements"]}
    rows = Counter(named)
    problems = [f"README.md table has no row for {f}" for f in sorted(fixtures - set(rows))]
    problems += [f"README.md table names {f}, which is not in fixtures/" for f in sorted(set(rows) - fixtures)]
    problems += [f"README.md table names {f} in {n} rows" for f, n in sorted(rows.items()) if n > 1]
    return problems


def git_env() -> dict[str, str]:
    """The environment without the variables that point git at a particular repository."""
    return {k: v for k, v in os.environ.items() if k not in GIT_LOCAL_ENV}


def git_root_files() -> list[str] | None:
    """Tracked files at the repository root, or None when git cannot list them.

    None when the repository root is not the top level of a git checkout (a
    source archive, or a copy that sits untracked inside some other checkout),
    and also when git is missing or fails in a real checkout: `root_files` then
    falls back to the root `.gitignore`, which holds untracked root files to
    the rule as well. Names are decoded with `os.fsdecode`, so a name that is
    not valid UTF-8 keeps its bytes as surrogate escapes.
    """
    env = git_env()
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=REPO_ROOT, env=env, capture_output=True, check=True
        ).stdout
        if Path(os.fsdecode(top.rstrip(b"\n"))).resolve() != REPO_ROOT:
            return None
        out = subprocess.run(
            ["git", "ls-files", "-z"], cwd=REPO_ROOT, env=env, capture_output=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return sorted(os.fsdecode(p) for p in out.split(b"\0") if p and b"/" not in p)


def wildmatch_bracket(pattern: bytes, i: int) -> tuple[bytes, int] | None:
    """Translate the bracket expression whose body starts at `pattern[i]`.

    Returns the regex and the index after the closing `]`, or None when the
    expression is malformed, which makes git's wildmatch match nothing.
    """
    negated = pattern[i : i + 1] in (b"!", b"^")
    i += negated
    items: list[bytes] = []
    prev: bytes | None = None
    first = True
    while True:
        c = pattern[i : i + 1]
        if not c:
            return None
        if c == b"]" and not first:
            break
        first = False
        if c == b"\\":
            i += 1
            prev = pattern[i : i + 1]
            if not prev:
                return None
            items.append(re.escape(prev))
        elif c == b"-" and prev is not None and pattern[i + 1 : i + 2] not in (b"", b"]"):
            i += 1
            if pattern[i : i + 1] == b"\\":
                i += 1
            hi = pattern[i : i + 1]
            if not hi:
                return None
            if prev <= hi:
                items.append(re.escape(prev) + b"-" + re.escape(hi))
            prev = None
        elif c == b"[" and pattern[i + 1 : i + 2] == b":":
            end = pattern.find(b"]", i + 2)
            if end == -1:
                return None
            if end - (i + 2) < 1 or pattern[end - 1 : end] != b":":
                items.append(re.escape(c))  # no ":]", so "[" is an ordinary member
                prev = c
            else:
                cls = WILDMATCH_CLASSES.get(pattern[i + 2 : end - 1])
                if cls is None:
                    return None
                items.append(cls)
                prev = None
                i = end
        else:
            items.append(re.escape(c))
            prev = c
        i += 1
    body = b"".join(items)
    if negated:
        return b"[^/" + body + b"]", i + 1
    return (b"[" + body + b"]" if body else b"(?!)"), i + 1


def wildmatch_regex(pattern: bytes) -> re.Pattern[bytes] | None:
    """Translate a git wildmatch `pattern` (with WM_PATHNAME) to a regex.

    Returns None for a pattern git's wildmatch can never match (a trailing
    backslash, an unclosed or malformed bracket expression).
    """
    out: list[bytes] = []
    i = 0
    while i < len(pattern):
        c = pattern[i : i + 1]
        if c == b"\\":
            escaped = pattern[i + 1 : i + 2]
            if not escaped:
                return None
            out.append(re.escape(escaped))
            i += 2
        elif c == b"?":
            out.append(b"[^/]")
            i += 1
        elif c == b"*":
            j = i
            while pattern[j : j + 1] == b"*":
                j += 1
            rest = pattern[j:]
            at_segment_start = i == 0 or pattern[i - 1 : i] == b"/"
            if j - i > 1 and at_segment_start and (not rest or rest.startswith((b"/", b"\\/"))):
                if rest.startswith(b"/"):
                    out.append(b"(?:.*/)?")  # "**/" matches zero or more directories
                    j += 1
                else:
                    out.append(b".*")
            else:
                out.append(b"[^/]*")
            i = j
        elif c == b"[":
            bracket = wildmatch_bracket(pattern, i + 1)
            if bracket is None:
                return None
            regex, i = bracket
            out.append(regex)
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile(b"".join(out), re.S)


def gitignored(name: str, lines: list[str]) -> bool:
    """Whether the root `.gitignore` `lines` exclude the root file `name`, as git decides.

    Each line is read as git reads it: one trailing carriage return is
    dropped, `#` starts a comment, trailing spaces are dropped unless a
    backslash escapes them (a trailing tab is kept), `!` negates, a trailing
    `/` matches directories only, and the rest is a wildmatch pattern
    (`\\` escapes, `?`, `*`, `**`, `[...]`, `[!...]`, `[^...]`, `[:class:]`)
    matched byte by byte. The last matching line wins. Matching is
    case-sensitive, as git is without `core.ignorecase`.
    """
    target = os.fsencode(name)
    ignored = False
    for line in lines:
        raw = os.fsencode(line).removesuffix(b"\r")
        if raw.startswith(b"#"):
            continue
        trimmed = GITIGNORE_LINE.fullmatch(raw)
        pattern = trimmed.group(1) if trimmed else raw
        negated = pattern.startswith(b"!")
        pattern = pattern.removeprefix(b"!")
        dir_only = pattern.endswith(b"/")
        pattern = pattern.removesuffix(b"/")
        if dir_only or not pattern:
            continue  # matches directories only, or nothing
        if b"/" in pattern:
            pattern = pattern.removeprefix(b"/")  # anchored to the root, where `name` is
        regex = wildmatch_regex(pattern)
        if regex is not None and regex.fullmatch(target):
            ignored = not negated
    return ignored


def root_files() -> list[str]:
    """Files at the repository root that the README must account for.

    These are the tracked root files when git can list them. Otherwise they
    are the root files the root `.gitignore` does not exclude, the ones a
    checkout would track.
    """
    tracked = git_root_files()
    if tracked is not None:
        return tracked
    try:
        text = (REPO_ROOT / ".gitignore").read_bytes().removeprefix(b"\xef\xbb\xbf")
    except OSError:
        text = b""
    lines = [os.fsdecode(line) for line in text.split(b"\n")]
    return sorted(
        p.name
        for p in REPO_ROOT.iterdir()
        if p.is_file() and p.name != ".git" and not gitignored(p.name, lines)
    )


def readme_names(readme: str, name: str) -> bool:
    """Whether README text `readme` names the root file `name`.

    The name counts when it appears backticked (`NAME`) or as the target of a
    link to it (`](NAME)`, `](./NAME)`, optionally with a `#fragment`), not
    when it is only part of a longer path or word.
    """
    name = re.escape(name)
    return re.search(rf"`{name}`|\]\((?:\./)?{name}(?:#[^)]*)?\)", readme) is not None


def check_root_files(readme: str) -> list[str]:
    problems = []
    for name in root_files():
        if name in ROOT_CONVENTION_FILES:
            continue
        try:
            name.encode("utf-8")
        except UnicodeEncodeError:
            shown = os.fsencode(name).decode("utf-8", "backslashreplace")
            problems.append(f"{shown} is at the repository root but its name is not valid UTF-8, so README.md cannot name it")
            continue
        if not readme_names(readme, name):
            problems.append(f"{name} is at the repository root but README.md does not name it")
    return problems


def main() -> int:
    profile = build()
    rendered = json.dumps(profile, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        rc = 0
        if not OUT.exists():
            print("conformance.json missing; run scripts/conformance_profile.py")
            rc = 1
        elif OUT.read_text() != rendered:
            print("conformance.json is stale; run scripts/conformance_profile.py")
            rc = 1
        else:
            print("conformance.json is current")
        try:
            readme = README.read_text()
        except OSError as exc:
            print(f"README.md: cannot be read ({exc.strerror or exc})")
            return 1
        problems = check_readme_table(profile, readme)
        for problem in problems:
            print(problem)
        if problems:
            rc = 1
        else:
            print(f"README.md table names all {len(profile['requirements'])} fixtures")
        root_problems = check_root_files(readme)
        for problem in root_problems:
            print(problem)
        if root_problems:
            rc = 1
        else:
            print("README.md names every root file")
        return rc
    OUT.write_text(rendered)
    print(f"wrote conformance.json ({len(profile['requirements'])} requirements)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
