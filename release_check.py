import os
import re
import subprocess
import sys

SUBJECT = re.compile(r"^\[(\d+\.\d+\.\d+|no release)\] \S")


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def read(sha, path):
    result = subprocess.run(["git", "show", f"{sha}:{path}"], capture_output=True)
    return result.stdout.decode("utf-8").replace("\r\n", "\n") if result.returncode == 0 else None


def bullets(text):
    return [line.rstrip() for line in text.split("\n") if line.startswith("- ")]


def sections(changelog):
    found = []
    for line in changelog.split("\n"):
        if line.startswith("## "):
            found.append([line[3:].strip(), []])
        elif found and line.startswith("- "):
            found[-1][1].append(line.rstrip())
    return found


def tag_target(version):
    result = subprocess.run(["git", "rev-list", "-n", "1", f"refs/tags/v{version}"], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def check(sha):
    subject = git("log", "-1", "--format=%s", sha).strip()
    body = git("log", "-1", "--format=%b", sha).replace("\r\n", "\n")
    match = SUBJECT.match(subject)
    if not match:
        return None, [f"subject '{subject}' does not start with [x.y.z] or [no release]"]
    parents = git("log", "-1", "--format=%P", sha).split()
    changed = git("diff-tree", "--no-commit-id", "--name-only", "-r", "--root", sha).split()
    version = read(sha, "VERSION")
    before = read(parents[0], "VERSION") if parents else None
    problems = []
    if match.group(1) == "no release":
        if before is not None and version != before:
            problems.append("a [no release] commit changes VERSION")
        return None, problems
    wanted = match.group(1)
    if "CHANGELOG.md" not in changed:
        problems.append("CHANGELOG.md is not part of the commit")
    if (version or "").strip() != wanted:
        problems.append(f"VERSION holds '{(version or '').strip()}' but the subject says {wanted}")
    changelog = read(sha, "CHANGELOG.md") or ""
    found = sections(changelog)
    if not found or found[0][0] != wanted:
        problems.append(f"CHANGELOG.md does not open with a section for {wanted}")
    elif found[0][1] != bullets(body) or not found[0][1]:
        problems.append(f"the commit body and the {wanted} section of CHANGELOG.md say different things")
    if any(name.lower() == "unreleased" for name, _ in found):
        problems.append("CHANGELOG.md still has an Unreleased section")
    target = tag_target(wanted)
    if target and target != sha:
        problems.append(f"version {wanted} was already released from {target[:7]}")
    return wanted, problems


def main():
    before, after = sys.argv[1], git("rev-parse", sys.argv[2]).strip()
    if not before or set(before) == {"0"}:
        shas = [after]
    else:
        shas = git("rev-list", "--reverse", f"{before}..{after}").split()
    failed = False
    publish = None
    for sha in shas:
        version, problems = check(sha)
        for problem in problems:
            print(f"{sha[:7]}: {problem}")
            failed = True
        if version and not problems and not tag_target(version):
            if sha != after:
                print(f"{sha[:7]}: version {version} is not the newest commit of the push and would never be released")
                failed = True
            else:
                publish = version
    if failed:
        sys.exit(1)
    if publish:
        with open("release-notes.md", "w", encoding="utf-8") as notes:
            notes.write(git("log", "-1", "--format=%b", after))
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"version={publish or ''}\n")
    print(f"publishing {publish}" if publish else "nothing to publish")


if __name__ == "__main__":
    main()
