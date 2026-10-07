"""Overlap between MiMo-V2.6-RL-oss (cyber) training tasks and CyberGym test tasks.

Both datasets are built from ARVO, a public set of reproducible OSS-Fuzz bugs. OSS-Fuzz
renumbered its bugs when it moved issue trackers, so one bug can carry an old (Monorail)
ID and a new ID. We translate with ARVO's own old->new mapping before matching.

Run:  uv run mimo_cybergym.py --signatures --images --build-steps --related-bugs --secbench
Writes everything to out/. All flags are needed for out/summary.json to match the other files in out/: a flag left
off writes null for its section but leaves that flag's earlier output file in place.
"""

import argparse
import csv
import hashlib
import io
import json
import math
import re
import tarfile
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow.parquet as pq
from datasets import load_dataset
from huggingface_hub import HfApi, hf_hub_download

# Pinned sources. Set a revision to None to use the current one (it is recorded in out/summary.json).
MIMO_REPO, MIMO_REV = "XiaomiMiMo/MiMo-V2.6-RL-oss", "639865fd3374018d6cb29b9fb82dd531406fcf5f"
CYBERGYM_REPO, CYBERGYM_REV = "sunblaze-ucb/cybergym", "bde190ded494e52bc684b66073b436c9d992c7c6"
ARVO_MAPPING = ("https://raw.githubusercontent.com/n132/ARVO/"
                "bc2a373c6b32fb3d9e7f86c516b1844885dcec51/arvo/oss_fuzz_mappings.csv")
# Per-bug ARVO metadata (fix commit, ClusterFuzz report) and fix patches, for --related-bugs and --secbench.
ARVO_META_COMMIT = "7e1a64f52520a5d63c766d5546a32fd748f23e21"
ARVO_META_RAW = f"https://raw.githubusercontent.com/n132/ARVO-Meta/{ARVO_META_COMMIT}/archive_data"
ARVO_META_CACHE = Path.home() / ".cache" / "agentleak" / f"arvo-meta-{ARVO_META_COMMIT[:8]}"
ARVO_V1_META_TREE = ("https://api.github.com/repos/n132/ARVO-Meta/git/trees/"
                     "df107a1b3bc839de773b477a49e86d2d9ee75ff9")  # archive_data/meta @ 7e1a64f

# Docker images for the cyber tasks, as named on the MiMo dataset card. One tag per task (arvo-v1-<N>).
IMAGE_REPO = "xiaomimimo/mimo-v2.6-rl-oss"
# --images sample, pinned by manifest digest: 6 hand-picked tasks (in and out of CyberGym, old and new IDs,
# an LLVMFuzzerInitialize task), then every 50th task by numeric ID, from the lowest (arvo-v1-42470443 is in both).
# arvo-v1-1065 was added on 2026-10-07 as one of the 6 images with a different build (entrypoint.sh).
IMAGE_SAMPLE = {
    "arvo-v1-54839": "sha256:3d46aac744cfe05b1b1746dc3a9fb0ffbf76e24e2e3c3343070b565d50f1c78c",
    "arvo-v1-42470443": "sha256:48cf0cca56ddb559646d374340d250f9d34bb791b54c70251cb336b80022d447",
    "arvo-v1-42501146": "sha256:8b8f0a3b0708d52bf1608ab156ad2262a433eca6ed2a1ab6277a1b2f10886563",
    "arvo-v1-27710": "sha256:a44fc4488c87929a634bcc9b8c3bda5459e9aa0cfc3a099dc0fe517aa8751a3d",
    "arvo-v1-42859": "sha256:ce0fdff47ebb976555b2cd04b59ad78b771d45c4b886506e43d8652aad12ba5f",
    "arvo-v1-44221": "sha256:689c12212e7ddd6cbd599aead0f8253737f75e548a4200b139f6eab2e1ca2cff",
    "arvo-v1-344": "sha256:98bc0ce42e62ce22f6f489c054b1364ea0ce868babad20c00e4a4643c9fad0f1",
    "arvo-v1-10126": "sha256:8962acf8a8b7d2a9c4e1631890a8bd7394a8c73885e7f87693838e50ef1a5d16",
    "arvo-v1-16266": "sha256:477505a550598ca37c84f1ed5999358ae88b9c3332b65bad51d4916b8be62c45",
    "arvo-v1-21289": "sha256:0bef62d9e55e676f99a152aac7c9acff6869bfb684d81c5e840699e83543f55e",
    "arvo-v1-25911": "sha256:9f2a0e72607a94992d9074884f46cb2eff7af86e6cedafc919c4d580e3672a13",
    "arvo-v1-31768": "sha256:7758e8f14867fbea323e1f1bf401f02d0a59eebeb4959595603d5ffc1b3b9ee3",
    "arvo-v1-39083": "sha256:de055b216af36459bcd6d8ce221bea2f4621414e40c02d3135cae715d3c01a62",
    "arvo-v1-46883": "sha256:a8678e4e4c118cfb8f3f3c0d9d7e948ee2436df75212e5da3fc44841ac5dbbc7",
    "arvo-v1-55820": "sha256:8ea09fef5642662195f8f18acbfcf3435bc59855063f691ea03f4008c0273595",
    "arvo-v1-42475442": "sha256:e6bf94defe65100032cec6934d4e71d2a48d04cc737e28a858e1de9eee4e52c3",
    "arvo-v1-42480815": "sha256:69ce5140aa1bd138c71a798dee1958f1950ea3677d54517b4dc62103890dd376",
    "arvo-v1-42483934": "sha256:9c1878c5e204ee37cc33c6ce58ef6f005bef3e8ea32beeb40e9a654bacfb0c88",
    "arvo-v1-42488351": "sha256:8d7c85d104d6d2e1d968d2d5b1929108bca53bcb474c13035659fcf2cefee5e9",
    "arvo-v1-42493692": "sha256:72d3a8fbc6801dcaed3ade4c2ba024ae4b459104d1d5febf1e0668e914015f1d",
    "arvo-v1-42503090": "sha256:e27df41303f04c4931b3707ced6f0f6d28e012a6c7adad3a5862ae757c427a3f",
    "arvo-v1-42515690": "sha256:95176dfa08722ce88188de97803fbb87a2a4eafd7a9872a1fd1337ca5fd02316",
    "arvo-v1-42522636": "sha256:5bd25658dfbd7ae7f08a0ae26fa1d775e25e8a97b12e52aabe77b1f9cde95c82",
    "arvo-v1-42532755": "sha256:6b4f8eed0080ca94b96705a11c9eb893d540728562a2bf3d4d93f158a07b2ef1",
    "arvo-v1-42540213": "sha256:f4b2bd75f4de7d489577d6b7aea1e5e92ed2cb6dae0a03933e8f3a43aec37f36",
    "arvo-v1-1065": "sha256:3deb5031142e755b917b9b562c0d801ff9de3b5bb9e98ce1da52bd968becd01a",
}

OUT = Path(__file__).parent / "out"


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "agentleak"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode()


def trailing_int(s) -> int:
    return int(re.search(r"(\d+)$", str(s)).group(1))


def hypergeom(N: int, K: int, n: int, observed: int) -> dict:
    """Overlap expected if n items are drawn at random from a pool of N that contains K benchmark items."""
    mean = n * K / N
    var = n * (K / N) * (1 - K / N) * (N - n) / (N - 1)
    denom = math.comb(N, n)
    p_ge = sum(math.comb(K, k) * math.comb(N - K, n - k) for k in range(observed, min(K, n) + 1)) / denom
    return {"pool_N": N, "benchmark_in_pool_K": K, "sample_n": n, "expected": round(mean, 1),
            "sd": round(math.sqrt(var), 1), "observed": observed, "z": round((observed - mean) / math.sqrt(var), 2),
            "p_ge_observed": round(p_ge, 4)}


def load_mimo():
    path = hf_hub_download(MIMO_REPO, "cyber.parquet", repo_type="dataset", revision=MIMO_REV)
    rows = pq.read_table(path).to_pylist()
    tasks = []
    for r in rows:
        iid = r["extra_info"]["instance_id"]
        spec = r["prompt"][0]["content"] if r["prompt"] else ""
        m = re.search(r"in function `([^`]*)` in file `([^`]*)`", spec)
        t = re.search(r"Sanitizer: (.+?) in function", spec)
        text = json.loads(r["extra_info"]["instance_json"]).get("problem_statement") or spec
        tasks.append({"instance_id": iid, "num": trailing_int(iid), "spec": spec, "text": text,
                      "type": t.group(1).strip() if t else "",
                      "function": m.group(1) if m else "", "file": m.group(2) if m else ""})
    return tasks


def load_cybergym(rev: str):
    ds = load_dataset(CYBERGYM_REPO, split="tasks", revision=rev)
    return [{"task_id": r["task_id"], "num": trailing_int(r["task_id"]), "project": r["project_name"],
             "description": r["vulnerability_description"]} for r in ds]


def load_mapping() -> dict:
    old2new = {}
    for row in csv.reader(io.StringIO(fetch(ARVO_MAPPING))):
        if len(row) >= 2 and row[0].strip().isdigit() and row[1].strip().isdigit():
            old2new[int(row[0])] = int(row[1])
    return old2new


def load_v1_pool() -> set:
    tree = json.loads(fetch(ARVO_V1_META_TREE))
    assert not tree.get("truncated"), "ARVO v1 meta tree truncated"
    return {trailing_int(Path(t["path"]).stem) for t in tree["tree"] if re.search(r"\d", t["path"])}


HARNESS_FUNCS = {"LLVMFuzzerInitialize", "LLVMFuzzerTestOneInput"}

POC_LIKE = re.compile(r"(^|/)[^/]*(poc|crash|testcase|repro|exploit)[^/]*$", re.I)


def registry_get(path: str, token: str, accept: str = ""):
    headers = {"Authorization": f"Bearer {token}", "User-Agent": "agentleak"}
    if accept:
        headers["Accept"] = accept
    url = f"https://registry-1.docker.io/v2/{IMAGE_REPO}/{path}"
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=600)


def check_image(tag: str, digest: str) -> dict:
    """List the files in one image's task-specific layers, streamed from the registry: no Docker daemon,
    nothing extracted. The layer that only unpacks /data into place is recorded but not listed."""
    with urllib.request.urlopen("https://auth.docker.io/token?service=registry.docker.io"
                                f"&scope=repository:{IMAGE_REPO}:pull", timeout=60) as r:
        token = json.load(r)["token"]
    accept = "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"
    with registry_get(f"manifests/{digest}", token, accept) as r:
        manifest = json.load(r)
    with registry_get(f"blobs/{manifest['config']['digest']}", token) as r:
        history = [h for h in json.load(r)["history"] if not h.get("empty_layer")]
    # Task steps start at the last `WORKDIR /home/agent`; the entrypoint.sh variant has none and starts at `COPY server.py`.
    marks = [i for i, h in enumerate(history) if (h.get("created_by") or "").startswith("WORKDIR /home/agent")]
    start = max(marks) if marks else min(i for i, h in enumerate(history) if "COPY server.py" in (h.get("created_by") or ""))
    task_steps = history[start:]
    # Align from the end: the shared base's history is not 1:1 with its layers (39 layers, 36 non-empty entries).
    task_layers = manifest["layers"][-len(task_steps):]
    steps, paths, server = [], [], None
    for h, layer in zip(task_steps, task_layers):
        step = h.get("created_by") or ""
        if "tar xzf /data/repo-vul.tar.gz" in step:
            steps.append({"step": step, "listed": False})
            continue
        names = []
        with registry_get(f"blobs/{layer['digest']}", token) as r, tarfile.open(fileobj=r, mode="r|gz") as tf:
            for ti in tf:
                names.append(ti.name)
                if ti.name == "root/server.py" and ti.isfile():  # a later layer replaces it; the last copy wins
                    server = tf.extractfile(ti).read()
        steps.append({"step": step, "listed": True, "files": len(names)})
        paths += names
    # The in-image grader: which /root paths does it name, and does it ever use the fixed binary?
    server_text = server.decode("utf-8", "replace") if server is not None else ""
    return {"tag": tag, "digest": digest, "task_steps": steps,
            "data_context": sorted({"/".join(p.split("/")[:2]) for p in paths if p.startswith("data/")}),
            "poc_like_paths": [p for p in paths if POC_LIKE.search(p)],
            "expected_crash_file_in_image": any(p.endswith("expected_func.json") for p in paths),
            "server_py": None if server is None else {
                "sha256": hashlib.sha256(server).hexdigest(),
                "root_paths_named": sorted(set(re.findall(r"/root/[\w.-]+", server_text))),
                "mentions_fix_binary": "fix_binary" in server_text}}


def image_config(digest: str) -> dict:
    """The published config of one image (manifest and config blob only, no layers)."""
    with urllib.request.urlopen("https://auth.docker.io/token?service=registry.docker.io"
                                f"&scope=repository:{IMAGE_REPO}:pull", timeout=60) as r:
        token = json.load(r)["token"]
    accept = "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"
    with registry_get(f"manifests/{digest}", token, accept) as r:
        manifest = json.load(r)
    with registry_get(f"blobs/{manifest['config']['digest']}", token) as r:
        cfg = json.load(r).get("config") or {}
    return {k: cfg.get(k) for k in ("User", "Entrypoint", "Cmd", "WorkingDir")}


# Results for a digest-pinned image cannot change, so they are cached by digest. Bump the version whenever
# check_image's or image_config's output changes.
IMAGE_CACHE = Path.home() / ".cache" / "agentleak" / "images"
IMAGE_CACHE_VERSION = 1


def cached(kind: str, digest: str, compute) -> dict:
    path = IMAGE_CACHE / f"v{IMAGE_CACHE_VERSION}_{kind}_{digest.replace(':', '_')}.json"
    if path.exists():
        return json.loads(path.read_text())
    result = compute()
    IMAGE_CACHE.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result))
    return result


HUB_TAG_IMAGES = "https://hub.docker.com/v2/repositories/{repo}/tags/{tag}/images"


def image_build_steps(tag: str) -> dict:
    """One tag's build instructions from the Docker Hub web API (not the registry, so no pulls are used)."""
    for attempt in range(6):
        try:
            data = json.loads(fetch(HUB_TAG_IMAGES.format(repo=IMAGE_REPO, tag=tag)))
            break
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503) or attempt == 5:
                raise
            time.sleep(10 * (attempt + 1))
    image = data[0] if isinstance(data, list) else data
    steps = [layer.get("instruction") or "" for layer in image.get("layers", [])]
    return {"digest": image.get("digest"), "fix_binary": any("/data/fix_binary" in st for st in steps),
            "entrypoint_variant": any("entrypoint.sh" in st for st in steps),
            "user_step": any(st.strip().upper().startswith("USER ") for st in steps)}


def arvo_file(kind: str, old_id: int, ext: str):
    """archive_data/<kind>/<old_id>.<ext> from ARVO-Meta at the pinned commit (cached locally); None if absent."""
    path = ARVO_META_CACHE / kind / f"{old_id}.{ext}"
    if path.exists():
        return path.read_text(encoding="utf-8")
    req = urllib.request.Request(f"{ARVO_META_RAW}/{kind}/{old_id}.{ext}", headers={"User-Agent": "agentleak"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            text = r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return text


def fix_commits(meta: dict) -> set:
    """Full commit SHAs named as the fix in an ARVO metadata record."""
    raw = meta.get("fix_commit") or meta.get("fix") or ""
    return set(re.findall(r"[0-9a-f]{40}", json.dumps(raw).lower()))


def crash_signature(meta: dict):
    """ClusterFuzz's grouping key from the original report: (project, crash type, crash state frames)."""
    content = (((meta.get("report") or {}).get("comments") or [{}])[0].get("content")) or ""
    state = re.search(r"Crash State:\n((?:  .*\n)+)", content)
    frames = tuple(f.strip() for f in state.group(1).splitlines() if f.strip()) if state else ()
    return (meta.get("project"), meta.get("crash_type"), frames) if frames else None


def spec_vs_report(task: dict, frames: list, report_type: str) -> str:
    """Case-1 crash check: does a MiMo spec name the crashing function and type of a sanitizer report?"""
    if task["function"] in HARNESS_FUNCS:
        return "names_fuzzer_entry_point"
    fn = bool(task["function"]) and any(f" in {task['function']} " in f for f in frames)
    if fn and task["type"] and report_type and task["type"].lower() == report_type.lower():
        return "function_and_type"
    if fn:
        return "function_only"
    if task["file"] and any(task["file"].split("/", 1)[-1] in f for f in frames):
        return "file_only"
    return "no_match"


# Text check: the word n-gram test used by common decontamination filters (lowercased \w+ words).
NGRAM_SIZES = (13, 8)


def words(s: str) -> list:
    return re.findall(r"\w+", s.lower())


def ngrams(ws: list, n: int) -> set:
    return {tuple(ws[i:i + n]) for i in range(len(ws) - n + 1)}


def drop_bracketed(s: str, open_: str, close: str) -> str:
    out, depth = [], 0
    for ch in s:
        if ch == open_:
            depth += 1
        elif ch == close and depth:
            depth -= 1
        elif not depth:
            out.append(ch)
    return "".join(out)


def bare_function_name(f: str) -> str:
    """'void ns::Cls::method<ns::T>(int) const' -> 'method'. Template arguments and argument lists are dropped
    first; a lambda or operator() resolves to its enclosing function."""
    tokens = drop_bracketed(drop_bracketed(f, "<", ">"), "(", ")").replace(" const", "").split()
    parts = [p for p in (tokens[-1].split("::") if tokens else [])
             if p and "lambda" not in p and not p.startswith(("operator", "'", "{"))]
    return parts[-1] if parts else ""


def longest_common_run(a: list, b: list) -> int:
    """Length of the longest run of consecutive words that appears in both texts."""
    n = 0
    while ngrams(a, n + 1) & ngrams(b, n + 1):
        n += 1
    return n


def crash_type(error_txt: str) -> str:
    """Bug type from the sanitizer report, e.g. 'heap-buffer-overflow', 'SEGV', 'double-free'.
    The SUMMARY line carries the canonical name; fall back to the headline."""
    m = (re.search(r"SUMMARY: \w+Sanitizer: ([\w-]+)", error_txt)
         or re.search(r"(?:ERROR|WARNING): \w+Sanitizer: (?:attempting )?([\w-]+)", error_txt))
    return m.group(1) if m else ""


def first_stack(error_txt: str) -> list:
    """Frames (line text) of the first stack trace in a sanitizer report."""
    frames, started = [], False
    for line in error_txt.splitlines():
        if re.match(r"\s*#\d+ 0x[0-9a-f]+ in ", line):
            frames.append(line.strip())
            started = True
        elif started:
            break
    return frames


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--signatures", action="store_true",
                    help="download CyberGym error.txt for overlapping tasks and compare crash frames")
    ap.add_argument("--images", action="store_true",
                    help=f"stream the task layers of {len(IMAGE_SAMPLE)} pinned cyber images from Docker Hub and look for PoCs "
                         f"(one image at a time; uses {len(IMAGE_SAMPLE)} of the anonymous pull quota)")
    ap.add_argument("--build-steps", action="store_true",
                    help="read the build steps of all cyber images from the Docker Hub web API (no pulls; ~5 min)")
    ap.add_argument("--related-bugs", action="store_true",
                    help="find CyberGym tasks that share a fix commit or ClusterFuzz crash signature with a MiMo bug "
                         "under a different ID (fetches ARVO-Meta records; cached)")
    ap.add_argument("--secbench", action="store_true",
                    help="also compare the MiMo cyber set with SEC-bench by OSS-Fuzz ID and fix patch")
    args = ap.parse_args()
    OUT.mkdir(exist_ok=True)

    cg_rev = CYBERGYM_REV or HfApi().dataset_info(CYBERGYM_REPO).sha
    mimo, cg = load_mimo(), load_cybergym(cg_rev)
    old2new, v1 = load_mapping(), load_v1_pool()
    canon = lambda i: old2new.get(i, i)  # old Monorail ID -> new tracker ID; new IDs map to themselves

    # 1. Exact numeric matches (prefix ignored: MiMo writes arvo_N for new-tracker IDs, CyberGym oss-fuzz:N).
    exact = sorted({t["num"] for t in mimo} & {t["num"] for t in cg})
    exact_same_prefix = [n for n in exact if any(t["num"] == n and t["task_id"].startswith("arvo") for t in cg)]

    # 2. Translated matches on canonical bug IDs.
    mimo_by_bug, cg_by_bug = defaultdict(list), defaultdict(list)
    for t in mimo:
        mimo_by_bug[canon(t["num"])].append(t)
    for t in cg:
        cg_by_bug[canon(t["num"])].append(t)
    shared = sorted(set(mimo_by_bug) & set(cg_by_bug))
    cg_hit = [t for b in shared for t in cg_by_bug[b]]
    mimo_hit = [t for b in shared for t in mimo_by_bug[b]]
    dups = {b: ts for b, ts in mimo_by_bug.items() if len(ts) > 1}

    # 3. Chance baselines on the ARVO v1 pool (the first ARVO release), which all CyberGym ARVO tasks come from.
    v1_canon = {canon(i) for i in v1}
    assert len(v1_canon) == len(v1), "ARVO mapping collapses v1 IDs"
    cg_arvo_old = {t["num"] for t in cg if t["task_id"].startswith("arvo")}
    assert cg_arvo_old <= v1, "CyberGym ARVO task outside the ARVO v1 pool"
    mimo_old_in_pool = {t["num"] for t in mimo if t["num"] in v1}
    base_exact = hypergeom(len(v1), len(cg_arvo_old), len(mimo_old_in_pool), len(mimo_old_in_pool & cg_arvo_old))
    cg_arvo_canon = {canon(n) for n in cg_arvo_old}
    mimo_bugs_in_pool = {b for b in mimo_by_bug if b in v1_canon}
    base_bugs = hypergeom(len(v1_canon), len(cg_arvo_canon), len(mimo_bugs_in_pool),
                          len(mimo_bugs_in_pool & cg_arvo_canon))
    # The same draws within each OSS-Fuzz project (as in case 2), so that both sets favouring the same projects
    # does not count as excess overlap. Projects come from ARVO's tracker metadata, keyed by new tracker ID.
    from secbench_cybergym import load_arvo_projects, stratified_hypergeom
    arvo_project = load_arvo_projects()

    def within_project(pool: set, bench: set, sample: set, new_id) -> dict:
        strata = defaultdict(lambda: [0, 0, 0])
        for b in pool:
            s = strata[arvo_project.get(new_id(b), "unknown")]
            s[0] += 1
            s[1] += b in bench
            s[2] += b in sample
        return stratified_hypergeom([tuple(v) for v in strata.values()], len(sample & bench))
    base_within_project = {
        "exact_ids_old_scheme": within_project(v1, cg_arvo_old, mimo_old_in_pool, canon),
        "unique_bugs_translated": within_project(v1_canon, cg_arvo_canon, mimo_bugs_in_pool, lambda b: b),
        "pool_bugs_without_project": sum(b not in arvo_project for b in v1_canon),
        "projects_source": "ARVO NewTracker/metadata.jsonl @ bc2a373c"}

    # MiMo tasks whose spec names a fuzzer entry point instead of a crash site in project code
    # (e.g. "ABRT in function `LLVMFuzzerInitialize`"). These look like environment defects.
    suspect = [t for t in mimo if t["function"] in HARNESS_FUNCS]

    # 4. Optional corroboration that matched IDs are the same crash. The identity itself comes from
    #    the ID mapping; here we check MiMo's spec against CyberGym's ground-truth sanitizer report.
    #    Control: MiMo specs of *other* overlapping bugs from the same project, to see how often
    #    the check passes by accident.
    sig, error_txt = None, {}
    if args.signatures:
        reports = {}
        for b in shared:
            kind, n = cg_by_bug[b][0]["task_id"].split(":")
            txt = Path(hf_hub_download(CYBERGYM_REPO, f"data/{kind}/{n}/error.txt",
                                       repo_type="dataset", revision=cg_rev)).read_text(errors="replace")
            reports[b] = (first_stack(txt), crash_type(txt))
            error_txt[b] = txt

        def grade(b, m):
            frames, cg_type = reports[b]
            if m["function"] in HARNESS_FUNCS:
                return "names_fuzzer_entry_point"
            fn = bool(m["function"]) and any(f" in {m['function']} " in f for f in frames)
            if fn and m["type"] and cg_type and m["type"].lower() == cg_type.lower():
                return "function_and_type"
            if fn:
                return "function_only"
            if m["file"] and any(m["file"].split("/", 1)[-1] in f for f in frames):
                return "file_only"
            return "no_match"

        order = ["function_and_type", "function_only", "file_only", "names_fuzzer_entry_point", "no_match"]
        best = {b: min((grade(b, m) for m in mimo_by_bug[b]), key=order.index) for b in shared}
        project = {b: cg_by_bug[b][0]["project"] for b in shared}
        control = [grade(b, m) for b in shared for b2 in shared
                   if b2 != b and project[b2] == project[b] for m in mimo_by_bug[b2]]
        cc = Counter(control)
        sig = {"checked": len(shared), "result": dict(Counter(best.values())),
               "not_function_and_type": [{"bug": b, "cybergym": cg_by_bug[b][0]["task_id"], "grade": g,
                                          "cybergym_type": reports[b][1],
                                          "mimo_spec": sorted({m["spec"] for m in mimo_by_bug[b]})}
                                         for b, g in best.items() if g != "function_and_type"],
               "control_same_project_other_bug": {"pairs": len(control), **dict(cc),
                                                  "function_and_type_rate": round(cc["function_and_type"] / max(len(control), 1), 3)}}

    # 5. Would a text-based decontamination filter have caught the overlap? Compare MiMo task text with
    #    CyberGym's level-1 task text (vulnerability_description) by word n-grams, as common filters do.
    #    (a) Filter view: a MiMo task is flagged if it shares any n-gram with any CyberGym description.
    #    (b) Pair view: longest run of shared words between each overlapping bug's CyberGym description and
    #        its MiMo task text; with --signatures also against CyberGym's sanitizer report (error.txt).
    cg_words = {t["task_id"]: words(t["description"]) for t in cg}
    mimo_words = {t["instance_id"]: words(t["text"]) for t in mimo}
    overlap_ids = {t["instance_id"] for t in mimo_hit}
    flagged = {}
    for n in NGRAM_SIZES:
        gram_to_cg = defaultdict(set)
        for tid, ws in cg_words.items():
            for g in ngrams(ws, n):
                gram_to_cg[g].add(tid)
        matches = {t["instance_id"]: set().union(*(gram_to_cg.get(g, set()) for g in ngrams(mimo_words[t["instance_id"]], n)))
                   for t in mimo}
        hit = {i for i, m in matches.items() if m}
        own = {t["instance_id"] for t in mimo_hit
               if matches[t["instance_id"]] & {c["task_id"] for c in cg_by_bug[canon(t["num"])]}}
        flagged[n] = {"overlap_tasks_flagged": len(hit & overlap_ids), "overlap_tasks_flagged_by_own_cybergym_task": len(own),
                      "overlap_tasks": len(overlap_ids),
                      "other_tasks_flagged": len(hit - overlap_ids), "other_tasks": len(mimo) - len(overlap_ids),
                      "cybergym_tasks_matched": sorted(set().union(*matches.values()))}
    pair_rows = []
    for b in shared:
        c = cg_by_bug[b][0]
        run_desc = max(longest_common_run(mimo_words[m["instance_id"]], cg_words[c["task_id"]]) for m in mimo_by_bug[b])
        run_err = (max(longest_common_run(mimo_words[m["instance_id"]], words(error_txt[b])) for m in mimo_by_bug[b])
                   if b in error_txt else None)
        names = {bare_function_name(m["function"]) for m in mimo_by_bug[b] if m["function"] not in HARNESS_FUNCS} - {""}
        names_fn = (any(re.search(rf"\b{re.escape(n)}\b", c["description"]) for n in names) if names else None)
        pair_rows.append({"canonical_bug_id": b, "cybergym_task_id": c["task_id"],
                          "cybergym_description_words": len(cg_words[c["task_id"]]),
                          "longest_shared_run_vs_description": run_desc, "longest_shared_run_vs_error_txt": run_err,
                          "description_names_mimo_target_function": names_fn})
    runs_desc = sorted(r["longest_shared_run_vs_description"] for r in pair_rows)
    runs_err = sorted(r["longest_shared_run_vs_error_txt"] for r in pair_rows if r["longest_shared_run_vs_error_txt"] is not None)
    text_check = {
        "benchmark_text": "CyberGym vulnerability_description (level-1 task text)",
        "training_text": "MiMo problem_statement (full task prompt)",
        "tokenization": "lowercase \\w+ words",
        "filter_view": {str(n): v for n, v in flagged.items()},
        "pair_view": {
            "pairs": len(pair_rows),
            "cybergym_descriptions_shorter_than_13_words": sum(r["cybergym_description_words"] < 13 for r in pair_rows),
            "description_names_mimo_target_function": sum(bool(r["description_names_mimo_target_function"]) for r in pair_rows),
            "pairs_with_a_mimo_target_function": sum(r["description_names_mimo_target_function"] is not None for r in pair_rows),
            "longest_shared_run_vs_description": {"max": runs_desc[-1], "median": runs_desc[len(runs_desc) // 2],
                                                  **{f"pairs_ge_{n}": sum(x >= n for x in runs_desc) for n in NGRAM_SIZES}},
            "longest_shared_run_vs_error_txt": ({"max": runs_err[-1], "median": runs_err[len(runs_err) // 2],
                                                 **{f"pairs_ge_{n}": sum(x >= n for x in runs_err) for n in NGRAM_SIZES}}
                                                if runs_err else None)},
    }

    # 6. Optional: do the task images ship a reference PoC? Lists the task-specific layers of a pinned sample.
    image_check, images = None, []
    if args.images:
        for tag, digest in IMAGE_SAMPLE.items():
            images.append({**cached("listing", digest, lambda: check_image(tag, digest)),
                           "config": cached("config", digest, lambda: image_config(digest))})
            print(f"image {tag}: data={images[-1]['data_context']} poc_like={len(images[-1]['poc_like_paths'])}", flush=True)
        (OUT / "image_check.json").write_text(json.dumps(images, indent=2))
        unlisted = Counter(re.sub(r"\s+", " ", s["step"]) for im in images for s in im["task_steps"] if not s["listed"])
        image_check = {"repo": IMAGE_REPO, "images_checked": len(images),
                       "images_with_poc_like_paths": sum(bool(im["poc_like_paths"]) for im in images),
                       "images_with_expected_crash_file": sum(im["expected_crash_file_in_image"] for im in images),
                       "images_with_fix_binary": sum("data/fix_binary" in im["data_context"] for im in images),
                       "config_user_set": sum(bool(im["config"]["User"]) for im in images),
                       "config_entrypoint_set": sum(bool(im["config"]["Entrypoint"]) for im in images),
                       "data_context_variants": dict(Counter(" ".join(im["data_context"]) for im in images)),
                       "server_py": {"images_with_it": sum(im["server_py"] is not None for im in images),
                                     "distinct_versions": len({im["server_py"]["sha256"] for im in images if im["server_py"]}),
                                     "mentions_fix_binary": sum(bool(im["server_py"] and im["server_py"]["mentions_fix_binary"])
                                                                for im in images),
                                     "root_paths_named": sorted({p for im in images if im["server_py"]
                                                                 for p in im["server_py"]["root_paths_named"]})},
                       "unlisted_unpack_step_variants": dict(unlisted)}

    # 7. Optional: which images copy a fixed binary? Build steps of every cyber image, from the Docker Hub web API.
    build_steps, build_rows = None, []
    if args.build_steps:
        read_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cg_kind = {t["num"]: t["task_id"].split(":")[0] for t in cg}
        rows = []
        for t in mimo:
            tag = f"arvo-v1-{t['num']}"
            info = image_build_steps(tag)
            category = (f"same ID as a CyberGym {cg_kind[t['num']]}: task" if t["num"] in cg_kind
                        else "same CyberGym bug under the other ID" if canon(t["num"]) in cg_by_bug
                        else "not in CyberGym, old ID" if t["num"] < 10**6 else "not in CyberGym, new ID")
            rows.append({"mimo_instance_id": t["instance_id"], "tag": tag, "digest": info["digest"], "category": category,
                         "fix_binary": info["fix_binary"], "entrypoint_variant": info["entrypoint_variant"],
                         "user_step": info["user_step"]})
            time.sleep(0.25)
        build_rows = rows
        with open(OUT / "image_build_steps.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        by_cat = defaultdict(Counter)
        for r in rows:
            by_cat[r["category"]][r["fix_binary"]] += 1
        build_steps = {"source": HUB_TAG_IMAGES.format(repo=IMAGE_REPO, tag="<tag>"), "images": len(rows),
                       "fix_binary_by_category": {c: {"with": n[True], "without": n[False]} for c, n in sorted(by_cat.items())},
                       "read_at": read_at,
                       "entrypoint_variant": {"images": sum(r["entrypoint_variant"] for r in rows),
                                              "with_fix_binary": sum(r["entrypoint_variant"] and r["fix_binary"] for r in rows)},
                       "images_with_user_step": sum(r["user_step"] for r in rows)}

    # 8. Optional: CyberGym tasks related to a MiMo bug that is a separate OSS-Fuzz issue. Using ARVO's per-bug
    #    records, a MiMo bug and a CyberGym task (not one of the shared bugs) are related if their fixes name the same
    #    commit, or if ClusterFuzz's crash signature (project, crash type, crash state) is identical. Only bugs in
    #    ARVO's first release have records. A signature carried by 3 or more of the records compared is reported as
    #    shared, because such signatures (e.g. a generic sink) say little about a specific bug.
    related, related_rows, secbench_rows = None, [], []
    new2old = {v: k for k, v in old2new.items()}
    old_of = lambda b: new2old.get(b, b)
    if args.related_bugs:
        mimo_pool = sorted(b for b in mimo_by_bug if old_of(b) in v1)
        cg_arvo = sorted({t["num"] for t in cg if t["task_id"].startswith("arvo")})
        cg_only = [o for o in cg_arvo if canon(o) not in mimo_by_bug]
        meta = {}
        for o in sorted({old_of(b) for b in mimo_pool} | set(cg_arvo)):
            text = arvo_file("meta", o, "json")
            meta[o] = json.loads(text) if text else None
        sig_count = Counter(crash_signature(m) for m in meta.values() if m and crash_signature(m))
        by_fix, by_sig = defaultdict(set), defaultdict(set)
        for o in cg_only:
            if meta[o]:
                for sha in fix_commits(meta[o]):
                    by_fix[sha].add(o)
                if crash_signature(meta[o]):
                    by_sig[crash_signature(meta[o])].add(o)
        order = ["function_and_type", "function_only", "file_only", "names_fuzzer_entry_point", "no_match"]
        rows = []
        for b in mimo_pool:
            m = meta[old_of(b)]
            if not m:
                continue
            bug_sig = crash_signature(m)
            fix_hits = set().union(*(by_fix.get(sha, set()) for sha in fix_commits(m)))
            sig_hits = by_sig.get(bug_sig, set()) if bug_sig else set()
            for o in sorted(fix_hits | sig_hits):
                txt = Path(hf_hub_download(CYBERGYM_REPO, f"data/arvo/{o}/error.txt", repo_type="dataset",
                                           revision=cg_rev)).read_text(errors="replace")
                checks = [spec_vs_report(t, first_stack(txt), crash_type(txt)) for t in mimo_by_bug[b]]
                rows.append({"mimo_bug": b, "mimo_instance_ids": ";".join(t["instance_id"] for t in mimo_by_bug[b]),
                             "mimo_bug_is_cybergym_task": b in cg_by_bug,
                             "cybergym_task_id": f"arvo:{o}", "project": meta[o].get("project"),
                             "same_fix_commit": o in fix_hits, "same_crash_signature": o in sig_hits,
                             "records_with_this_signature": sig_count[bug_sig] if o in sig_hits else "",
                             "different_fix_commits": (not (fix_commits(m) & fix_commits(meta[o]))
                                                       if fix_commits(m) and fix_commits(meta[o]) else ""),
                             "crash_check": min(checks, key=order.index)})
        with open(OUT / "related_bugs.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        task_kind = {}
        for r in rows:  # per CyberGym task: fix commit, a signature specific to the pair, or a shared signature
            kind = ("same fix commit" if r["same_fix_commit"]
                    else "signature carried by 2 records" if r["records_with_this_signature"] == 2
                    else "signature carried by 3 or more records")
            if task_kind.get(r["cybergym_task_id"]) != "same fix commit":
                task_kind[r["cybergym_task_id"]] = kind
        sig_rows = [r for r in rows if r["same_crash_signature"]]
        related_rows = rows
        related = {"source": f"n132/ARVO-Meta@{ARVO_META_COMMIT} archive_data/meta",
                   "mimo_bugs_with_record": sum(1 for b in mimo_pool if meta[old_of(b)]),
                   "mimo_bugs_without_record": len(mimo_by_bug) - sum(1 for b in mimo_pool if meta[old_of(b)]),
                   "cybergym_arvo_tasks_not_shared": len(cg_only),
                   "pairs": len(rows), "cybergym_tasks": len(task_kind), "mimo_bugs": len({r["mimo_bug"] for r in rows}),
                   "cybergym_tasks_by_evidence": dict(Counter(task_kind.values())),
                   "cybergym_tasks_whose_mimo_match_is_not_a_cybergym_task": len(
                       {r["cybergym_task_id"] for r in rows if not r["mimo_bug_is_cybergym_task"]}),
                   "signature_pairs_with_different_fix_commits": f"{sum(r['different_fix_commits'] for r in sig_rows)} of {len(sig_rows)}",
                   "crash_check_pairs_by_task_evidence": {
                       k: dict(Counter(r["crash_check"] for r in rows if task_kind[r["cybergym_task_id"]] == k))
                       for k in set(task_kind.values())}}

    # 9. Optional: MiMo cyber vs SEC-bench (case 2's benchmark). OSS-Fuzz ID join for SEC-bench's oss split, plus a
    #    same-fix join (git blob pairs, as in case 2) between SEC-bench's patches and ARVO's fix patches for MiMo bugs.
    secbench = None
    if args.secbench:
        from secbench_cybergym import SECBENCH_REPO, SECBENCH_REV, load_secbench, patch_blobs, same_fix, top_project_frame
        sb = load_secbench()
        mimo_nums = {t["num"] for t in mimo}
        id_plain = {r["instance_id"]: canon(r["ossfuzz_id"]) for r in sb if r["split"] == "oss" and r["ossfuzz_id"] in mimo_nums}
        id_trans = {r["instance_id"]: canon(r["ossfuzz_id"]) for r in sb if r["split"] == "oss" and canon(r["ossfuzz_id"]) in mimo_by_bug}
        pool_bugs = sorted(b for b in mimo_by_bug if old_of(b) in v1)
        mimo_patch = {b: patch_blobs(arvo_file("patches", old_of(b), "diff") or "") for b in pool_bugs}
        by_path = defaultdict(set)
        for b, blobs in mimo_patch.items():
            for path in blobs:
                by_path[path].add(b)
        fix_match = defaultdict(set)
        for r in sb:
            sbp = patch_blobs(r["patch"])
            for b in set().union(*(by_path.get(path, set()) for path in sbp)):
                if same_fix(sbp, mimo_patch[b]):
                    fix_match[r["instance_id"]].add(b)
        sb_by_id = {r["instance_id"]: r for r in sb}
        pairs = sorted({(i, b) for i, b in id_trans.items()} | {(i, b) for i, bs in fix_match.items() for b in bs})
        rows = []
        for i, b in pairs:
            rep = sb_by_id[i]["sanitizer_report"] or ""
            frames, rtype = first_stack(rep), crash_type(rep)
            order = ["function_and_type", "function_only", "file_only", "names_fuzzer_entry_point", "no_match"]
            rows.append({"secbench_instance_id": i, "secbench_split": sb_by_id[i]["split"], "mimo_bug": b,
                         "mimo_instance_ids": ";".join(t["instance_id"] for t in mimo_by_bug[b]),
                         "id_match": ("plain" if id_plain.get(i) == b else "translated") if id_trans.get(i) == b else "",
                         "same_fix": b in fix_match.get(i, set()), "bug_in_cybergym": b in cg_by_bug,
                         "crash_check": min((spec_vs_report(t, frames, rtype) for t in mimo_by_bug[b]), key=order.index),
                         "secbench_report_symbolized": bool(top_project_frame(rep))})
        secbench_rows = rows
        with open(OUT / "mimo_secbench.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["secbench_instance_id"])
            w.writeheader()
            w.writerows(rows)
        # Chance baselines, as in cases 1 and 2: both sets' bugs in ARVO's first release, drawn uniformly (or within
        # each OSS-Fuzz project) from that pool.
        from secbench_cybergym import load_arvo_projects, stratified_hypergeom
        v1_canon = {canon(i) for i in v1}
        mimo_in_pool = {b for b in mimo_by_bug if b in v1_canon}
        sb_in_pool = {canon(r["ossfuzz_id"]) for r in sb if r["split"] == "oss" and canon(r["ossfuzz_id"]) in v1_canon}
        shared_in_pool = len(mimo_in_pool & sb_in_pool)
        arvo_project = load_arvo_projects()
        strata = defaultdict(lambda: [0, 0, 0])
        for b in v1_canon:
            proj = arvo_project.get(b, "unknown")
            strata[proj][0] += 1
            strata[proj][1] += b in sb_in_pool
            strata[proj][2] += b in mimo_in_pool
        secbench = {"source": f"{SECBENCH_REPO}@{SECBENCH_REV}",
                    "chance_baseline_oss": {
                        "uniform": hypergeom(len(v1_canon), len(sb_in_pool), len(mimo_in_pool), shared_in_pool),
                        "within_project": stratified_hypergeom([tuple(v) for v in strata.values()], shared_in_pool),
                        "id_overlaps_outside_pool": len(set(id_trans.values()) - v1_canon)},
                    "id_join_oss": {"plain": len(id_plain), "translated": len(id_trans)},
                    "same_fix_instances": dict(Counter(sb_by_id[i]["split"] for i in fix_match)),
                    "oss_id_overlaps_with_same_fix": sum(b in fix_match.get(i, set()) for i, b in id_trans.items()),
                    # Why a same-issue pair has no confirmed same fix
                    "oss_id_overlaps_without_same_fix": dict(Counter(
                        "MiMo bug outside ARVO's first release" if old_of(b) not in v1
                        else "no ARVO fix patch, or one without blob IDs" if not mimo_patch.get(b)
                        else "SEC-bench patch without blob IDs" if not patch_blobs(sb_by_id[i]["patch"])
                        else "no file in common" if not set(patch_blobs(sb_by_id[i]["patch"])) & set(mimo_patch[b])
                        else "same files, different blobs" for i, b in id_trans.items() if b not in fix_match.get(i, set()))),
                    "mimo_bugs_with_fix_patch": sum(bool(v) for v in mimo_patch.values()),
                    "instances": dict(Counter(sb_by_id[i]["split"] for i in {r["secbench_instance_id"] for r in rows})),
                    "pairs": len(rows),
                    "instances_by_match": {"same issue (ID)": len(id_trans),
                                           "fix only": len({r["secbench_instance_id"] for r in rows} - set(id_trans))},
                    "fix_only_pairs_crash_check": dict(Counter(r["crash_check"] for r in rows if r["secbench_instance_id"] not in id_trans)),
                    "mimo_bugs": len({r["mimo_bug"] for r in rows}),
                    "mimo_bugs_not_in_cybergym": len({r["mimo_bug"] for r in rows if not r["bug_in_cybergym"]}),
                    "mimo_tasks": len({t for r in rows for t in r["mimo_instance_ids"].split(";")}),
                    "crash_check": dict(Counter(r["crash_check"] for r in rows)),
                    "crash_check_symbolized_reports_only": dict(Counter(r["crash_check"] for r in rows if r["secbench_report_symbolized"]))}

    # 10. Filtered split: drop bugs that are in CyberGym, keep one task per remaining bug (preferring a
    #    spec that names a real crash site), and drop bugs whose only spec names a fuzzer entry point.
    clean, dropped_suspect = [], 0
    for b, ts in mimo_by_bug.items():  # first-appearance order
        if b in cg_by_bug:
            continue
        good = [t for t in ts if t["function"] not in HARNESS_FUNCS]
        if good:
            clean.append(good[0]["instance_id"])
        else:
            dropped_suspect += len(ts)
    non_cg_tasks = sum(len(ts) for b, ts in mimo_by_bug.items() if b not in cg_by_bug)

    # Outputs
    with open(OUT / "overlap.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["canonical_bug_id", "cybergym_task_ids", "cybergym_project", "mimo_instance_ids", "match_type"])
        for b in shared:
            cts, mts = cg_by_bug[b], mimo_by_bug[b]
            match = "exact" if any(m["num"] == c["num"] for m in mts for c in cts) else "translated"
            w.writerow([b, ";".join(c["task_id"] for c in cts), cts[0]["project"],
                        ";".join(m["instance_id"] for m in mts), match])
    with open(OUT / "mimo_duplicates.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["canonical_bug_id", "mimo_instance_ids", "specs_identical"])
        for b, ts in sorted(dups.items()):
            w.writerow([b, ";".join(t["instance_id"] for t in ts), len({t["spec"] for t in ts}) == 1])
    (OUT / "mimo_cyber_clean_ids.txt").write_text("\n".join(clean) + "\n")
    with open(OUT / "text_overlap.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(pair_rows[0]))
        w.writeheader()
        w.writerows(pair_rows)
    with open(OUT / "mimo_suspect_specs.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["mimo_instance_id", "spec", "bug_in_cybergym"])
        for t in suspect:
            w.writerow([t["instance_id"], t["spec"], canon(t["num"]) in cg_by_bug])

    summary = {
        "sources": {"mimo": f"{MIMO_REPO}@{MIMO_REV} cyber.parquet", "cybergym": f"{CYBERGYM_REPO}@{cg_rev} split=tasks",
                    "arvo_mapping": ARVO_MAPPING, "arvo_v1_pool": ARVO_V1_META_TREE,
                    "arvo_tracker_meta": "n132/ARVO@bc2a373c NewTracker/metadata.jsonl",
                    "arvo_meta": f"n132/ARVO-Meta@{ARVO_META_COMMIT}",
                    "images": IMAGE_SAMPLE if args.images else None},
        "counts": {"mimo_tasks": len(mimo), "mimo_old_scheme_ids": sum(t["num"] < 10**6 for t in mimo),
                   "mimo_unique_issues": len(mimo_by_bug), "mimo_duplicated_issues": len(dups),
                   "mimo_duplicate_pairs_identical_prompt": sum(len({t["spec"] for t in ts}) == 1 for ts in dups.values()),
                   "mimo_suspect_specs": len(suspect), "cybergym_tasks": len(cg),
                   "cybergym_by_kind": dict(Counter(t["task_id"].split(":")[0] for t in cg)),
                   "arvo_v1_pool": len(v1), "mapping_pairs": len(old2new)},
        "overlap": {"exact_same_prefix": len(exact_same_prefix), "exact_any_prefix": len(exact),
                    "translated_cybergym_tasks": len(cg_hit),
                    "translated_cybergym_share": round(len(cg_hit) / len(cg), 4),
                    "translated_mimo_tasks": len(mimo_hit), "translated_unique_bugs": len(shared)},
        "chance_baseline": {"exact_ids_old_scheme": base_exact, "unique_bugs_translated": base_bugs,
                            "within_project": base_within_project},
        "filtered_split": {"kept": len(clean), "removed_cybergym_tasks": len(mimo_hit),
                           "removed_fuzzer_entry_point_only": dropped_suspect,
                           "removed_duplicate_copies": non_cg_tasks - len(clean) - dropped_suspect,
                           # What the split still holds: it is filtered against CyberGym's shared bugs only.
                           "kept_tasks_in_related_bugs": (len(set(clean) & {x for r in related_rows for x in r["mimo_instance_ids"].split(";")})
                                                          if args.related_bugs else None),
                           "kept_tasks_in_mimo_secbench": (len(set(clean) & {x for r in secbench_rows for x in r["mimo_instance_ids"].split(";")})
                                                           if args.secbench else None),
                           "kept_tasks_in_either": (len(set(clean) & {x for r in related_rows + secbench_rows for x in r["mimo_instance_ids"].split(";")})
                                                    if args.related_bugs and args.secbench else None),
                           "kept_tasks_with_fix_binary": (len(set(clean) & {r["mimo_instance_id"] for r in build_rows if r["fix_binary"]})
                                                          if args.build_steps else None)},
        "signature_check": sig,
        "text_check": text_check,
        "image_check": image_check,
        "image_build_steps": build_steps,
        "related_bugs": related,
        "secbench": secbench,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ("counts", "overlap", "chance_baseline", "filtered_split", "text_check")}, indent=2))
    if sig:
        print("signatures:", json.dumps(sig["result"]), "| control:", json.dumps(sig["control_same_project_other_bug"]))


if __name__ == "__main__":
    main()
