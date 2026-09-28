import hashlib
import json
import os
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from loguru import logger
from typesafe_sdk import Choice, Noul, TypeSafeClient

from archscan.graph import Module, ProjectGraph

ROLES = {
    "api_route": "Defines HTTP or RPC endpoints.",
    "data_access": "Reads or writes a database or storage.",
    "business_logic": "Implements the core rules of the application.",
    "config": "Holds settings or constants.",
    "utility": "Generic helpers used by other modules.",
    "ui": "Renders user interface or terminal output.",
}

QUESTIONS = {
    "role": Choice(instructions="What is the main role of this module?", criteria=ROLES),
    "handles_auth": Noul(instructions="Does this module handle authentication or authorization?"),
}

NOUL_THRESHOLD = 0.5
DEFAULT_MODEL = "jev-latest"
WORKERS = 8
CACHE_FILE = "judgments.json"


@dataclass
class Judgment:
    role: str
    handles_auth: float


@dataclass
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _questions_hash() -> str:
    dumped = {name: q.model_dump() for name, q in QUESTIONS.items()}
    return hashlib.sha256(_canonical(dumped).encode()).hexdigest()


def _cache_key(state: dict, model: str) -> str:
    payload = _canonical({"state": state, "model": model, "questions": _questions_hash()})
    return hashlib.sha256(payload.encode()).hexdigest()


def _cache_enabled() -> bool:
    return os.getenv("ARCHSCAN_CACHE") != "0"


def _cache_path() -> Path:
    override = os.getenv("ARCHSCAN_CACHE_DIR")
    base = Path(override) if override else Path.home() / ".cache" / "archscan"
    return base / CACHE_FILE


def _load_cache(path: Path) -> dict[str, dict]:
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            return data
        logger.debug("Ignoring judgment cache {}: not an object", path)
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as error:
        logger.debug("Ignoring judgment cache {}: {}", path, error)
    return {}


def _save_cache(path: Path, entries: dict[str, dict]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".judgments-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(entries, handle)
            os.replace(temp, path)
        except BaseException:
            Path(temp).unlink(missing_ok=True)
            raise
    except OSError as error:
        logger.warning("Could not write judgment cache {}: {}", path, error)


def _state(project: ProjectGraph, module: Module) -> dict:
    return {
        "module": module.name,
        "source": (project.root / module.path).read_text(errors="replace"),
        "imports_internal": sorted(project.graph.successors(module.name)),
        "imports_external": sorted(set(module.external_imports)),
    }


def judge_project(
    project: ProjectGraph,
    model: str = DEFAULT_MODEL,
) -> tuple[dict[str, Judgment], TokenUsage]:
    modules = project.modules()
    total = len(modules)
    usage = TokenUsage()
    lock = threading.Lock()
    local = threading.local()
    clients: list[TypeSafeClient] = []
    results: dict[str, Judgment] = {}
    done = 0

    cache_on = _cache_enabled()
    cache_path = _cache_path()
    cache = _load_cache(cache_path) if cache_on else {}
    new_entries: dict[str, dict] = {}

    def finish(module: Module, judgment: Judgment) -> None:
        nonlocal done
        with lock:
            results[module.name] = judgment
            done += 1
            logger.info("Judged {} ({}/{})", module.name, done, total)

    def client() -> TypeSafeClient:
        if not hasattr(local, "client"):
            created = TypeSafeClient()
            local.client = created.__enter__()
            with lock:
                clients.append(created)
        return local.client

    def work(module: Module) -> None:
        if not module.has_code:
            finish(module, Judgment("package", 0.0))
            return
        state = _state(project, module)
        key = _cache_key(state, model)
        hit = cache.get(key)
        if hit is not None:
            try:
                cached = Judgment(hit["role"], float(hit["handles_auth"]))
            except (KeyError, TypeError, ValueError):
                cached = None
            if cached is not None:
                finish(module, cached)
                return
        try:
            response = client().system_one(state=state, questions=QUESTIONS, model=model)
        except Exception as error:
            logger.warning("Judging {} failed: {}", module.name, error)
            finish(module, Judgment("unknown", 0.0))
            return

        used_in = response.usage.input_tokens or 0
        used_out = response.usage.output_tokens or 0
        with lock:
            usage.input_tokens += used_in
            usage.output_tokens += used_out
            usage.calls += 1

        try:
            role = response.choices["role"]
            auth = response.nouls["handles_auth"].noul
        except Exception as error:
            logger.warning("Judging {} failed: {}", module.name, error)
            finish(module, Judgment("unknown", 0.0))
            return

        logger.debug("{}: role={} in={} out={}", module.name, role.choice, used_in, used_out)
        with lock:
            new_entries[key] = {"role": role.choice, "handles_auth": auth}
        finish(module, Judgment(role.choice, auth))

    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            list(pool.map(work, modules))
    finally:
        for created in clients:
            created.__exit__(None, None, None)

    if cache_on and new_entries:
        _save_cache(cache_path, {**cache, **new_entries})
    return {m.name: results[m.name] for m in modules}, usage
