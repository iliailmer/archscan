from dataclasses import dataclass

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
    "test": "Contains tests.",
}

CAPABILITIES = {
    "touches_db": "Does this module access a database?",
    "touches_network": "Does this module make or accept network calls?",
    "reads_user_input": "Does this module read input from users or external clients?",
    "handles_auth": "Does this module handle authentication or authorization?",
    "reads_secrets": "Does this module read secrets, keys, or credentials?",
}

QUESTIONS = {
    "role": Choice(instructions="What is the main role of this module?", criteria=ROLES),
    **{name: Noul(instructions=text) for name, text in CAPABILITIES.items()},
}

NOUL_THRESHOLD = 0.5
DEFAULT_MODEL = "jev-latest"


@dataclass
class Judgment:
    role: str
    role_confidence: float
    capabilities: dict[str, float]

    @property
    def active_capabilities(self) -> list[str]:
        return [k for k, p in self.capabilities.items() if p >= NOUL_THRESHOLD]


@dataclass
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0

    def cost(self, price_in: float, price_out: float) -> float:
        """Cost in USD. Prices are USD per million tokens."""
        return (self.input_tokens * price_in + self.output_tokens * price_out) / 1_000_000


def judge_module(
    client: TypeSafeClient,
    project: ProjectGraph,
    module: Module,
    usage: TokenUsage,
    model: str = DEFAULT_MODEL,
) -> Judgment:
    graph = project.graph
    state = {
        "module": module.name,
        "source": (project.root / module.path).read_text(errors="replace"),
        "imports_internal": sorted(graph.successors(module.name)),
        "imports_external": sorted(set(module.external_imports)),
    }
    response = client.system_one(state=state, questions=QUESTIONS, model=model)
    used_in = response.usage.input_tokens or 0
    used_out = response.usage.output_tokens or 0
    usage.input_tokens += used_in
    usage.output_tokens += used_out
    usage.calls += 1
    role = response.choices["role"]
    logger.debug("{}: role={} in={} out={}", module.name, role.choice, used_in, used_out)
    return Judgment(
        role=role.choice,
        role_confidence=role.confidence,
        capabilities={name: response.nouls[name].noul for name in CAPABILITIES},
    )


def judge_project(project: ProjectGraph, model: str = DEFAULT_MODEL) -> tuple[dict[str, Judgment], TokenUsage]:
    usage = TokenUsage()
    judgments = {}
    modules = project.modules()
    with TypeSafeClient() as client:
        for i, module in enumerate(modules, 1):
            logger.info("Judging {} ({}/{})", module.name, i, len(modules))
            judgments[module.name] = judge_module(client, project, module, usage, model)
    return judgments, usage
