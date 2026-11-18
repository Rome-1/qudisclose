"""The multi-agent response team: triage, reproducer, patcher, reviewer, release, postmortem.

Every role talks to a `Provider` (Claude via the Anthropic SDK, or a scripted stand-in for tests and demos)
and returns a strictly validated pydantic model. Untrusted text (reports, tool output) is always wrapped with
`wrap_untrusted` before it reaches a model."""

from qudisclose.agents.provider import (
    AnthropicProvider, ClaudeCliProvider, Provider, ProviderRefusal, ScriptedProvider,
)
from qudisclose.agents.roles import (
    PatcherAgent, PostmortemAgent, ReleaseAgent, ReproducerAgent, ReviewerAgent, TriageAgent,
)

__all__ = ["AnthropicProvider", "ClaudeCliProvider", "Provider", "ProviderRefusal", "ScriptedProvider",
           "PatcherAgent", "PostmortemAgent", "ReleaseAgent", "ReproducerAgent", "ReviewerAgent", "TriageAgent"]
