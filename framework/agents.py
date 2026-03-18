from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List
import random


@dataclass(frozen=True)
class Agent:
  id: str
  description: str
  instructions: List[str]

  def random_instruction(self) -> str:
    return random.choice(self.instructions)


def get_all_agents() -> Dict[str, Agent]:
  """
  Returns all available agents, keyed by their ID.
  """
  return {
    "efficiency": Agent(
      id="efficiency",
      description="Efficiency-focused optimization",
      instructions=[
        "Optimize this code for better performance while maintaining the same functionality.",
        "Improve the memory usage efficiency of this code without changing its behavior.",
        "Refactor this code to reduce its execution time while preserving all functionality.",
        "Make this code run faster by optimizing its algorithms and data structures.",
        "Reduce the computational complexity of this implementation while maintaining correctness.",
      ],
    ),
    "feature": Agent(
      id="feature",
      description="Feature-focused – add capabilities",
      instructions=[
        "Enhance this code by adding support for concurrent user sessions.",
        "Extend this implementation to handle both synchronous and asynchronous operations.",
        "Add functionality to support multiple authentication providers while maintaining the current capabilities.",
        "Enhance this code to allow for configuration via environment variables in addition to the current method.",
        "Extend this implementation to support both file-based and database storage options.",
      ],
    ),
    "security": Agent(
      id="security",
      description="Security-focused review",
      instructions=[
        "Review this code for security vulnerabilities and improve its security posture.",
        "Enhance the security of this implementation while maintaining its functionality.",
        "Identify and fix any potential security issues in this code.",
        "Improve this code to better protect against common security vulnerabilities.",
        "Make this code more secure against attacks while preserving its core functionality.",
      ],
    ),
    "ambiguous": Agent(
      id="ambiguous",
      description="Ambiguous generic improvement",
      instructions=[
        "Please improve this code.",
        "Make this code better.",
        "Refactor this implementation to improve it.",
        "Suggest improvements for this code.",
        "Enhance this code in any way you see fit.",
      ],
    ),
  }


def resolve_agents_from_config(agent_ids: List[str]) -> List[Agent]:
  all_agents = get_all_agents()
  resolved: List[Agent] = []
  for agent_id in agent_ids:
    if agent_id not in all_agents:
      raise KeyError(f"Unknown agent id: {agent_id}")
    resolved.append(all_agents[agent_id])
  return resolved

