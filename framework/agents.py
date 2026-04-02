from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Agent:
  id: str
  description: str
  instructions: List[str]

  def random_instruction(self) -> str:
    return random.choice(self.instructions)


def resolve_agents_from_config(
  agent_ids: List[str],
  agents_cfg: Dict[str, Dict] | None = None,
) -> List[Agent]:
  """
  Build Agent objects for the given IDs using the ``agents`` section of the
  experiment config.

  Parameters
  ----------
  agent_ids:
      Ordered list of agent IDs to resolve (from ``experiment.agents``).
  agents_cfg:
      The ``agents`` top-level block from the loaded YAML config
      (i.e. ``config.get("agents", {})``).  Each key is an agent ID; the
      value must have ``description`` (str) and ``instructions`` (list[str]).

  Raises
  ------
  KeyError
      If an ID in ``agent_ids`` has no matching entry in ``agents_cfg``.
  ValueError
      If a matching entry has no instructions or has a non-list instructions
      field.
  """
  if agents_cfg is None:
    agents_cfg = {}

  resolved: List[Agent] = []
  for agent_id in agent_ids:
    if agent_id not in agents_cfg:
      raise KeyError(
        f"Unknown agent id: '{agent_id}'. "
        f"Add it to the 'agents:' block in your config file."
      )
    entry = agents_cfg[agent_id]
    instructions = entry.get("instructions", [])
    if not isinstance(instructions, list) or not instructions:
      raise ValueError(
        f"Agent '{agent_id}' must have a non-empty 'instructions' list in config."
      )
    resolved.append(
      Agent(
        id=agent_id,
        description=str(entry.get("description", "")),
        instructions=[str(i) for i in instructions],
      )
    )
  return resolved
