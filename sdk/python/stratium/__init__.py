"""Build a Stratium policy enforcement point.

    grant = client.create_delegation(...)
    d = client.decide(tool="Read", raw_input={"file_path": "/tmp/x"},
                      token=grant.token, ...)
    if d:
        ...
"""

from ._types import Decision, Effect, Grant, Leg, Legs, Scope

__all__ = ["Decision", "Effect", "Grant", "Leg", "Legs", "Scope"]
