"""Detection engines.  New engines are registered here; the scanner treats
them uniformly through the protocol in ``base``."""
from .base import Engine, Verdict
from .eicar import EicarEngine
from .heuristics import HeuristicsEngine
from .clamav import ClamAvEngine

__all__ = ["Engine", "Verdict", "EicarEngine", "HeuristicsEngine", "ClamAvEngine"]
