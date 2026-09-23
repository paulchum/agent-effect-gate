"""Read package metadata without importing the application or its runtime."""
from pathlib import Path
import runpy

distribution_version = runpy.run_path(
    str(Path(__file__).parent / "agent_effect_gate" / "_version.py")
)["__version__"]
