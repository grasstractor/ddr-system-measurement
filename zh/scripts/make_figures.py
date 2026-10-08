"""Rebuild Chinese figures using shared evidence and publication style."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from paper_figures import run
from ddr_flowcharts import create

if __name__ == "__main__":
    run("zh")
    create(True)
