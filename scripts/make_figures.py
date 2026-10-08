"""Rebuild English figures using the shared publication style."""
from paper_figures import run
from ddr_flowcharts import create

if __name__ == "__main__":
    run("en")
    create(False)
