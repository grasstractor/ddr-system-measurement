# Rebuild the figures

The scripts read the frozen summaries and address sets in `data/` and produce
vector PDF figures and 240 dpi PNG previews. The checked-in outputs use Arial
for English and Microsoft YaHei for Chinese.

## Environment

Tested with Python 3.11.2, Matplotlib 3.11.2, and NumPy 2.4.6. From the repository
root:

```sh
python -m venv .venv
# Windows PowerShell:
.venv/Scripts/Activate.ps1
# macOS / Linux:
# source .venv/bin/activate
python -m pip install -r requirements.txt
```

English figures use the first installed font from Arial and DejaVu Sans.
DejaVu Sans ships with Matplotlib. Chinese figures use the first installed font
from Microsoft YaHei, Noto Sans CJK SC, Noto Sans SC, Source Han Sans SC,
PingFang SC, Heiti SC, and WenQuanYi Zen Hei. Install one of these fonts before
building the Chinese figures. For example, Debian and Ubuntu provide
`fonts-noto-cjk`:

```sh
sudo apt-get install fonts-noto-cjk
```

If a newly installed font is missing from Matplotlib's font list, remove
`fontlist-v*.json` from the directory printed by
`python -c "import matplotlib; print(matplotlib.get_cachedir())"` and rerun.

## Commands

```sh
python scripts/make_figures.py
python zh/scripts/make_figures.py
```

Each command builds eight figures. English outputs are in `figures/`; Chinese
outputs are in `zh/figures/`. Run `python scripts/ddr_flowcharts.py` to rebuild
only the bilingual DDR flow comparison. Each output directory includes a
`figure-manifest.json` with PDF sizes and SHA-256 hashes.

| Figure basename | Content | Size (inches) |
| --- | --- | --- |
| `methodology` | Native controls, public discovery, and analysis tasks | 7.16 × 1.93 |
| `ddr-connection-flows` | RFC 9462 verified discovery and three native DoH paths | 7.16 × 6.50 |
| `success-overlap` | Successful-address intersections across systems | 3.50 × 2.38 |
| `failure-stages` | Endpoint-validation outcomes | 3.50 × 2.20 |
| `rule-interventions` | Success counts for individual and combined rule changes | 7.16 × 4.08 |
| `rule-interactions` | Conditional gains from rule combinations | 7.16 × 2.03 |
| `semantic-continuity` | Public and native DNS64 response comparisons | 7.16 × 1.92 |
| `authority-control` | Native macOS HTTP authority controls | 3.50 × 1.48 |

## Source files and checks

Run the offline evidence and output checks with the Python standard library:

```sh
python scripts/verify_artifact.py
```

This checks success sets, endpoint-validation and rule-comparison counts,
public/native DNS64 results, and both PDF manifests.

`scripts/paper_figures.py` contains the shared style and seven data figures.
`scripts/ddr_flowcharts.py` contains the bilingual connection-flow diagram.
The two `make_figures.py` entry points rebuild their language's full figure set.

Inputs include `summary.json`, `los-angeles-failure-analysis.json`, per-system
IPv4/IPv6 success address lists, `windows-dot-all-success.txt`, and
`extensions/figure-evidence.json`. The generator checks key denominators,
success-set sizes, and DNS64 response/path counts against the frozen evidence.
The flowchart also checks text against node and canvas bounds.

All figures use a minimum 8.5 pt font at their stated size. PDFs embed their
fonts. Original resolver addresses are labeled R₀; DNS A records retain the
record-type name A. `data/derived.json` and the figure manifests are refreshed
by the build commands.
