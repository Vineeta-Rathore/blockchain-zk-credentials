"""
Generates the proof-generation latency figure for CredentialVerification(8).

Loads 49 warm-run measurements from data/latency_raw_n8.json (primary) or
../PhD/build/circuits/latency_raw_n8.json (fallback). Run 1 (WASM cold-start)
is excluded; all statistics are computed from the raw sample array.
"""

import json, os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from matplotlib.lines import Line2D

# ── Load actual measured samples ───────────────────────────────────────────────
# Primary: data/latency_raw_n8.json (self-contained, included with Journal3 repo)
# Fallback: ../PhD/build/circuits/latency_raw_n8.json (full monorepo layout)
_here = os.path.dirname(os.path.abspath(__file__))
_candidates = [
    os.path.join(_here, 'data', 'latency_raw_n8.json'),
    os.path.join(_here, '..', 'PhD', 'build', 'circuits', 'latency_raw_n8.json'),
]
_raw_path = next((p for p in _candidates if os.path.exists(p)), None)
if _raw_path is None:
    raise FileNotFoundError(
        "latency_raw_n8.json not found. Expected at data/latency_raw_n8.json "
        "or ../PhD/build/circuits/latency_raw_n8.json"
    )
with open(_raw_path) as f:
    _raw = json.load(f)

samples    = np.array(_raw['warmSamples'])   # 49 actual warm-run measurements
COLD_START = _raw['coldStartMs']
N          = len(samples)                    # 49

# Compute statistics from actual samples
MEAN   = float(np.mean(samples))
STD    = float(np.std(samples, ddof=1))
P50    = float(np.percentile(samples, 50))
P95    = float(np.percentile(samples, 95))
VMIN   = float(np.min(samples))
VMAX   = float(np.max(samples))

print("=== Actual measured statistics ===")
print(f"  n    = {N}")
print(f"  mean = {MEAN:.3f} ms")
print(f"  std  = {STD:.3f} ms")
print(f"  p50  = {P50:.3f} ms")
print(f"  p95  = {P95:.3f} ms")
print(f"  min  = {VMIN:.3f} ms")
print(f"  max  = {VMAX:.3f} ms")
print(f"  cold = {COLD_START:.1f} ms")

# ── Colour palette ─────────────────────────────────────────────────────────────
C_WARM   = "#2563EB"   # blue
C_COLD   = "#DC2626"   # red
C_MEAN   = "#15803D"   # green
C_P95    = "#D97706"   # amber
C_FACE   = "#DBEAFE"   # light blue fill
C_MEDIAN = "#1D4ED8"   # dark blue median

RNG = np.random.default_rng(seed=42)

fig, axes = plt.subplots(
    1, 2,
    figsize=(7.6, 4.4),
    gridspec_kw={"width_ratios": [1.55, 1], "wspace": 0.46},
    dpi=300
)

# ── Panel A: Box plot + jitter ─────────────────────────────────────────────────
ax = axes[0]

bp = ax.boxplot(
    samples,
    vert=True,
    patch_artist=True,
    widths=0.40,
    positions=[1],
    showfliers=False,
    whis=(0, 100),          # whiskers extend to actual min/max (not 1.5 IQR)
    medianprops=dict(color=C_MEDIAN, linewidth=2.5),
    boxprops=dict(facecolor=C_FACE, edgecolor=C_WARM, linewidth=1.8),
    whiskerprops=dict(color=C_WARM, linewidth=1.5, linestyle="--"),
    capprops=dict(color=C_WARM, linewidth=2.0),
)

jitter = RNG.uniform(-0.09, 0.09, N)
ax.scatter(np.ones(N) + jitter, samples,
           color=C_WARM, alpha=0.40, s=13, zorder=3, linewidths=0)

ax.hlines(MEAN, 0.68, 1.32, colors=C_MEAN, linewidth=2.2, linestyle="-", zorder=5)
ax.hlines(P95,  0.68, 1.32, colors=C_P95,  linewidth=1.6, linestyle=":", zorder=5)

ax.text(1.34, MEAN, f"$\\bar{{x}}$={MEAN:.0f}",
        fontsize=7.5, color=C_MEAN, va="center", ha="left")
ax.text(1.34, P95,  f"$p_{{95}}$={P95:.0f}",
        fontsize=7.5, color=C_P95,  va="center", ha="left")

ax.scatter([1], [COLD_START], marker="D", s=58, color=C_COLD,
           zorder=6, linewidths=0.8, edgecolors="white")
ax.annotate(
    f"Cold-start\n{COLD_START:.1f} ms (excl.)",
    xy=(0.94, COLD_START),
    xytext=(0.62, COLD_START - 50),
    fontsize=7, color=C_COLD, ha="left",
    arrowprops=dict(arrowstyle="-", color=C_COLD, lw=0.9)
)

ylo = max(200, VMIN - 60)
yhi = COLD_START + 80
ax.set_xlim(0.50, 1.72)
ax.set_ylim(ylo, yhi)
ax.set_xticks([])
ax.set_ylabel("Proof generation latency (ms)", fontsize=9)
ax.set_title(r"(a) Distribution  ($n=49$ warm runs)", fontsize=9, pad=6)
ax.tick_params(axis="y", labelsize=8)
ax.yaxis.set_minor_locator(mticker.MultipleLocator(25))
ax.grid(axis="y", which="major", linestyle="--", linewidth=0.5,
        color="#E5E7EB", zorder=0)
ax.grid(axis="y", which="minor", linestyle=":", linewidth=0.3,
        color="#F3F4F6", zorder=0)
ax.spines[["top", "right"]].set_visible(False)

stat_text = (
    f"$\\bar{{x}}$ = {MEAN:.1f} ms\n"
    f"$\\sigma$  = {STD:.1f} ms\n"
    f"$p_{{50}}$ = {P50:.1f} ms\n"
    f"$p_{{95}}$ = {P95:.1f} ms\n"
    f"min = {VMIN:.1f} ms\n"
    f"max = {VMAX:.1f} ms"
)
ax.text(
    0.972, 0.975, stat_text,
    transform=ax.transAxes,
    fontsize=7.5, verticalalignment="top", horizontalalignment="right",
    bbox=dict(boxstyle="round,pad=0.4", facecolor="white",
              edgecolor="#D1D5DB", linewidth=0.8),
    family="monospace"
)

# ── Panel B: Empirical CDF ─────────────────────────────────────────────────────
ax2 = axes[1]

sorted_s = np.sort(samples)
ecdf     = np.arange(1, N + 1) / N

ax2.plot(sorted_s, ecdf, color=C_WARM, linewidth=2.0, zorder=3)
ax2.fill_betweenx(ecdf, sorted_s, alpha=0.11, color=C_WARM, zorder=2)

ref_lines = [
    (P50,  f"$p_{{50}}$={P50:.0f}",  C_MEDIAN, "--"),
    (MEAN, f"mean={MEAN:.0f}",        C_MEAN,   "-."),
    (P95,  f"$p_{{95}}$={P95:.0f}",  C_P95,    ":"),
]
for val, label, col, ls in ref_lines:
    cdf_val = np.interp(val, sorted_s, ecdf)
    ax2.vlines(val, 0, cdf_val, colors=col, linewidth=1.3, linestyle=ls, zorder=4)
    ax2.hlines(cdf_val, sorted_s[0] - 5, val,
               colors=col, linewidth=1.3, linestyle=ls, zorder=4)

cdf_p50  = np.interp(P50,  sorted_s, ecdf)
cdf_mean = np.interp(MEAN, sorted_s, ecdf)
cdf_p95  = np.interp(P95,  sorted_s, ecdf)

x_label  = sorted_s[-1] + 15
label_specs = [
    (P50,  cdf_p50,  x_label, 0.25, f"$p_{{50}}$={P50:.0f}",  C_MEDIAN),
    (MEAN, cdf_mean, x_label, 0.52, f"mean={MEAN:.0f}",        C_MEAN),
    (P95,  cdf_p95,  x_label, 0.82, f"$p_{{95}}$={P95:.0f}",  C_P95),
]
for ax_x, ax_y, tx, ty, lbl, col in label_specs:
    ax2.annotate(
        lbl,
        xy=(ax_x, ax_y), xycoords="data",
        xytext=(tx, ty),  textcoords="data",
        fontsize=7.5, color=col, ha="left", va="center",
        arrowprops=dict(arrowstyle="-", color=col, lw=0.8,
                        shrinkA=2, shrinkB=2,
                        connectionstyle="arc3,rad=0.0")
    )

ax2.set_xlim(sorted_s[0] - 20, sorted_s[-1] + 80)
ax2.set_ylim(-0.02, 1.12)
ax2.set_xlabel("Latency (ms)", fontsize=9)
ax2.set_ylabel("Cumulative probability", fontsize=9)
ax2.set_title("(b) Empirical CDF", fontsize=9, pad=6)
ax2.tick_params(labelsize=8)
ax2.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1, decimals=0))
ax2.grid(linestyle="--", linewidth=0.5, color="#E5E7EB", zorder=0)
ax2.spines[["top", "right"]].set_visible(False)

# ── Legend ─────────────────────────────────────────────────────────────────────
legend_handles = [
    Line2D([0], [0], color=C_MEDIAN, linewidth=2.5, label="Median"),
    Line2D([0], [0], color=C_MEAN,   linewidth=2.2, label=f"Mean ({MEAN:.1f} ms)"),
    Line2D([0], [0], color=C_P95,    linewidth=1.6, linestyle=":",
           label=f"$p_{{95}}$ ({P95:.1f} ms)"),
    Line2D([0], [0], marker="D", color=C_COLD, markersize=6,
           linewidth=0, label=f"Cold-start ({COLD_START:.1f} ms, excl.)"),
]
fig.legend(
    handles=legend_handles,
    fontsize=7.5, ncol=4,
    loc="lower center",
    bbox_to_anchor=(0.5, -0.04),
    framealpha=0.95, edgecolor="#D1D5DB", handlelength=2.0,
    columnspacing=1.2
)

fig.suptitle(
    "Proof Generation Latency -- CredentialVerification(8)",
    fontsize=10, fontweight="bold", y=1.01
)
fig.text(
    0.5, -0.10,
    (f"50 runs, snarkjs WASM prover (Intel i5-1235U, Windows 11). "
     f"Run 1 (cold-start, {COLD_START:.1f} ms) excluded; $n={N}$ warm runs reported."),
    ha="center", fontsize=7.5, color="#6B7280"
)

# ── Save ───────────────────────────────────────────────────────────────────────
pdf_path = os.path.join(_here, "Figure 3.pdf")
png_path = os.path.join(_here, "fig3_latency_boxplot.png")
fig.savefig(pdf_path, format="pdf", bbox_inches="tight", dpi=300)
fig.savefig(png_path, format="png", bbox_inches="tight", dpi=300)
print(f"\nSaved:\n  {pdf_path}\n  {png_path}")
