"""Figure: field-1's joule budget during the three 600 s FORGE+ECHO runs (paper/data/E_budget, FEAT rows)."""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
df = pd.read_csv(os.path.join(HERE, "..", "data", "E9_traces", "traces_field1.csv"))
df = df[df.session.astype(str).str.startswith("budget")]
fig, ax = plt.subplots(figsize=(3.5, 2.0))
for i, (s, g) in enumerate(df.groupby("session")):
    t0 = g[g.label == "FORGE_ECHO"].t_s.min()
    ax.plot(g.t_s - t0, g.budget_j, lw=1, label=f"run {i + 1}")
ax.axvspan(0, 600, color="0.9", zorder=0)
ax.set_xlabel("time from attack start (s)")
ax.set_ylabel("budget (J)")
ax.legend(fontsize=7, frameon=False)
ax.tick_params(labelsize=7)
ax.xaxis.label.set_size(8); ax.yaxis.label.set_size(8)
fig.tight_layout()
fig.savefig(os.path.join(HERE, "..", "ieee", "fig_budget.pdf"))
