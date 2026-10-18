'use strict';

const esc = (v) =>
  String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

// Server-rendered case list with each case's timeline and proposals.
function renderCasesPage(cases) {
  const sections = cases.listCases().map((c) => {
    const v = cases.view(c.id);
    const rows = v.timeline
      .map(
        (t) => `<tr><td>${esc(t.seq)}</td><td>${esc(t.at)}</td><td class="k k-${esc(t.kind)}">${esc(t.kind)}</td><td>${esc(t.actor)}</td><td>${esc(t.summary)}</td></tr>`,
      )
      .join('');
    const props = v.proposals
      .map(
        (p) =>
          `<tr><td>${esc(p.id)}</td><td>${esc(p.tool)}</td><td>${esc(p.status)}</td><td>${esc(p.plan.blastRadius)}</td><td>${esc(p.proposer)}</td><td>${esc(p.approvedBy || '')}</td></tr>`,
      )
      .join('');
    return `<section>
  <h2>${esc(c.id)} · ${esc(c.title)} <span class="badge">${esc(c.status)}</span></h2>
  <p class="meta">Scope: workloads [${esc(v.scope.workloadIds.join(', '))}] · sessions [${esc(v.scope.sessionIds.join(', '))}]</p>
  <h3>Proposals</h3>
  <table><tr><th>ID</th><th>Tool</th><th>Status</th><th>Blast radius</th><th>Proposer</th><th>Approved by</th></tr>${props || '<tr><td colspan="6">none</td></tr>'}</table>
  <h3>Timeline</h3>
  <table><tr><th>#</th><th>Time</th><th>Kind</th><th>Actor</th><th>Summary</th></tr>${rows}</table>
</section>`;
  });
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ContainOps</title>
<style>
  :root { color-scheme: light dark; --fg:#1b1f24; --bg:#fff; --muted:#667; --line:#d0d7de; }
  @media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { --fg:#e6e8eb; --bg:#14171c; --muted:#9aa4b2; --line:#30363d; } }
  body { margin:0; padding:16px; font:14px/1.5 system-ui, sans-serif; background:var(--bg); color:var(--fg); }
  h1 { font-size:20px; } h2 { font-size:16px; margin-bottom:4px; } h3 { font-size:13px; text-transform:uppercase; color:var(--muted); }
  table { width:100%; border-collapse:collapse; margin-bottom:12px; font-size:13px; overflow-wrap:anywhere; }
  th, td { border-bottom:1px solid var(--line); padding:6px; text-align:left; vertical-align:top; }
  .meta { color:var(--muted); margin:0 0 8px; }
  .badge { font-size:11px; border:1px solid var(--line); border-radius:4px; padding:1px 6px; }
  .k { font-family: ui-monospace, monospace; font-size:12px; }
</style></head>
<body><h1>ContainOps · Cases</h1>${sections.join('') || '<p>No cases yet. POST events to /events.</p>'}</body></html>`;
}

module.exports = { renderCasesPage };
