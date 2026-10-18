'use strict';

const { httpError } = require('./errors');

// Case and proposal store. Every state change is appended to the case
// timeline, which is the audit record for the incident.
class CaseStore {
  constructor() {
    this.cases = new Map();
    this.proposals = new Map();
    this.seq = 0;
  }

  nextId(prefix) {
    this.seq += 1;
    return `${prefix}-${String(this.seq).padStart(4, '0')}`;
  }

  openCase({ title, workloadId, sessionIds, workloadIds }) {
    const c = {
      id: this.nextId('case'),
      title,
      status: 'open',
      openedAt: new Date().toISOString(),
      // Containment is bounded to these resources. Proposals outside this
      // scope are refused.
      scope: { workloadIds: [...new Set(workloadIds)], sessionIds: [...new Set(sessionIds)] },
      primaryWorkloadId: workloadId,
      timeline: [],
    };
    this.cases.set(c.id, c);
    this.addTimeline(c.id, { kind: 'case_opened', actor: 'system', summary: title });
    return c;
  }

  findOpenFor(workloadId) {
    return [...this.cases.values()].find(
      (c) => c.status === 'open' && c.primaryWorkloadId === workloadId,
    );
  }

  extendScope(caseId, { sessionIds = [], workloadIds = [] }) {
    const c = this.getCase(caseId);
    c.scope.sessionIds = [...new Set([...c.scope.sessionIds, ...sessionIds])];
    c.scope.workloadIds = [...new Set([...c.scope.workloadIds, ...workloadIds])];
  }

  getCase(id) {
    const c = this.cases.get(id);
    if (!c) throw httpError(404, `unknown case ${id}`);
    return c;
  }

  addTimeline(caseId, entry) {
    const c = this.cases.get(caseId);
    const item = {
      seq: c.timeline.length + 1,
      at: entry.at || new Date().toISOString(),
      kind: entry.kind,
      actor: entry.actor,
      summary: entry.summary,
      data: entry.data || null,
    };
    c.timeline.push(item);
    return item;
  }

  addProposal(fields) {
    const p = { id: this.nextId('prop'), createdAt: new Date().toISOString(), approvedBy: null, ...fields };
    this.proposals.set(p.id, p);
    return p;
  }

  getProposal(id) {
    const p = this.proposals.get(id);
    if (!p) throw httpError(404, `unknown proposal ${id}`);
    return p;
  }

  listCases() {
    return [...this.cases.values()].map((c) => ({
      id: c.id,
      title: c.title,
      status: c.status,
      openedAt: c.openedAt,
      events: c.timeline.length,
    }));
  }

  view(id) {
    const c = this.getCase(id);
    const proposals = [...this.proposals.values()].filter((p) => p.caseId === id);
    return { ...c, proposals };
  }
}

module.exports = { CaseStore };
