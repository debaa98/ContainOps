'use strict';

const { httpError } = require('./errors');

const AGENT_PREFIX = 'agent:';

// Proposal lifecycle:
//   propose (agent) -> approve | reject (human) -> execute -> verified | failed
// Agents can propose only. Execution requires a prior human approval, and
// targets must be inside the case scope.
class ContainmentService {
  constructor({ env, cases, tools }) {
    this.env = env;
    this.cases = cases;
    this.tools = tools;
  }

  propose({ caseId, tool, params = {}, proposer, rationale }) {
    const c = this.cases.getCase(caseId);
    if (c.status !== 'open') throw httpError(409, `case ${caseId} is not open`);
    if (!proposer) throw httpError(400, 'proposer is required');
    const t = this.tools[tool];
    if (!t) throw httpError(400, `unknown tool ${tool}`);

    const targetId = params[t.target.param];
    const scoped = t.target.kind === 'session' ? c.scope.sessionIds : c.scope.workloadIds;
    if (!scoped.includes(targetId)) {
      throw httpError(403, `${t.target.kind} ${targetId} is outside the scope of ${caseId}`);
    }
    const exists = t.target.kind === 'session' ? this.env.sessions.has(targetId) : this.env.workloads.has(targetId);
    if (!exists) throw httpError(404, `${t.target.kind} ${targetId} not found`);

    const plan = t.plan(this.env, params);
    const p = this.cases.addProposal({
      caseId,
      tool,
      params,
      proposer,
      rationale: rationale || '',
      plan,
      status: 'proposed',
    });
    this.cases.addTimeline(caseId, {
      kind: 'proposal',
      actor: proposer,
      summary: `${tool}: ${plan.summary}`,
      data: { proposalId: p.id, rationale: p.rationale, blastRadius: plan.blastRadius },
    });
    return p;
  }

  approve({ proposalId, approver }) {
    return this.decide(proposalId, approver, 'approved');
  }

  reject({ proposalId, approver, reason }) {
    return this.decide(proposalId, approver, 'rejected', reason);
  }

  decide(proposalId, approver, decision, reason) {
    const p = this.cases.getProposal(proposalId);
    if (p.status !== 'proposed') throw httpError(409, `proposal ${proposalId} is ${p.status}`);
    if (!approver || approver.startsWith(AGENT_PREFIX)) throw httpError(403, 'approver must be a human identity');
    if (approver === p.proposer) throw httpError(403, 'proposer cannot approve their own proposal');

    p.status = decision;
    p.decidedBy = approver;
    if (decision === 'approved') p.approvedBy = approver;
    this.cases.addTimeline(p.caseId, {
      kind: decision === 'approved' ? 'approval' : 'rejection',
      actor: approver,
      summary: `${decision} ${p.tool} on ${Object.values(p.params).join(', ')}${reason ? ` (${reason})` : ''}`,
      data: { proposalId },
    });
    return p;
  }

  execute({ proposalId, actor }) {
    const p = this.cases.getProposal(proposalId);
    if (p.status !== 'approved') throw httpError(409, `proposal ${proposalId} must be approved before execution (is ${p.status})`);
    const t = this.tools[p.tool];

    const changed = t.execute(this.env, p.params);
    this.cases.addTimeline(p.caseId, {
      kind: 'execution',
      actor: actor || 'system',
      summary: `${p.tool} ${changed ? 'applied' : 'already in desired state'}`,
      data: { proposalId },
    });

    const ok = t.verify(this.env, p.params);
    p.status = ok ? 'verified' : 'failed';
    p.verifiedAt = new Date().toISOString();
    this.cases.addTimeline(p.caseId, {
      kind: 'verification',
      actor: 'system',
      summary: ok ? `${p.tool} verified: effect confirmed` : `${p.tool} FAILED verification`,
      data: { proposalId, ok },
    });
    return p;
  }
}

module.exports = { ContainmentService, AGENT_PREFIX };
