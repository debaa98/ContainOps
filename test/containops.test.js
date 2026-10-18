'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSystem } = require('../src/system');
const { provisionDemo, makeEmitter, runBaseline, runCompromise } = require('../src/simulator');
const { createServer } = require('../src/server');

function setup() {
  const sys = createSystem();
  const demo = provisionDemo(sys.env);
  const emit = makeEmitter(sys.ingest, 't');
  runBaseline({ env: sys.env, emit, ...demo });
  return { sys, demo, emit };
}

function compromisedCase() {
  const ctx = setup();
  runCompromise({ env: ctx.sys.env, emit: ctx.emit, ...ctx.demo });
  const [c] = ctx.sys.cases.listCases();
  return { ...ctx, caseId: c.id };
}

test('baseline traffic raises no detections', () => {
  const { sys } = setup();
  assert.equal(sys.cases.listCases().length, 0);
});

test('stolen token from a foreign IP opens a case and scopes it', () => {
  const { sys, caseId } = compromisedCase();
  const c = sys.cases.view(caseId);
  assert.deepEqual(c.scope.sessionIds, ['sess-7f3a']);
  assert.deepEqual(c.scope.workloadIds, ['wl-billing-api']);
  assert.ok(c.timeline.some((t) => t.summary.includes('anomalous_session_use')));
  assert.ok(c.timeline.some((t) => t.summary.includes('suspicious_egress')));
});

test('duplicate event ids are dropped', () => {
  const { sys } = setup();
  const e = { id: 'dup-1', ts: new Date().toISOString(), source: 'idp', type: 'idp.token_use', sessionId: 'sess-7f3a', src_ip: '1.1.1.1' };
  assert.equal(sys.ingest.ingest(e).accepted, true);
  assert.equal(sys.ingest.ingest(e).reason, 'duplicate');
});

test('invalid events are rejected with 400', () => {
  const { sys } = setup();
  assert.throws(() => sys.ingest.ingest({ id: 'x', ts: 'not-a-date', source: 'idp', type: 'idp.token_use' }), { status: 400 });
  assert.throws(() => sys.ingest.ingest({ id: 'x', source: 'idp', type: 'idp.token_use' }), { status: 400 });
});

test('agent cannot execute a proposal it made', () => {
  const { sys, caseId, demo } = compromisedCase();
  const p = sys.containment.propose({ caseId, tool: 'session.revoke', params: { sessionId: demo.sessionId }, proposer: 'agent:bot' });
  assert.throws(() => sys.containment.execute({ proposalId: p.id }), { status: 409 });
  assert.equal(sys.env.sessions.get(demo.sessionId).status, 'active');
});

test('agent cannot approve its own proposal or approve as itself', () => {
  const { sys, caseId, demo } = compromisedCase();
  const p = sys.containment.propose({ caseId, tool: 'session.revoke', params: { sessionId: demo.sessionId }, proposer: 'agent:bot' });
  assert.throws(() => sys.containment.approve({ proposalId: p.id, approver: 'agent:bot' }), { status: 403 });
  assert.throws(() => sys.containment.approve({ proposalId: p.id, approver: '' }), { status: 403 });
});

test('targets outside case scope are refused', () => {
  const { sys, caseId } = compromisedCase();
  sys.env.addWorkload({ id: 'wl-other', name: 'other' });
  sys.env.addSession({ id: 'sess-other', user: 'x@corp.example', workloadId: 'wl-other', sourceIp: '10.9.9.9' });
  assert.throws(() => sys.containment.propose({ caseId, tool: 'session.revoke', params: { sessionId: 'sess-other' }, proposer: 'agent:bot' }), { status: 403 });
  assert.throws(() => sys.containment.propose({ caseId, tool: 'workload.isolate', params: { workloadId: 'wl-other' }, proposer: 'agent:bot' }), { status: 403 });
});

test('session revocation is executed and verified; attacker is then denied', () => {
  const { sys, caseId, demo, emit } = compromisedCase();
  const p = sys.containment.propose({ caseId, tool: 'session.revoke', params: { sessionId: demo.sessionId }, proposer: 'agent:bot' });
  sys.containment.approve({ proposalId: p.id, approver: 'analyst@corp.example' });
  const done = sys.containment.execute({ proposalId: p.id, actor: 'analyst@corp.example' });
  assert.equal(done.status, 'verified');
  assert.equal(sys.env.authorize(demo.sessionId), false);
  assert.throws(() => sys.containment.execute({ proposalId: p.id }), { status: 409 });
  runCompromise({ env: sys.env, emit, ...demo, rounds: 1 });
  const last = sys.cases.view(caseId).timeline.at(-1);
  assert.ok(last);
});

test('workload isolation blocks external egress and is verified', () => {
  const { sys, caseId, demo } = compromisedCase();
  const p = sys.containment.propose({ caseId, tool: 'workload.isolate', params: { workloadId: demo.workloadId }, proposer: 'agent:bot' });
  sys.containment.approve({ proposalId: p.id, approver: 'analyst@corp.example' });
  const done = sys.containment.execute({ proposalId: p.id, actor: 'analyst@corp.example' });
  assert.equal(done.status, 'verified');
  assert.equal(sys.env.egressAllowed(demo.workloadId, '198.51.100.7'), false);
  assert.equal(sys.env.egressAllowed(demo.workloadId, '10.0.5.20'), true);
});

test('rejected proposals cannot be executed', () => {
  const { sys, caseId, demo } = compromisedCase();
  const p = sys.containment.propose({ caseId, tool: 'session.revoke', params: { sessionId: demo.sessionId }, proposer: 'agent:bot' });
  sys.containment.reject({ proposalId: p.id, approver: 'analyst@corp.example', reason: 'false positive' });
  assert.throws(() => sys.containment.execute({ proposalId: p.id }), { status: 409 });
  assert.equal(sys.env.sessions.get(demo.sessionId).status, 'active');
});

test('closed cases do not accept new proposals', () => {
  const { sys, caseId, demo } = compromisedCase();
  sys.cases.getCase(caseId).status = 'closed';
  assert.throws(() => sys.containment.propose({ caseId, tool: 'session.revoke', params: { sessionId: demo.sessionId }, proposer: 'agent:bot' }), { status: 409 });
});

test('HTTP API: ingest, propose, approve, execute, timeline', async () => {
  const sys = createSystem();
  const server = createServer(sys);
  await new Promise((r) => server.listen(0, r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (path, body) =>
    fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  try {
    const sim = await post('/simulate', {});
    assert.equal(sim.status, 200);
    const { cases } = await sim.json();
    const caseId = cases[0].id;

    const view = await (await fetch(`${base}/cases/${caseId}`)).json();
    assert.equal(view.scope.sessionIds[0], 'sess-7f3a');

    const prop = await (await post(`/cases/${caseId}/proposals`, {
      tool: 'workload.isolate', params: { workloadId: 'wl-billing-api' }, proposer: 'agent:bot', rationale: 'exfil',
    })).json();
    assert.equal(prop.status, 'proposed');

    const bad = await post(`/proposals/${prop.id}/approve`, { approver: 'agent:bot' });
    assert.equal(bad.status, 403);

    await post(`/proposals/${prop.id}/approve`, { approver: 'analyst@corp.example' });
    const executed = await (await post(`/proposals/${prop.id}/execute`, { actor: 'analyst@corp.example' })).json();
    assert.equal(executed.status, 'verified');

    const env = await (await fetch(`${base}/environment`)).json();
    assert.equal(env.workloads[0].status, 'isolated');

    const ui = await fetch(`${base}/ui`);
    assert.match(await ui.text(), /Timeline/);
  } finally {
    await new Promise((r) => server.close(r));
  }
});
