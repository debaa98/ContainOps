'use strict';

// End-to-end scenario: baseline traffic, compromise, detection, agent proposals,
// human approval, execution, verification, and the resulting case timeline.
const { createSystem } = require('./system');
const { provisionDemo, makeEmitter, runBaseline, runCompromise } = require('./simulator');

function printTimeline(c) {
  console.log(`\n${c.id} · ${c.title} [${c.status}]`);
  console.log(`scope: workloads=${c.scope.workloadIds} sessions=${c.scope.sessionIds}`);
  for (const t of c.timeline) {
    console.log(`  ${String(t.seq).padStart(2)}. ${t.kind.padEnd(14)} ${t.actor.padEnd(22)} ${t.summary}`);
  }
}

function run() {
  const sys = createSystem();
  const demo = provisionDemo(sys.env);
  const emit = makeEmitter(sys.ingest, 'sim');

  console.log('== 1. Baseline traffic');
  runBaseline({ env: sys.env, emit, ...demo });
  console.log(`   open cases: ${sys.cases.listCases().length}`);

  console.log('== 2. Compromise (stolen token replayed from', '203.0.113.50', ')');
  runCompromise({ env: sys.env, emit, ...demo });
  const [c] = sys.cases.listCases();
  const caseId = c.id;
  console.log(`   ${caseId} opened with ${c.events} timeline entries`);

  console.log('== 3. Agent proposes containment (agent cannot execute)');
  const agent = 'agent:triage-bot';
  const pRevoke = sys.containment.propose({
    caseId,
    tool: 'session.revoke',
    params: { sessionId: demo.sessionId },
    proposer: agent,
    rationale: 'Token replayed from a non-baseline IP and used to read /exports/customers.',
  });
  const pIsolate = sys.containment.propose({
    caseId,
    tool: 'workload.isolate',
    params: { workloadId: demo.workloadId },
    proposer: agent,
    rationale: '25 MB egress to an external host; the workload is the exfiltration path.',
  });
  console.log(`   proposed ${pRevoke.id} and ${pIsolate.id}`);
  try {
    sys.containment.execute({ proposalId: pRevoke.id, actor: agent });
  } catch (err) {
    console.log(`   execute before approval refused: ${err.message}`);
  }

  console.log('== 4. Out-of-scope target is refused');
  try {
    sys.containment.propose({
      caseId,
      tool: 'session.revoke',
      params: { sessionId: 'sess-unrelated' },
      proposer: agent,
      rationale: 'test',
    });
  } catch (err) {
    console.log(`   refused (${err.status}): ${err.message}`);
  }

  console.log('== 5. Human approves and executes');
  const approver = 'soc-analyst@corp.example';
  sys.containment.approve({ proposalId: pRevoke.id, approver });
  sys.containment.execute({ proposalId: pRevoke.id, actor: approver });
  sys.containment.approve({ proposalId: pIsolate.id, approver });
  sys.containment.execute({ proposalId: pIsolate.id, actor: approver });

  console.log('== 6. Post-containment replay: attacker is stopped');
  runCompromise({ env: sys.env, emit, ...demo, rounds: 2 });

  printTimeline(sys.cases.view(caseId));
  console.log('\nproposal states:', [pRevoke.id, pIsolate.id].map((id) => `${id}=${sys.cases.getProposal(id).status}`).join(' '));
}

if (require.main === module) run();

module.exports = { run };
