'use strict';

// Simulated compromised workload. Events are emitted through the same ingest
// path as real telemetry. Outcomes come from the environment, so containment
// visibly changes what the attacker can do.
const ATTACKER_IP = '203.0.113.50';
const EXFIL_HOST = '198.51.100.7';
const WORKLOAD_IP = '10.40.1.9';

function provisionDemo(env) {
  env.addWorkload({ id: 'wl-billing-api', name: 'billing-api', owner: 'payments-team' });
  env.addSession({ id: 'sess-7f3a', user: 'dana@corp.example', workloadId: 'wl-billing-api', sourceIp: '10.20.3.14' });
  return { workloadId: 'wl-billing-api', sessionId: 'sess-7f3a', user: 'dana@corp.example' };
}

function makeEmitter(ingest, prefix = 'evt') {
  let n = 0;
  return (fields) => {
    n += 1;
    return ingest.ingest({ id: `${prefix}-${String(n).padStart(4, '0')}`, ts: new Date().toISOString(), ...fields });
  };
}

function runBaseline({ env, emit, workloadId, sessionId, user, rounds = 3 }) {
  const s = env.sessions.get(sessionId);
  for (let i = 0; i < rounds; i++) {
    emit({ source: 'idp', type: 'idp.token_use', sessionId, user, src_ip: s.baselineIp, outcome: 'allowed' });
    emit({ source: 'workload', type: 'workload.api_call', workloadId, sessionId, src_ip: s.baselineIp, path: '/invoices', outcome: 'allowed' });
    emit({ source: 'netflow', type: 'netflow', workloadId, src_ip: WORKLOAD_IP, dst: '10.0.5.20', bytes: 2048, outcome: 'allowed' });
  }
}

// Attacker replays a stolen session token and exfiltrates data.
// Each event's outcome reflects the current environment state.
function runCompromise({ env, emit, workloadId, sessionId, user, rounds = 3 }) {
  for (let i = 0; i < rounds; i++) {
    const tokenOk = env.authorize(sessionId);
    emit({ source: 'idp', type: 'idp.token_use', sessionId, user, src_ip: ATTACKER_IP, outcome: tokenOk ? 'allowed' : 'denied' });
    if (tokenOk) {
      emit({ source: 'workload', type: 'workload.api_call', workloadId, sessionId, src_ip: ATTACKER_IP, path: '/exports/customers', outcome: 'allowed' });
    }
    const egressOk = env.egressAllowed(workloadId, EXFIL_HOST);
    emit({ source: 'netflow', type: 'netflow', workloadId, src_ip: WORKLOAD_IP, dst: EXFIL_HOST, bytes: 25 * 1024 * 1024, outcome: egressOk ? 'allowed' : 'blocked' });
  }
}

module.exports = { provisionDemo, makeEmitter, runBaseline, runCompromise, ATTACKER_IP, EXFIL_HOST };
