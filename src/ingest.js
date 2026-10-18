'use strict';

const { isInternal } = require('./env');
const { httpError } = require('./errors');

const EXFIL_BYTES = 10 * 1024 * 1024;
const REQUIRED_FIELDS = ['id', 'ts', 'source', 'type'];

// Detection rules. Each returns a finding or null.
const RULES = [
  // A session token presented from an address other than the one it was issued to.
  function anomalousSessionUse(e, env) {
    if (e.type !== 'idp.token_use' || !e.sessionId) return null;
    const s = env.sessions.get(e.sessionId);
    if (!s || e.src_ip === s.baselineIp) return null;
    return {
      rule: 'anomalous_session_use',
      workloadId: s.workloadId,
      sessionId: s.id,
      summary: `Session ${s.id} (${s.user}) presented from ${e.src_ip}; baseline ${s.baselineIp}; outcome ${e.outcome}`,
    };
  },
  // Large transfer from a workload to an external destination.
  function suspiciousEgress(e) {
    if (e.type !== 'netflow' || !e.workloadId || isInternal(e.dst) || !(e.bytes > EXFIL_BYTES)) return null;
    return {
      rule: 'suspicious_egress',
      workloadId: e.workloadId,
      sessionId: null,
      summary: `${e.workloadId} sent ${e.bytes} bytes to external ${e.dst} (${e.outcome})`,
    };
  },
];

// Accepts normalized events from any source. Duplicates are dropped by id.
// Detections open a case for the affected workload, or attach to the open one.
class Ingestor {
  constructor({ env, cases }) {
    this.env = env;
    this.cases = cases;
    this.seen = new Set();
    this.events = [];
  }

  ingest(raw) {
    const event = normalize(raw);
    if (this.seen.has(event.id)) return { accepted: false, reason: 'duplicate', id: event.id };
    this.seen.add(event.id);
    this.events.push(event);

    const findings = [];
    for (const rule of RULES) {
      const f = rule(event, this.env);
      if (f) findings.push(f);
    }
    for (const f of findings) this.attach(f, event);
    return { accepted: true, id: event.id, findings: findings.map((f) => f.rule) };
  }

  attach(finding, event) {
    let c = this.cases.findOpenFor(finding.workloadId);
    if (!c) {
      const sessionIds = this.env.sessionsOn(finding.workloadId).map((s) => s.id);
      c = this.cases.openCase({
        title: `Suspicious activity on ${finding.workloadId}`,
        workloadId: finding.workloadId,
        sessionIds,
        workloadIds: [finding.workloadId],
      });
    }
    if (finding.sessionId) this.cases.extendScope(c.id, { sessionIds: [finding.sessionId] });
    this.cases.addTimeline(c.id, {
      kind: 'detection',
      actor: 'system',
      at: event.ts,
      summary: `[${finding.rule}] ${finding.summary}`,
      data: { eventId: event.id, rule: finding.rule },
    });
    return c;
  }
}

function normalize(raw) {
  if (!raw || typeof raw !== 'object') throw httpError(400, 'event must be an object');
  for (const k of REQUIRED_FIELDS) {
    if (typeof raw[k] !== 'string' || raw[k].length === 0) throw httpError(400, `event missing ${k}`);
  }
  if (Number.isNaN(Date.parse(raw.ts))) throw httpError(400, 'event ts is not a valid timestamp');
  return { ...raw };
}

module.exports = { Ingestor, RULES, EXFIL_BYTES };
