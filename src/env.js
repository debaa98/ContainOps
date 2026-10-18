'use strict';

// Simulated enforcement plane. Stands in for an identity provider's session
// store and a workload orchestrator's network policy. Only containment tools
// mutate it; detections and the simulator only read it.
class SimEnvironment {
  constructor() {
    this.sessions = new Map();
    this.workloads = new Map();
  }

  addWorkload({ id, name, owner }) {
    const w = { id, name: name || id, owner: owner || null, status: 'running', isolatedAt: null };
    this.workloads.set(id, w);
    return w;
  }

  addSession({ id, user, workloadId, sourceIp }) {
    if (!this.workloads.has(workloadId)) throw new Error(`unknown workload ${workloadId}`);
    const s = { id, user, workloadId, baselineIp: sourceIp, status: 'active', revokedAt: null };
    this.sessions.set(id, s);
    return s;
  }

  sessionsOn(workloadId) {
    return [...this.sessions.values()].filter((s) => s.workloadId === workloadId);
  }

  // A request presenting this session is accepted only if the session is
  // active and its workload is not isolated.
  authorize(sessionId) {
    const s = this.sessions.get(sessionId);
    if (!s || s.status !== 'active') return false;
    return this.workloads.get(s.workloadId).status !== 'isolated';
  }

  // Running workloads may reach anywhere. Isolated workloads may reach only
  // internal (RFC 1918) addresses.
  egressAllowed(workloadId, dstIp) {
    const w = this.workloads.get(workloadId);
    if (!w) return false;
    if (w.status !== 'isolated') return true;
    return isInternal(dstIp);
  }

  revokeSession(sessionId) {
    const s = this.sessions.get(sessionId);
    if (s.status === 'revoked') return false;
    s.status = 'revoked';
    s.revokedAt = new Date().toISOString();
    return true;
  }

  isolateWorkload(workloadId) {
    const w = this.workloads.get(workloadId);
    if (w.status === 'isolated') return false;
    w.status = 'isolated';
    w.isolatedAt = new Date().toISOString();
    return true;
  }

  snapshot() {
    return {
      workloads: [...this.workloads.values()],
      sessions: [...this.sessions.values()],
    };
  }
}

function isInternal(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(String(ip));
}

module.exports = { SimEnvironment, isInternal };
