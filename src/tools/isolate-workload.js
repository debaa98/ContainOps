'use strict';

// Probe destination used to confirm external egress is blocked (TEST-NET-3).
const PROBE_EXTERNAL_IP = '203.0.113.1';

module.exports = {
  name: 'workload.isolate',
  description: 'Isolate a workload: block non-internal egress and reject its sessions.',
  target: { kind: 'workload', param: 'workloadId' },

  plan(env, { workloadId }) {
    const w = env.workloads.get(workloadId);
    const active = env.sessionsOn(workloadId).filter((s) => s.status === 'active').length;
    return {
      summary: `Isolate workload ${workloadId} (${w.name})`,
      blastRadius: `Service ${w.name} stops serving traffic. ${active} active session(s) lose access. External egress is blocked.`,
      reversible: true,
    };
  },

  execute(env, { workloadId }) {
    return env.isolateWorkload(workloadId);
  },

  verify(env, { workloadId }) {
    return env.workloads.get(workloadId).status === 'isolated' && !env.egressAllowed(workloadId, PROBE_EXTERNAL_IP);
  },
};
