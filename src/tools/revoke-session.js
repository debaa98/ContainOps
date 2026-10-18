'use strict';

module.exports = {
  name: 'session.revoke',
  description: 'Revoke one identity session so its token stops authorizing requests.',
  target: { kind: 'session', param: 'sessionId' },

  plan(env, { sessionId }) {
    const s = env.sessions.get(sessionId);
    return {
      summary: `Revoke session ${sessionId} (${s.user}) on ${s.workloadId}`,
      blastRadius: `1 session. ${s.user} must sign in again on every client.`,
      reversible: true,
    };
  },

  execute(env, { sessionId }) {
    return env.revokeSession(sessionId);
  },

  verify(env, { sessionId }) {
    return env.sessions.get(sessionId).status === 'revoked' && !env.authorize(sessionId);
  },
};
