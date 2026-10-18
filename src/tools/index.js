'use strict';

// Containment tools. Each tool declares its target, a read-only plan,
// the mutation, and a verification that checks the effect independently.
const TOOLS = {
  'session.revoke': require('./revoke-session'),
  'workload.isolate': require('./isolate-workload'),
};

module.exports = { TOOLS };
