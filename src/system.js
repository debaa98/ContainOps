'use strict';

const { SimEnvironment } = require('./env');
const { CaseStore } = require('./cases');
const { Ingestor } = require('./ingest');
const { ContainmentService } = require('./containment');
const { TOOLS } = require('./tools');

function createSystem() {
  const env = new SimEnvironment();
  const cases = new CaseStore();
  const ingest = new Ingestor({ env, cases });
  const containment = new ContainmentService({ env, cases, tools: TOOLS });
  return { env, cases, ingest, containment };
}

module.exports = { createSystem };
