'use strict';

const http = require('node:http');
const { createSystem } = require('./system');
const { httpError } = require('./errors');
const { renderCasesPage } = require('./ui');
const { provisionDemo, makeEmitter, runBaseline, runCompromise } = require('./simulator');

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1e6) reject(httpError(413, 'body too large'));
    });
    req.on('end', () => {
      if (!data) return resolve(undefined);
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(httpError(400, 'invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function route(sys, method, parts, body) {
  const key = `${method} /${parts.join('/')}`;
  if (key === 'POST /events') {
    if (Array.isArray(body)) return body.map((e) => sys.ingest.ingest(e));
    return sys.ingest.ingest(body);
  }
  if (key === 'GET /environment') return sys.env.snapshot();
  if (key === 'GET /cases') return sys.cases.listCases();
  if (parts[0] === 'cases' && parts.length === 2 && method === 'GET') return sys.cases.view(parts[1]);
  if (parts[0] === 'cases' && parts[2] === 'proposals' && method === 'POST') {
    return sys.containment.propose({ caseId: parts[1], ...body });
  }
  if (parts[0] === 'proposals' && parts.length === 3 && method === 'POST') {
    const [, id, action] = parts;
    if (action === 'approve') return sys.containment.approve({ proposalId: id, approver: body && body.approver });
    if (action === 'reject') return sys.containment.reject({ proposalId: id, approver: body && body.approver, reason: body && body.reason });
    if (action === 'execute') return sys.containment.execute({ proposalId: id, actor: body && body.actor });
  }
  if (key === 'POST /simulate') {
    const demo = provisionDemo(sys.env);
    const emit = makeEmitter(sys.ingest, 'sim');
    runBaseline({ env: sys.env, emit, ...demo });
    runCompromise({ env: sys.env, emit, ...demo });
    return { provisioned: demo, cases: sys.cases.listCases() };
  }
  throw httpError(404, `no route for ${key}`);
}

function createServer(sys = createSystem()) {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const parts = url.pathname.split('/').filter(Boolean);
    try {
      if (req.method === 'GET' && url.pathname === '/ui') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(renderCasesPage(sys.cases));
      }
      const body = req.method === 'POST' ? await readBody(req) : undefined;
      const out = route(sys, req.method, parts, body);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(out, null, 2));
    } catch (err) {
      res.writeHead(err.status || 500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 8080;
  createServer().listen(port, () => {
    console.log(`ContainOps listening on http://localhost:${port}  (UI: /ui)`);
  });
}

module.exports = { createServer };
