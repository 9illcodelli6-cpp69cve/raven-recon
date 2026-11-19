/* Local DOM regression checks. Requires Playwright; set RAVEN_TEST_BROWSER to an
   installed Chromium executable if needed. Every URL is intercepted: no app,
   target, CDN, or network service is contacted. Marker strings contain no code. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { chromium } = require('playwright');

const html = fs.readFileSync(path.join(__dirname, '../web/prototype.html'), 'utf8');
for (const match of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) {
  if (match[1].trim()) new vm.Script(match[1]);
}
const origin = 'http://127.0.0.1:19541';
const marker = '<raven-inert>text & "quote" \'single\'</raven-inert>';

(async () => {
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.RAVEN_TEST_BROWSER ? { executablePath: process.env.RAVEN_TEST_BROWSER } : {}),
  });
  try {
    const context = await browser.newContext({ serviceWorkers: 'block' });
    const page = await context.newPage();
    const pageErrors = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    const traffic = { intercepted: 0, abortedExternal: 0, unexpectedSend: 0 };
    let scopeReply = { status: 400, body: { error: marker } };
    const initialIdentity = { user_agent_key: 'custom', user_agent: 'UI regression check',
      ua_catalog: {}, search_headers: { 'X-Workspace-Label': 'initial-local-fixture' } };
    let identityGetReply = { status: 200, body: initialIdentity };
    let identityPutReply = { status: 200, body: initialIdentity };
    let scopeGetBody = { name: 'old-workspace', include: ['old.test'], data_path: 'local-test-only' };
    let releaseScope = null;
    let waitForScope = null;
    let scopeRequested = false;
    await context.route('**/*', async route => {
      traffic.intercepted++;
      const url = new URL(route.request().url());
      if (url.origin !== origin) { traffic.abortedExternal++; return route.abort(); }
      if (url.pathname === '/') return route.fulfill({ contentType: 'text/html', body: html });
      let body = {};
      let status = 200;
      if (url.pathname === '/api/scope') {
        if (route.request().method() === 'PUT') {
          scopeRequested = true;
          if (waitForScope) await waitForScope;
          ({ body, status } = scopeReply);
        } else body = scopeGetBody;
      } else if (url.pathname === '/api/identity') {
        ({ body, status } = route.request().method() === 'PUT' ? identityPutReply : identityGetReply);
      } else if (url.pathname === '/api/summary') body = { assets: 0, http: 0, urls: 0, families: 0 };
      else if (['/api/assets', '/api/urls', '/api/changes', '/api/runs'].includes(url.pathname)) body = [];
      else if (url.pathname === '/api/jobs') body = { jobs: [], stats: {} };
      else if (url.pathname === '/api/xss-verify-isolation') body = { ok: false, disabled: true, reason: 'disabled' };
      else if (url.pathname === '/api/send') {
        traffic.unexpectedSend++;
        status = 503;
        body = { error: 'UI test must stub apiSend; no target request is permitted' };
      }
      return route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    });
    await page.goto(origin + '/', { waitUntil: 'load' });
    await page.waitForFunction(() => document.getElementById('wsName').textContent === 'old-workspace'
      && document.getElementById('rows').textContent.includes('No assets yet')
      && !document.getElementById('rSend').disabled);
    assert.deepEqual(await page.evaluate(() => identityHeaders()), initialIdentity.search_headers,
      'startup must hydrate exactly the configured research headers');
    await page.evaluate(() => document.querySelector('.ws-opt[data-ws]').click());
    assert.equal(await page.locator('#wsName').innerText(), 'old-workspace');
    assert.equal(await page.locator('.ws-opt[data-ws]').first().isVisible(), false);

    const renderingChecks = await page.evaluate(async marker => {
      let checks = 0;
      function assertLiteral(root, label = root.id || 'rendered output') {
        if (root.querySelector('raven-inert')) throw new Error(label + ': marker was parsed as an element');
        if (!root.textContent.includes(marker)) throw new Error(label + ': marker text changed or disappeared');
        checks++;
      }
      const response = document.getElementById('rResp');
      const success = { status: 200, reason: 'OK', elapsed_ms: 1, bytes: 4, headers: {}, body: 'text' };
      const cases = [
        { blocked: true, error: marker }, { error: marker },
        { ...success, reason: marker }, { ...success, body: marker },
        { ...success, headers: { [marker]: marker } },
      ];
      for (const item of cases) { response.innerHTML = fmtResp(item); assertLiteral(response); }
      const aclCases = [
        { error: marker }, { refused: marker },
        { method: marker, url: marker, note: marker },
        { results: [{ ok: true, label: marker, status: 200, bytes: 4,
          content_type: marker, credential_preview: marker }] },
        { results: [{ ok: true, label: 'fixture', status: marker, bytes: marker }] },
        { results: [{ ok: false, label: marker, error: marker }] },
        { comparisons: [{ verdict: marker, label: marker, reason: marker }] },
      ];
      const aclOutput = document.getElementById('acResults');
      for (const [index, item] of aclCases.entries()) {
        aclOutput.innerHTML = acRender(item); assertLiteral(aclOutput, 'ACL rendering case ' + index);
      }
      const xssCases = [
        { error: marker }, { refused: marker },
        { method: marker, url: marker, param: marker, status: marker,
          content_type: marker, canary: marker, verdict: marker, note: marker },
        { reflections: [{ offset: marker, context: marker, raw_chars: [marker], surrounding: marker }] },
        { note: marker, execution_confirmation: { attempted: true, executed: true, reason: marker } },
      ];
      const xssOutput = document.getElementById('xsResults');
      for (const [index, item] of xssCases.entries()) {
        xssOutput.innerHTML = xsRender(item); assertLiteral(xssOutput, 'XSS rendering case ' + index);
      }
      if (xssOutput.textContent.includes('EXECUTION CONFIRMED') || !xssOutput.textContent.includes('Browser execution disabled')) {
        throw new Error('stale execution success must not re-enable the quarantined UI');
      }
      const savedApiSend = apiSend;
      try {
        apiSend = async () => { throw new Error(marker); };
        await document.getElementById('rSend').onclick();
        assertLiteral(response);

        for (const item of cases) {
          apiSend = async () => item;
          termBody.replaceChildren();
          CMDS.curl('http://example.invalid/');
          await Promise.resolve();
          if (item.headers) {
            // The curl view does not display response headers.
            if (item.reason !== marker && item.body !== marker && !item.error) continue;
          }
          assertLiteral(termBody);
        }
        apiSend = async () => { throw new Error(marker); };
        termBody.replaceChildren();
        CMDS.curl('http://example.invalid/');
        await Promise.resolve();
        assertLiteral(termBody);

        apiSend = async () => ({ ...success, status: marker, bytes: marker, elapsed_ms: marker });
        document.getElementById('iPayloads').value = marker;
        document.getElementById('iUrl').value = 'http://example.invalid/§value§';
        await document.getElementById('intrStart').onclick();
        const cells = document.querySelectorAll('#iRows tr:first-child td');
        for (const cell of Array.from(cells).slice(1)) assertLiteral(cell);
      } finally { apiSend = savedApiSend; }

      document.getElementById('ntDomain').value = marker;
      ntRender();
      const preview = document.getElementById('ntPrev');
      if (preview.querySelector('raven-inert') || !preview.textContent.includes(JSON.stringify([marker]))) {
        throw new Error('scope preview did not preserve escaped JSON text');
      }
      checks++;
      renderWorkspaceScope({ name: marker, include: [marker] });
      assertLiteral(document.querySelector('.scope-badge'));
      if (document.getElementById('crumb').querySelector('raven-inert')) throw new Error('unsafe breadcrumb');
      renderWorkspaceScope({ name: 'old-workspace', include: ['old.test'] });
      document.getElementById('rows').textContent = 'existing evidence';
      return checks;
    }, marker);

    identityPutReply = { status: 500, body: { ...initialIdentity, error: marker } };
    await page.evaluate(() => applyUA('custom', 'must not become active'));
    assert.deepEqual(await page.evaluate(() => identityState), initialIdentity);
    assert.equal(await page.locator('#rSend').isDisabled(), true);
    assert.equal(await page.locator('raven-inert').count(), 0);
    identityPutReply = { status: 200, body: {} };
    await page.evaluate(() => applyUA('custom', 'invalid response'));
    assert.deepEqual(await page.evaluate(() => identityState), initialIdentity);
    identityPutReply = { status: 200, body: { ...initialIdentity, user_agent: 'New local profile' } };
    await page.evaluate(async () => {
      document.getElementById('rReq').value = 'POST /local HTTP/1.1\nUser-Agent: old\nX-Keep: local\n\nUser-Agent: body text';
      await applyUA('custom', 'New local profile');
    });
    assert.equal(await page.locator('#rReq').inputValue(),
      'POST /local HTTP/1.1\nUser-Agent: New local profile\nX-Keep: local\n\nUser-Agent: body text');
    assert.deepEqual(await page.evaluate(() => identityHeaders()), initialIdentity.search_headers);
    assert.equal(await page.locator('#rSend').isDisabled(), false);
    assert.equal(await page.locator('#xsConfirm').count(), 0);
    assert.match(await page.locator('#xsIsoStatus').innerText(), /execution disabled/i);
    assert.equal(await page.evaluate(() => buildReq('GET', 'http://local.test/').includes('undefined')), false);

    const previous = await page.evaluate(() => ({
      name: document.getElementById('wsName').textContent,
      crumb: document.getElementById('crumb').textContent,
      scope: document.querySelector('.scope-badge').textContent,
      evidence: document.getElementById('rows').textContent,
    }));
    const readDisplay = () => page.evaluate(() => ({
      name: document.getElementById('wsName').textContent,
      crumb: document.getElementById('crumb').textContent,
      scope: document.querySelector('.scope-badge').textContent,
      evidence: document.getElementById('rows').textContent,
    }));

    waitForScope = new Promise(resolve => { releaseScope = resolve; });
    await page.evaluate(() => {
      ntOpen(); document.getElementById('ntDomain').value = 'new.test';
      document.getElementById('ntCreate').click();
    });
    for (let i = 0; i < 50 && !scopeRequested; i++) await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(scopeRequested, true, 'scope update was submitted');
    assert.deepEqual(await readDisplay(), previous, 'pending request must preserve the current workspace');
    releaseScope();
    await page.waitForFunction(() => !document.getElementById('ntCreate').disabled);
    assert.deepEqual(await readDisplay(), previous, 'rejected update must preserve labels and evidence');
    assert.equal(await page.locator('#ntModal').evaluate(node => node.classList.contains('open')), true);
    assert.equal(await page.locator('raven-inert').count(), 0);

    waitForScope = null;
    scopeReply = { status: 500, body: { name: 'uncommitted', include: ['uncommitted.test'] } };
    await page.evaluate(() => document.getElementById('ntCreate').click());
    await page.waitForFunction(() => !document.getElementById('ntCreate').disabled);
    assert.deepEqual(await readDisplay(), previous, 'HTTP failure must not be treated as success');

    scopeReply = { status: 200, body: {} };
    await page.evaluate(() => document.getElementById('ntCreate').click());
    await page.waitForFunction(() => !document.getElementById('ntCreate').disabled);
    assert.deepEqual(await readDisplay(), previous, 'invalid response must preserve the current workspace');

    scopeReply = { status: 200, body: { name: 'server-canonical-name', include: ['canonical.test'] } };
    identityGetReply = { status: 200, body: { ...initialIdentity, search_headers: {} } };
    await page.evaluate(() => {
      document.getElementById('acCookieA').value = 'local owner fixture';
      document.getElementById('acCookieB').value = 'local other fixture';
      document.getElementById('iPayloads').value = 'old workspace text';
    });
    await page.evaluate(() => document.getElementById('ntCreate').click());
    await page.waitForFunction(() => !document.getElementById('ntCreate').disabled);
    assert.equal((await readDisplay()).name, 'server-canonical-name');
    assert.equal((await readDisplay()).scope, 'canonical.test');
    assert.equal(await page.locator('#ntModal').evaluate(node => node.classList.contains('open')), false);
    assert.deepEqual(await page.evaluate(() => identityHeaders()), {});
    for (const id of ['rReq', 'acCookieA', 'acCookieB', 'iPayloads']) {
      assert.equal(await page.locator('#' + id).inputValue(), '', 'workspace switch clears ' + id);
    }
    assert.equal(await page.locator('#rSend').isDisabled(), false);
    identityGetReply = { status: 503, body: { error: 'local identity load failure' } };
    await page.evaluate(async () => { try { await refreshIdentity(); } catch {} });
    assert.equal(await page.locator('#rSend').isDisabled(), true);
    identityGetReply = { status: 200, body: initialIdentity };
    await page.evaluate(() => refreshIdentity());
    assert.equal(await page.locator('#rSend').isDisabled(), false);
    scopeGetBody = { name: 'invalid-settings', include: [], configuration_error: 'local saved settings require recovery' };
    await page.reload({ waitUntil: 'load' });
    await page.waitForFunction(() => document.getElementById('workspaceNotice').textContent.includes('local saved settings require recovery'));
    assert.equal(await page.locator('#rSend').isDisabled(), true);
    assert.equal(traffic.unexpectedSend, 0, 'no request may reach the outbound API');
    assert.deepEqual(pageErrors, []);
    console.log(JSON.stringify({ passed: true, renderingChecks, workspaceChecks: 5, identityAndRecoveryChecks: true,
      traffic, allPageRequestsIntercepted: true, pageErrors }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
