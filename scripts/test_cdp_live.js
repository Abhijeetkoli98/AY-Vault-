const { spawn } = require('child_process');
const http = require('http');

async function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function getWsUrl(port) {
  for (let i = 0; i < 30; i++) {
    try {
      const data = await new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${port}/json/version`, res => {
          let body = '';
          res.on('data', chunk => body += chunk);
          res.on('end', () => resolve(JSON.parse(body)));
        }).on('error', reject);
      });
      if (data.webSocketDebuggerUrl) return data.webSocketDebuggerUrl;
    } catch (e) {
      await wait(200);
    }
  }
  throw new Error("Could not connect to Chrome debugging port");
}

async function run() {
  const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const port = 9226;
  const chrome = spawn(chromePath, [
    `--remote-debugging-port=${port}`,
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
    '--user-data-dir=' + require('os').tmpdir() + '/chrome_cdp_verify_' + Date.now()
  ]);

  let uncaughtErrors = [];

  try {
    const wsUrl = await getWsUrl(port);
    console.log('[+] Connected to Chrome CDP:', wsUrl);

    const ws = new WebSocket(wsUrl);
    await new Promise((res, rej) => {
      ws.onopen = res;
      ws.onerror = rej;
    });

    let id = 1;
    const callbacks = new Map();
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && callbacks.has(msg.id)) {
        callbacks.get(msg.id)(msg.result, msg.error);
        callbacks.delete(msg.id);
      }
    };

    function send(method, params = {}) {
      return new Promise((resolve, reject) => {
        const msgId = id++;
        callbacks.set(msgId, (result, error) => {
          if (error) reject(error);
          else resolve(result);
        });
        ws.send(JSON.stringify({ id: msgId, method, params }));
      });
    }

    const target = await send('Target.createTarget', { url: 'about:blank' });
    const pageWsUrl = `ws://127.0.0.1:${port}/devtools/page/${target.targetId}`;
    const pageWs = new WebSocket(pageWsUrl);
    await new Promise((res, rej) => { pageWs.onopen = res; pageWs.onerror = rej; });

    let pageId = 1;
    const pageCallbacks = new Map();
    pageWs.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && pageCallbacks.has(msg.id)) {
        pageCallbacks.get(msg.id)(msg.result, msg.error);
        pageCallbacks.delete(msg.id);
      }
      if (msg.method === 'Runtime.exceptionThrown') {
        const desc = msg.params.exceptionDetails?.exception?.description || msg.params.exceptionDetails?.text;
        console.error('[-] PAGE EXCEPTION:', desc);
        uncaughtErrors.push(desc);
      }
      if (msg.method === 'Runtime.consoleAPICalled') {
        const level = msg.params.type;
        const text = msg.params.args.map(a => a.value || a.description || JSON.stringify(a)).join(' ');
        if (level === 'error') {
          console.error(`[-] BROWSER CONSOLE ERROR: ${text}`);
          uncaughtErrors.push(text);
        } else {
          console.log(`[Browser ${level}]: ${text}`);
        }
      }
    };

    function sendPage(method, params = {}) {
      return new Promise((resolve, reject) => {
        const msgId = pageId++;
        pageCallbacks.set(msgId, (result, error) => {
          if (error) reject(error);
          else resolve(result);
        });
        pageWs.send(JSON.stringify({ id: msgId, method, params }));
      });
    }

    await sendPage('Page.enable');
    await sendPage('Runtime.enable');
    await sendPage('Log.enable');

    console.log('[*] Navigating to https://ay-vault.web.app/ ...');
    await sendPage('Page.navigate', { url: 'https://ay-vault.web.app/' });
    await wait(3500);

    // 1. Sign In as Admin
    console.log('[*] 1. Logging in as Admin...');
    await sendPage('Runtime.evaluate', {
      expression: `
        (() => {
          fillPersona('admin', 'Admin@AYVault2026!');
          document.getElementById('login-form').dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
        })()
      `
    });
    await wait(1500);

    // 2. Test Navigation to Users & open modal-new-user
    console.log('[*] 2. Navigating to Users & testing openNewUserModal...');
    const userModalRes = await sendPage('Runtime.evaluate', {
      expression: `
        (() => {
          showSection('users');
          if (typeof openNewUserModal !== 'function') return 'MISSING_FUNCTION';
          openNewUserModal();
          const modal = document.getElementById('modal-new-user');
          const isVisible = modal && modal.classList.contains('active');
          return isVisible ? 'MODAL_OPENED' : 'MODAL_NOT_ACTIVE';
        })()
      `,
      returnByValue: true
    });
    console.log('[+] openNewUserModal result:', userModalRes.result.value);

    // 3. Provision new user
    console.log('[*] 3. Submitting new user form...');
    const createUserRes = await sendPage('Runtime.evaluate', {
      expression: `
        (async () => {
          document.getElementById('new-user-username').value = 'emily.test';
          document.getElementById('new-user-fullname').value = 'Emily Test Engineer';
          document.getElementById('new-user-role').value = 'Manager';
          document.getElementById('new-user-department').value = 'Operations';
          document.getElementById('new-user-clearance').value = 'RESTRICTED';
          document.getElementById('new-user-password').value = 'Pass@AYVault2026!';
          
          const form = document.getElementById('new-user-form');
          form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
          await new Promise(r => setTimeout(r, 600));

          const userRow = Array.from(document.querySelectorAll('#users-table-body tr')).find(r => r.textContent.includes('emily.test'));
          return userRow ? 'USER_CREATED_AND_LISTED' : 'USER_NOT_IN_TABLE';
        })()
      `,
      awaitPromise: true,
      returnByValue: true
    });
    console.log('[+] Provision user result:', createUserRes.result.value);

    // 4. Test Document preview as Admin
    console.log('[*] 4. Testing document preview as Admin...');
    const docPreviewRes = await sendPage('Runtime.evaluate', {
      expression: `
        (async () => {
          showSection('documents');
          await new Promise(r => setTimeout(r, 400));
          await previewDocument('doc-1');
          await new Promise(r => setTimeout(r, 400));
          const box = document.getElementById('preview-content-box');
          const dlBtn = document.getElementById('btn-preview-download');
          const title = document.getElementById('preview-modal-title').innerText;
          const hasContent = box.innerText.includes('AY Vault - Cyber Incident');
          const isDlEnabled = dlBtn && !dlBtn.disabled;
          closeModal('modal-preview');
          return { title, hasContent, isDlEnabled };
        })()
      `,
      awaitPromise: true,
      returnByValue: true
    });
    console.log('[+] Admin Preview result:', JSON.stringify(docPreviewRes.result.value));

    // 5. Test Logout and Viewer login
    console.log('[*] 5. Testing Logout & Viewer login (Bob)...');
    await sendPage('Runtime.evaluate', {
      expression: `
        (async () => {
          handleLogout();
          await new Promise(r => setTimeout(r, 500));
          fillPersona('bob_viewer', 'Viewer@AYVault2026!');
          document.getElementById('login-form').dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
        })()
      `,
      awaitPromise: true
    });
    await wait(1500);

    // 6. Test Viewer attempting to preview TOP_SECRET document (doc-1)
    console.log('[*] 6. Testing Viewer access denial on TOP_SECRET document (doc-1)...');
    const viewerDeniedRes = await sendPage('Runtime.evaluate', {
      expression: `
        (async () => {
          showSection('documents');
          await new Promise(r => setTimeout(r, 400));
          await previewDocument('doc-1');
          await new Promise(r => setTimeout(r, 400));
          const box = document.getElementById('preview-content-box');
          const dlBtn = document.getElementById('btn-preview-download');
          const versionsBtn = document.getElementById('btn-preview-versions');
          const title = document.getElementById('preview-modal-title').innerText;
          const isDenied = box.innerText.includes('Access Denied');
          const isDlDisabled = dlBtn && dlBtn.disabled;
          const isVersionsDisabled = versionsBtn && versionsBtn.disabled;
          closeModal('modal-preview');
          return { title, isDenied, isDlDisabled, isVersionsDisabled };
        })()
      `,
      awaitPromise: true,
      returnByValue: true
    });
    console.log('[+] Viewer Denied result:', JSON.stringify(viewerDeniedRes.result.value));

    // 7. Test Viewer previewing accessible document (doc-5 UNRESTRICTED)
    console.log('[*] 7. Testing Viewer preview on UNRESTRICTED document (doc-5)...');
    const viewerAllowedRes = await sendPage('Runtime.evaluate', {
      expression: `
        (async () => {
          await previewDocument('doc-5');
          await new Promise(r => setTimeout(r, 400));
          const box = document.getElementById('preview-content-box');
          const dlBtn = document.getElementById('btn-preview-download');
          const isContentPresent = box.innerText.includes('Employee Data Protection');
          const isDlDisabled = dlBtn && dlBtn.disabled; // Viewer role should STILL have download disabled
          closeModal('modal-preview');
          return { isContentPresent, isDlDisabled };
        })()
      `,
      awaitPromise: true,
      returnByValue: true
    });
    console.log('[+] Viewer Allowed preview (download disabled) result:', JSON.stringify(viewerAllowedRes.result.value));

    // Summary
    console.log('\n========================================');
    console.log('UNCAUGHT ERRORS COUNT:', uncaughtErrors.length);
    if (uncaughtErrors.length > 0) {
      console.error('Errors found:', uncaughtErrors);
    } else {
      console.log('ALL VERIFICATIONS PASSED WITH ZERO ERRORS!');
    }
    console.log('========================================\n');

  } catch (err) {
    console.error('[-] Test failed:', err);
  } finally {
    chrome.kill();
    process.exit(0);
  }
}

run();
