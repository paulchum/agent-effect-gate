'use strict';
const $ = id => document.getElementById(id);
let session = null, selected = null, offset = 0, nextOffset = null;
let queueGeneration = 0, detailGeneration = 0, busy = false;
const humanTime = value => new Date(value * 1000).toLocaleString();
function notice(text, error = false) {
  $('message').textContent = text; $('message').className = error ? 'message error' : 'message'; $('message').hidden = false;
}
function element(tag, text, className) {
  const node = document.createElement(tag); if (text !== undefined) node.textContent = text;
  if (className) node.className = className; return node;
}
function showLogin() {
  session = null; selected = null; ++queueGeneration; ++detailGeneration;
  $('workspace').hidden = true; $('identity').hidden = true; $('login').hidden = false;
  $('queue').replaceChildren(); $('events').replaceChildren(); $('prepared').textContent = ''; $('manifest').textContent = '';
  $('payload-base64').textContent = ''; $('upload-text').textContent = ''; $('upload-meta').textContent = ''; $('upload-preview').hidden = true; $('detail').hidden = true; $('detail-empty').hidden = false;
}
async function api(path, data) {
  const options = {credentials: 'same-origin', headers: {}};
  if (data !== undefined) {
    options.method = 'POST'; options.headers['Content-Type'] = 'application/json';
    if (session) options.headers['X-CSRF-Token'] = session.csrf;
    options.body = JSON.stringify(data);
  }
  const response = await fetch(path, options);
  const body = await response.json();
  if (!response.ok) {
    if (response.status === 401) showLogin();
    const labels = {not_authenticated: 'Sign in with a valid reviewer account.', csrf_required: 'Your session changed. Reload and sign in again.',
      rate_limited: 'Too many sign-in attempts. Try again after the displayed retry interval.',
      review_changed_refresh_required: 'This request changed. Refresh and review its current details before deciding.',
      approval_binding_changed: 'The policy or adapter changed. This request needs a new proposal.',
      task_suspended: 'This task is suspended. An operator must resume it before approval.'};
    throw new Error(labels[body.error] || `Request stopped: ${body.error || response.status}`);
  }
  return body;
}
async function signIn(result) {
  session = result; $('username').textContent = result.username;
  $('login').hidden = true; $('identity').hidden = false; $('workspace').hidden = false;
  $('password').value = ''; $('message').hidden = true; offset = 0; await refresh();
}
async function refresh() {
  if (!session) return;
  const currentSession = session;
  const info = await api('/api/overview');
  if (session !== currentSession) return;
  $('pending-count').textContent = info.pending; $('nav-count').textContent = info.pending;
  $('actions-count').textContent = info.tasks.reduce((sum, task) => sum + task.budgets.actions.remaining, 0).toLocaleString();
  $('reads-count').textContent = info.tasks.reduce((sum, task) => sum + task.budgets.reads.remaining, 0).toLocaleString();
  $('reads-note').textContent = `${info.tasks.reduce((sum, task) => sum + task.budgets.retries.remaining, 0).toLocaleString()} retries remaining · independently limited`;
  $('actions-note').textContent = `${info.tasks.length} assigned task${info.tasks.length === 1 ? '' : 's'} · trusted host snapshots are free`;
  $('task-scope').replaceChildren(...info.tasks.map(task => element('span', `${task.id}${task.suspended ? ' · suspended' : ''}`, 'scope-chip')));
  $('events').replaceChildren(...info.events.map(event => {
    const row = element('tr');
    for (const value of [event.kind, event.task, event.agent, humanTime(event.timestamp)]) row.append(element('td', value));
    return row;
  }));
  await loadQueue();
}
async function loadQueue() {
  const generation = ++queueGeneration;
  const result = await api(`/api/queue?state=${encodeURIComponent($('state-filter').value)}&offset=${offset}`);
  if (generation !== queueGeneration || !session) return;
  nextOffset = result.next_offset; $('previous').disabled = offset === 0; $('next').disabled = nextOffset === null;
  $('page-number').textContent = `Page ${Math.floor(offset / 25) + 1}`;
  const cards = result.items.map(item => {
    const button = element('button', undefined, 'request-card'); button.type = 'button';
    if (selected && selected.id === item.id) button.classList.add('selected');
    const title = element('span', undefined, 'title'); title.append(element('span', item.destination), element('span', item.state, `badge ${item.state.toLowerCase()}`));
    button.append(title, element('span', `${item.task_id} · ${item.agent}`, 'sub'), element('span', item.id, 'record-id'));
    button.addEventListener('click', () => openDetail(item).catch(error => notice(error.message, true))); return button;
  });
  $('queue').replaceChildren(...(cards.length ? cards : [element('p', 'No requests in this view. Refresh after an agent proposes an effect.', 'empty-queue')]));
}
async function openDetail(item) {
  const generation = ++detailGeneration;
  // Disable the old decision controls immediately; late responses never select
  // a different request underneath an in-flight reviewer decision.
  selected = null; $('approve').disabled = true; $('reject').disabled = true; $('acknowledge').checked = false;
  const value = await api(`/api/review/${item.kind}/${encodeURIComponent(item.id)}`);
  if (generation !== detailGeneration || !session) return;
  selected = value; $('detail-empty').hidden = true; $('detail').hidden = false;
  $('detail-kind').textContent = `${value.kind === 'tool' ? 'TOOL INVOCATION' : 'EXTERNAL RELEASE'} · EXACT REVIEW`;
  $('detail-title').textContent = value.tool_id || value.manifest.id || 'External release';
  $('detail-state').textContent = value.state; $('detail-state').className = `badge ${value.state.toLowerCase()}`;
  const metadata = [['Task', value.task_id], ['Agent', value.agent], ['Request', value.id],
                    ['Policy', `v${value.policy_version} · current v${value.current_policy_version}`],
                    ['Created', humanTime(value.created_at)], ['Approval TTL', `${value.approval_ttl_seconds} seconds`]];
  if (value.manifest.transport?.origin) metadata.unshift(['Destination', value.manifest.transport.origin + (value.prepared_request?.target || '')]);
  metadata.unshift(['Effect', (value.manifest.effect || value.kind).replaceAll('_', ' ')]);
  if (value.approver) metadata.push(['Reviewer', value.approver]);
  if (value.expires_at) metadata.push(['Expires', humanTime(value.expires_at)]);
  $('detail-meta').replaceChildren(...metadata.flatMap(([key, text]) => [element('dt', key), element('dd', text)]));
  $('review-warning').textContent = `${value.task_suspended ? 'TASK SUSPENDED. ' : ''}${!value.binding_current ? 'STALE POLICY OR ADAPTER. ' : ''}${value.warning}`;
  // Never use innerHTML, Markdown rendering, eval or an iframe for agent content.
  $('manifest').textContent = JSON.stringify(value.manifest, null, 2);
  const upload = value.payload_preview;
  $('upload-preview').hidden = !upload;
  $('upload-text').textContent = upload ? (upload.text ?? 'Binary payload. Review the exact base64 bytes and verify the SHA-256.') : '';
  $('upload-meta').textContent = upload ? `${upload.media_type} · ${upload.byte_length} bytes · SHA-256 ${upload.sha256}` : '';
  $('payload-extra').hidden = value.kind !== 'release' && !upload;
  if (value.kind === 'tool') {
    $('payload-label').textContent = 'Exact prepared request'; $('prepared').textContent = JSON.stringify(value.prepared_request, null, 2);
    $('payload-base64').textContent = upload ? upload.data_b64 : '';
  } else {
    $('payload-label').textContent = 'Payload preview · UTF-8 text, not active content';
    $('payload-base64').textContent = value.payload_b64;
    try { $('prepared').textContent = new TextDecoder('utf-8', {fatal: true}).decode(Uint8Array.from(atob(value.payload_b64), char => char.charCodeAt(0))); }
    catch { $('prepared').textContent = 'Binary payload. Review the exact base64 bytes below and verify the SHA-256.'; }
  }
  $('request-hash').textContent = value.request_sha256 || value.payload_sha256;
  $('reject').disabled = !['PENDING', 'APPROVED'].includes(value.state);
  $('reject').textContent = value.state === 'APPROVED' ? 'Revoke approval' : 'Reject request';
  $('acknowledge').disabled = !value.can_approve;
  $('approve').textContent = value.approval_expired ? 'Renew exact approval' : 'Approve request';
  $('decision-note').textContent = (value.approval_expired ? 'This approval expired. Review the same bound request before renewing. ' : '') + 'Approval does not dispatch the effect. The agent must call execute after approval.';
  await loadQueue();
}
async function decide(decision) {
  if (!selected || busy || (decision === 'approve' && !$('acknowledge').checked)) return;
  busy = true; const value = selected; $('approve').disabled = true; $('reject').disabled = true;
  try {
    const result = await api('/api/decision', {kind: value.kind, id: value.id, decision, review_token: value.review_token});
    notice(`${result.state === 'APPROVED' ? 'Approved' : 'Rejected / revoked'} by ${session.username}. The decision is recorded in the audit journal.`);
    await openDetail(value); await refresh();
  } catch (error) { notice(error.message, true); }
  finally { busy = false; if (selected && selected.id === value.id) $('reject').disabled = !['PENDING', 'APPROVED'].includes(selected.state); }
}
$('login-form').addEventListener('submit', async event => {
  event.preventDefault(); $('sign-in').disabled = true;
  try { await signIn(await api('/api/login', {username: $('user').value, password: $('password').value})); }
  catch (error) { notice(error.message, true); $('password').value = ''; }
  finally { $('sign-in').disabled = false; }
});
$('logout').addEventListener('click', async () => { try { await api('/api/logout', {}); showLogin(); } catch (error) { notice(error.message, true); } });
$('refresh').addEventListener('click', () => refresh().catch(error => notice(error.message, true)));
$('state-filter').addEventListener('change', () => { offset = 0; loadQueue().catch(error => notice(error.message, true)); });
$('previous').addEventListener('click', () => { offset = Math.max(0, offset - 25); loadQueue().catch(error => notice(error.message, true)); });
$('next').addEventListener('click', () => { if (nextOffset !== null) offset = nextOffset; loadQueue().catch(error => notice(error.message, true)); });
$('acknowledge').addEventListener('change', () => { $('approve').disabled = busy || !$('acknowledge').checked || !selected || !selected.can_approve; });
$('approve').addEventListener('click', () => decide('approve')); $('reject').addEventListener('click', () => decide('reject'));
api('/api/session').then(signIn).catch(() => showLogin());
