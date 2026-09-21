const state = { arena: null };
const $ = (id) => document.getElementById(id);

async function json(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) throw Object.assign(new Error('request_failed'), { status: response.status, body: await response.json().catch(() => ({})) });
  return response.status === 204 ? null : response.json();
}

async function loadArena() {
  state.arena = await json('/api/v1/arena');
  $('status').textContent = `场次 ${state.arena.epoch} · ${state.arena.status}` +
    (state.arena.winner ? ` · 通关者 ${state.arena.winner.github_login}` : '');
  $('language').replaceChildren(...state.arena.supported_languages.map((language) => {
    const option = document.createElement('option'); option.value = language; option.textContent = language; return option;
  }));
  $('submit').disabled = state.arena.status !== 'OPEN';
}

async function loadPreview() {
  try {
    const preview = await json('/api/v1/arena/preview');
    $('preview').textContent = preview.challenge.question;
  } catch (_) { $('preview').textContent = '预览暂时不可用'; }
}

async function pollSubmission(id) {
  for (;;) {
    const value = await json(`/api/v1/submissions/${encodeURIComponent(id)}`);
    $('result').textContent = JSON.stringify(value, null, 2);
    if (['COMPILE_ERROR','RUNTIME_ERROR','TIMED_OUT','OUTPUT_LIMIT_EXCEEDED','INVALID_OUTPUT','CHALLENGE_EXPIRED','WRONG_ANSWER','PASSED','CORRECT_BUT_LOST_RACE','ARENA_CLOSED','INTERNAL_ERROR'].includes(value.status)) return;
    await new Promise((resolve) => setTimeout(resolve, 700));
  }
}

async function submit(savedDraft) {
  const draft = savedDraft || {
    epoch: state.arena.epoch,
    language: $('language').value,
    source: $('source').value,
    publication_agreed: $('consent').checked,
    idempotency_key: crypto.randomUUID(),
  };
  sessionStorage.setItem('arena_draft', JSON.stringify(draft));
  try {
    const accepted = await json('/api/v1/submissions', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify(draft) });
    sessionStorage.removeItem('arena_draft');
    await pollSubmission(accepted.submission_id);
  } catch (error) {
    if (error.status === 401) { location.assign('/auth/github/start'); return; }
    $('result').textContent = JSON.stringify(error.body || {error: error.message}, null, 2);
  }
}

$('submit').addEventListener('click', submit);
Promise.all([loadArena(), loadPreview()]).then(async () => {
  const draft = sessionStorage.getItem('arena_draft');
  if (!draft) return;
  try {
    const value = JSON.parse(draft);
    $('source').value = value.source; $('language').value = value.language; $('consent').checked = value.publication_agreed;
    const me = await fetch('/api/v1/me');
    if (me.ok) await submit(value);
  } catch (_) { sessionStorage.removeItem('arena_draft'); }
});
new EventSource('/api/v1/arena/events').addEventListener('arena_solved', () => loadArena());
setInterval(loadPreview, 10000);
setInterval(loadArena, 2000);
