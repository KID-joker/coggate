import * as monaco from 'monaco-editor/editor/editor.api.js';
import EditorWorker from 'monaco-editor/editor/editor.worker.js?worker';
import 'monaco-editor/languages/definitions/cpp/register.js';
import 'monaco-editor/languages/definitions/go/register.js';
import 'monaco-editor/languages/definitions/java/register.js';
import 'monaco-editor/languages/definitions/javascript/register.js';
import 'monaco-editor/languages/definitions/python/register.js';
import 'monaco-editor/languages/definitions/rust/register.js';
import './style.css';

import { languageFiles, languageLabels, monacoLanguages, templates } from './templates';
import type {
  Accepted,
  ApiErrorBody,
  Arena,
  Draft,
  Language,
  Me,
  Preview,
  PreviewVerification,
  Quota,
  Submission,
} from './types';

type WorkerScope = typeof self & {
  MonacoEnvironment: { getWorker: () => Worker };
};

(self as WorkerScope).MonacoEnvironment = {
  getWorker: () => new EditorWorker(),
};

const TERMINAL = new Set([
  'COMPILE_ERROR',
  'RUNTIME_ERROR',
  'TIMED_OUT',
  'OUTPUT_LIMIT_EXCEEDED',
  'INVALID_OUTPUT',
  'CHALLENGE_EXPIRED',
  'WRONG_ANSWER',
  'PASSED',
  'CORRECT_BUT_LOST_RACE',
  'ARENA_CLOSED',
  'INTERNAL_ERROR',
]);

const verdicts: Record<string, { title: string; description: string; tone: 'running' | 'success' | 'error'; icon: string }> = {
  ACCEPTED: { title: 'Queued', description: 'Waiting for a secure execution slot.', tone: 'running', icon: '…' },
  COMPILING: { title: 'Compiling', description: 'Building the source with the selected fixed toolchain.', tone: 'running', icon: '…' },
  READY: { title: 'Compilation complete', description: 'Generating the actual challenge for this run.', tone: 'running', icon: '…' },
  CHALLENGE_ISSUED: { title: 'Challenge issued', description: 'The actual challenge is now bound to this submission.', tone: 'running', icon: '…' },
  RUNNING: { title: 'Running in isolation', description: 'Network access is disabled and execution resources are limited.', tone: 'running', icon: '…' },
  VERIFYING: { title: 'Verifying answer', description: 'CogGate is validating the program output.', tone: 'running', icon: '…' },
  VERIFIED_ACCEPTED_PENDING_FINALIZE: { title: 'Correct answer', description: 'Atomically confirming the first solver.', tone: 'running', icon: '…' },
  PASSED: { title: 'Challenge cleared', description: 'You are the first solver. The arena is now closed.', tone: 'success', icon: '✓' },
  CORRECT_BUT_LOST_RACE: { title: 'Correct, but not first', description: 'Another solver completed finalization first.', tone: 'error', icon: '!' },
  COMPILE_ERROR: { title: 'Compilation failed', description: 'Open the Compiler tab to inspect the error.', tone: 'error', icon: '×' },
  RUNTIME_ERROR: { title: 'Runtime error', description: 'The program exited with a non-zero status.', tone: 'error', icon: '×' },
  TIMED_OUT: { title: 'Time limit exceeded', description: 'The program exceeded the allowed execution time.', tone: 'error', icon: '×' },
  OUTPUT_LIMIT_EXCEEDED: { title: 'Output limit exceeded', description: 'The program produced more output than the sandbox allows.', tone: 'error', icon: '×' },
  INVALID_OUTPUT: { title: 'Invalid output', description: 'Print only an unpadded base64url answer.', tone: 'error', icon: '×' },
  CHALLENGE_EXPIRED: { title: 'Challenge expired', description: 'The actual challenge expired before verification. Submit again.', tone: 'error', icon: '×' },
  WRONG_ANSWER: { title: 'Wrong answer', description: 'The program ran, but its output failed CogGate verification.', tone: 'error', icon: '×' },
  ARENA_CLOSED: { title: 'Arena closed', description: 'Another solver finished first, so this submission did not continue.', tone: 'error', icon: '×' },
  INTERNAL_ERROR: { title: 'System error', description: 'This execution could not be completed. Try again later.', tone: 'error', icon: '×' },
};

const errorMessages: Record<string, string> = {
  arena_closed: 'The arena is closed.',
  epoch_changed: 'The round changed. Review the new challenge before submitting again.',
  quota_exhausted: 'You have used all 10 attempts for today.',
  submission_in_flight: 'You already have a submission running.',
  queue_full: 'The execution queue is full. Try again shortly.',
  publication_consent_required: 'Agree to publish winning code before submitting.',
  source_empty: 'Source code cannot be empty.',
  payload_too_large: 'The source exceeds the allowed size.',
  forbidden: 'This GitHub account is not allowed to submit.',
  internal_error: 'The service is temporarily unavailable. Try again later.',
};

class ApiError extends Error {
  constructor(readonly status: number, readonly body: ApiErrorBody) {
    super(body.error ?? `HTTP ${status}`);
  }
}

interface AppState {
  arena: Arena | null;
  me: Me | null;
  preview: Preview | null;
  editor: monaco.editor.IStandaloneCodeEditor | null;
  models: Map<Language, monaco.editor.ITextModel>;
  language: Language;
  submission: Submission | null;
  submitting: boolean;
  suppressSave: boolean;
}

const state: AppState = {
  arena: null,
  me: null,
  preview: null,
  editor: null,
  models: new Map(),
  language: 'rust',
  submission: null,
  submitting: false,
  suppressSave: false,
};

function element<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`missing element #${id}`);
  return value as T;
}

async function api<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, options);
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as ApiErrorBody;
    throw new ApiError(response.status, body);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

function showToast(message: string, tone: 'normal' | 'error' = 'normal'): void {
  const toast = document.createElement('div');
  toast.className = `toast${tone === 'error' ? ' is-error' : ''}`;
  toast.textContent = message;
  element('toast-region').append(toast);
  window.setTimeout(() => toast.remove(), 4200);
}

function formatBytes(bytes: number): string {
  return bytes < 1024 ? `${bytes} B` : `${Math.round(bytes / 1024)} KiB`;
}

function formatDuration(value: number | null): string {
  return value === null ? '—' : `${value} ms`;
}

function draftKey(language: Language): string {
  return `coggate:draft:${state.arena?.epoch ?? 'unknown'}:${language}`;
}

function loadSource(language: Language): string {
  return localStorage.getItem(draftKey(language)) ?? templates[language];
}

let saveTimer = 0;
function saveDraft(): void {
  if (state.suppressSave || !state.editor) return;
  localStorage.setItem(draftKey(state.language), state.editor.getValue());
  element('dirty-mark').hidden = false;
  window.clearTimeout(saveTimer);
  saveTimer = window.setTimeout(() => {
    element('dirty-mark').hidden = true;
    element('save-state').classList.add('is-visible');
    window.setTimeout(() => element('save-state').classList.remove('is-visible'), 1000);
  }, 350);
  updateSubmitButton();
}

function createModel(language: Language): monaco.editor.ITextModel {
  const existing = state.models.get(language);
  if (existing) return existing;
  const model = monaco.editor.createModel(
    loadSource(language),
    monacoLanguages[language],
    monaco.Uri.parse(`inmemory://coggate/${languageFiles[language]}`),
  );
  state.models.set(language, model);
  return model;
}

function setupEditor(): void {
  monaco.editor.defineTheme('coggate', {
    base: 'vs-dark',
    inherit: true,
    rules: [
      { token: 'comment', foreground: '626D7D', fontStyle: 'italic' },
      { token: 'keyword', foreground: '66D2FF' },
      { token: 'string', foreground: 'A7E48D' },
      { token: 'number', foreground: 'D6A6FF' },
      { token: 'type', foreground: 'FFD580' },
    ],
    colors: {
      'editor.background': '#0E1116',
      'editor.foreground': '#D7DCE4',
      'editorLineNumber.foreground': '#3E4856',
      'editorLineNumber.activeForeground': '#8792A2',
      'editorCursor.foreground': '#58CFFF',
      'editor.selectionBackground': '#1F5268',
      'editor.inactiveSelectionBackground': '#1A3947',
      'editor.lineHighlightBackground': '#121820',
      'editorIndentGuide.background1': '#202731',
      'editorIndentGuide.activeBackground1': '#34404E',
      'editorWidget.background': '#171C23',
      'editorWidget.border': '#333C49',
      'input.background': '#0E1116',
      'focusBorder': '#58CFFF66',
    },
  });
  state.editor = monaco.editor.create(element('editor'), {
    model: createModel(state.language),
    theme: 'coggate',
    automaticLayout: true,
    fontFamily: 'SFMono-Regular, Consolas, Liberation Mono, Menlo, monospace',
    fontSize: 12,
    lineHeight: 20,
    minimap: { enabled: true, maxColumn: 80, scale: 0.75 },
    padding: { top: 14, bottom: 14 },
    scrollBeyondLastLine: false,
    smoothScrolling: true,
    cursorSmoothCaretAnimation: 'on',
    renderWhitespace: 'selection',
    bracketPairColorization: { enabled: true },
    guides: { bracketPairs: true, indentation: true },
    tabSize: 4,
    insertSpaces: true,
    wordWrap: 'off',
    fixedOverflowWidgets: true,
    overviewRulerBorder: false,
  });
  state.editor.onDidChangeModelContent(saveDraft);
  state.editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => void submit());
}

function setLanguage(language: Language): void {
  state.language = language;
  state.suppressSave = true;
  state.editor?.setModel(createModel(language));
  state.suppressSave = false;
  element<HTMLSelectElement>('language').value = language;
  element('filename').textContent = languageFiles[language];
  updateSubmitButton();
}

function populateLanguages(arena: Arena): void {
  const select = element<HTMLSelectElement>('language');
  const previous = arena.supported_languages.includes(state.language) ? state.language : arena.supported_languages[0];
  select.replaceChildren(...arena.supported_languages.map((language) => {
    const option = document.createElement('option');
    option.value = language;
    option.textContent = languageLabels[language];
    return option;
  }));
  if (previous) setLanguage(previous);
}

function arenaStatusLabel(status: Arena['status']): string {
  return { PREPARING: 'PREPARING', OPEN: 'OPEN', SOLVED: 'SOLVED', MAINTENANCE: 'MAINTENANCE', ARCHIVED: 'ARCHIVED' }[status];
}

function renderArena(): void {
  const arena = state.arena;
  if (!arena) return;
  const status = element('arena-status');
  status.className = `status-pill status-pill--${arena.status === 'OPEN' ? 'open' : arena.status === 'SOLVED' ? 'solved' : 'closed'}`;
  status.innerHTML = '<i></i>';
  status.append(arenaStatusLabel(arena.status));
  element('round-label').textContent = `ROUND ${arena.epoch}`;
  element('sdk-label').textContent = `SDK ${arena.sdk_version}`;
  element('source-limit').textContent = formatBytes(arena.source_limit_bytes);
  element('language-count').textContent = `${arena.supported_languages.length} runtimes`;
  element('daily-limit').textContent = `${arena.daily_limit} runs`;

  const banner = element('winner-banner');
  if (arena.winner) {
    const link = element<HTMLAnchorElement>('winner-link');
    link.textContent = `@${arena.winner.github_login}`;
    link.href = arena.winner.profile_url;
    const issue = element<HTMLAnchorElement>('issue-link');
    issue.hidden = !arena.issue_url;
    if (arena.issue_url) issue.href = arena.issue_url;
    banner.hidden = false;
  } else {
    banner.hidden = true;
  }
  updateSubmitButton();
}

function renderQuota(quota: Quota): void {
  element('quota').hidden = false;
  element('quota-value').textContent = `${quota.remaining_today} / ${state.arena?.daily_limit ?? 10}`;
}

function renderAccount(): void {
  if (state.me) {
    element('account-name').textContent = `@${state.me.github_login}`;
    element('logout').hidden = false;
    renderQuota(state.me.quota);
  } else {
    element('account-name').textContent = 'Sign in with GitHub on submit';
    element('logout').hidden = true;
    element('quota').hidden = true;
  }
  updateSubmitButton();
}

async function loadArena(): Promise<void> {
  const arena = await api<Arena>('/api/v1/arena');
  const languagesChanged = !state.arena || state.arena.supported_languages.join(',') !== arena.supported_languages.join(',');
  state.arena = arena;
  if (languagesChanged) populateLanguages(arena);
  renderArena();
}

async function loadMe(): Promise<void> {
  try {
    state.me = await api<Me>('/api/v1/me');
  } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 401) throw error;
    state.me = null;
  }
  renderAccount();
}

async function loadPreview(): Promise<void> {
  try {
    state.preview = await api<Preview>('/api/v1/arena/preview');
    element('preview').textContent = state.preview.challenge.question;
    element('preview').hidden = false;
    element('preview-skeleton').hidden = true;
    element<HTMLButtonElement>('verify-answer').disabled = false;
    element<HTMLButtonElement>('copy-question').disabled = false;
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      state.preview = null;
      element('preview').textContent = 'No preview is available for the current round.';
      element('preview').hidden = false;
      element('preview-skeleton').hidden = true;
      element<HTMLButtonElement>('verify-answer').disabled = true;
      element<HTMLButtonElement>('copy-question').disabled = true;
      return;
    }
    throw error;
  }
}

async function copyPreviewQuestion(): Promise<void> {
  const question = state.preview?.challenge.question;
  if (!question) return;
  const button = element<HTMLButtonElement>('copy-question');
  try {
    await navigator.clipboard.writeText(question);
    button.textContent = 'Copied';
    showToast('Preview question copied to clipboard.');
    window.setTimeout(() => {
      button.textContent = 'Copy question';
    }, 1600);
  } catch {
    showToast('Could not copy the preview question.', 'error');
  }
}

async function verifyPreviewAnswer(): Promise<void> {
  const input = element<HTMLInputElement>('preview-answer');
  const button = element<HTMLButtonElement>('verify-answer');
  const feedback = element('answer-feedback');
  const answer = input.value.trim();
  feedback.className = 'answer-feedback';
  if (!answer) {
    feedback.textContent = 'Enter an answer before checking it.';
    feedback.classList.add('is-error');
    input.focus();
    return;
  }

  button.disabled = true;
  button.textContent = 'Checking…';
  try {
    const result = await api<PreviewVerification>('/api/v1/arena/preview/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ answer }),
    });
    feedback.textContent = result.correct
      ? 'Correct — this answer matches the preview challenge.'
      : 'Incorrect — this answer does not match the preview challenge.';
    feedback.classList.add(result.correct ? 'is-success' : 'is-error');
  } catch (error) {
    const code = error instanceof ApiError ? error.body.error : '';
    feedback.textContent = code === 'invalid_answer_encoding'
      ? 'Use canonical base64url without padding.'
      : 'Could not check the answer. Try again.';
    feedback.classList.add('is-error');
  } finally {
    button.disabled = state.preview === null;
    button.textContent = 'Verify answer';
  }
}

function updateSubmitButton(): void {
  const button = element<HTMLButtonElement>('submit');
  const source = state.editor?.getValue().trim() ?? '';
  const agreed = element<HTMLInputElement>('consent').checked;
  const open = state.arena?.status === 'OPEN';
  const quotaAvailable = !state.me || state.me.quota.remaining_today > 0;
  button.disabled = !open || !agreed || !source || !quotaAvailable || state.submitting;
  element('submit-label').textContent = state.submitting
    ? 'Running'
    : state.me
      ? 'Submit & run'
      : 'Sign in with GitHub & submit';
}

function stepIndex(status: string): number {
  if (status === 'ACCEPTED') return 0;
  if (status === 'COMPILING' || status === 'COMPILE_ERROR') return 1;
  if (status === 'READY' || status === 'CHALLENGE_ISSUED') return 2;
  if (['RUNNING', 'RUNTIME_ERROR', 'TIMED_OUT', 'OUTPUT_LIMIT_EXCEEDED', 'INVALID_OUTPUT'].includes(status)) return 3;
  return 4;
}

function renderJudgeSteps(status: string, terminal: boolean): void {
  const labels = ['Queue', 'Compile', 'Issue challenge', 'Sandbox', 'Verify'];
  const current = stepIndex(status);
  element('judge-steps').replaceChildren(...labels.map((label, index) => {
    const item = document.createElement('li');
    if (index < current || (terminal && index === current && status === 'PASSED')) item.className = 'is-complete';
    else if (index === current && !terminal) item.className = 'is-active';
    item.textContent = label;
    return item;
  }));
}

function renderSubmission(submission: Submission): void {
  state.submission = submission;
  const terminal = TERMINAL.has(submission.status);
  const verdict = verdicts[submission.status] ?? verdicts.INTERNAL_ERROR;
  element('empty-result').hidden = true;
  element('result-content').hidden = false;
  const icon = element('verdict-icon');
  icon.className = `verdict-icon is-${verdict.tone}`;
  icon.textContent = verdict.icon;
  element('verdict-title').textContent = verdict.title;
  element('verdict-description').textContent = verdict.description;
  element('compile-time').textContent = formatDuration(submission.execution.compile_ms);
  element('run-time').textContent = formatDuration(submission.execution.run_ms);
  renderJudgeSteps(submission.status, terminal);

  const indicator = element('result-indicator');
  indicator.className = `tab-indicator is-${terminal ? (submission.status === 'PASSED' ? 'success' : 'error') : 'running'}`;
  element('actual-panel').textContent = submission.challenge
    ? `# challenge ${submission.challenge.challenge_id}\n# generator ${submission.challenge.generator_version}\n# expires ${new Date(submission.challenge.expires_at * 1000).toLocaleString()}\n\n${submission.challenge.question}`
    : 'The actual challenge appears after judging completes.';
  element('compile-panel').textContent = submission.execution.compile_output || 'The compiler produced no output.';
  element('stdout-panel').textContent = `${submission.execution.stdout ?? 'No standard output.'}${submission.execution.stdout_truncated ? '\n\n[Output truncated]' : ''}`;
  element('stderr-panel').textContent = `${submission.execution.stderr ?? 'No standard error.'}${submission.execution.stderr_truncated ? '\n\n[Output truncated]' : ''}`;
  renderQuota(submission.quota);
  if (state.me) state.me.quota = submission.quota;

  if (submission.winner && state.arena) {
    state.arena.winner = submission.winner;
    state.arena.status = 'SOLVED';
    renderArena();
  }
  state.submitting = !terminal;
  updateSubmitButton();
}

async function followSubmission(id: string): Promise<void> {
  state.submitting = true;
  updateSubmitButton();
  let eventSource: EventSource | null = null;
  let wake: (() => void) | null = null;
  try {
    eventSource = new EventSource(`/api/v1/submissions/${encodeURIComponent(id)}/events`);
    eventSource.onmessage = () => wake?.();
    for (;;) {
      const submission = await api<Submission>(`/api/v1/submissions/${encodeURIComponent(id)}`);
      renderSubmission(submission);
      if (TERMINAL.has(submission.status)) break;
      await new Promise<void>((resolve) => {
        wake = resolve;
        window.setTimeout(resolve, 700);
      });
      wake = null;
    }
  } finally {
    eventSource?.close();
    state.submitting = false;
    updateSubmitButton();
  }
}

function pendingDraft(): Draft {
  if (!state.arena || !state.editor) throw new Error('arena_not_ready');
  return {
    epoch: state.arena.epoch,
    language: state.language,
    source: state.editor.getValue(),
    publication_agreed: element<HTMLInputElement>('consent').checked,
    idempotency_key: crypto.randomUUID(),
  };
}

async function submit(restored?: Draft): Promise<void> {
  if (state.submitting) return;
  const draft = restored ?? pendingDraft();
  sessionStorage.setItem('coggate:pending-submission', JSON.stringify(draft));
  state.submitting = true;
  updateSubmitButton();
  activateConsoleTab('result');
  try {
    const accepted = await api<Accepted>('/api/v1/submissions', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(draft),
    });
    sessionStorage.removeItem('coggate:pending-submission');
    renderQuota(accepted.quota);
    await followSubmission(accepted.submission_id);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      window.location.assign('/auth/github/start');
      return;
    }
    if (error instanceof ApiError && error.body.submission_id) {
      sessionStorage.removeItem('coggate:pending-submission');
      await followSubmission(error.body.submission_id);
      return;
    }
    sessionStorage.removeItem('coggate:pending-submission');
    state.submitting = false;
    const code = error instanceof ApiError ? error.body.error ?? '' : '';
    showToast(errorMessages[code] ?? 'Submission failed. Try again later.', 'error');
    if (code === 'epoch_changed' || code === 'arena_closed') await loadArena();
    updateSubmitButton();
  }
}

function restorePendingSubmission(): void {
  const raw = sessionStorage.getItem('coggate:pending-submission');
  if (!raw || !state.me || !state.arena) return;
  try {
    const draft = JSON.parse(raw) as Draft;
    if (draft.epoch !== state.arena.epoch || !state.arena.supported_languages.includes(draft.language)) {
      sessionStorage.removeItem('coggate:pending-submission');
      return;
    }
    setLanguage(draft.language);
    state.editor?.setValue(draft.source);
    element<HTMLInputElement>('consent').checked = draft.publication_agreed;
    void submit(draft);
  } catch {
    sessionStorage.removeItem('coggate:pending-submission');
  }
}

function activateProblemTab(name: string): void {
  document.querySelectorAll<HTMLElement>('[data-problem-tab]').forEach((tab) => {
    const active = tab.dataset.problemTab === name;
    tab.classList.toggle('is-active', active);
    tab.setAttribute('aria-selected', String(active));
  });
  element('challenge-panel').hidden = name !== 'challenge';
  element('rules-panel').hidden = name !== 'rules';
}

function activateConsoleTab(name: string): void {
  document.querySelectorAll<HTMLElement>('[data-console-tab]').forEach((tab) => {
    const active = tab.dataset.consoleTab === name;
    tab.classList.toggle('is-active', active);
    tab.setAttribute('aria-selected', String(active));
  });
  document.querySelectorAll<HTMLElement>('[data-console-panel]').forEach((panel) => {
    panel.hidden = panel.dataset.consolePanel !== name;
  });
}

function clearResult(): void {
  state.submission = null;
  element('empty-result').hidden = false;
  element('result-content').hidden = true;
  element('actual-panel').textContent = 'The actual challenge appears after judging completes.';
  element('compile-panel').textContent = 'No compiler output.';
  element('stdout-panel').textContent = 'No standard output.';
  element('stderr-panel').textContent = 'No standard error.';
  element('result-indicator').className = 'tab-indicator';
  activateConsoleTab('result');
}

function setupResizers(): void {
  const shell = element('app');
  const workspace = element('workspace');
  const column = element('column-resizer');
  const consoleResizer = element('console-resizer');
  column.addEventListener('pointerdown', (event) => {
    column.setPointerCapture(event.pointerId);
    document.body.classList.add('is-resizing-columns');
  });
  column.addEventListener('pointermove', (event) => {
    if (!column.hasPointerCapture(event.pointerId)) return;
    const rect = workspace.getBoundingClientRect();
    const percent = Math.min(55, Math.max(27, ((event.clientX - rect.left) / rect.width) * 100));
    shell.style.setProperty('--problem-width', `${percent}%`);
    localStorage.setItem('coggate:problem-width', `${percent}%`);
  });
  column.addEventListener('pointerup', (event) => {
    column.releasePointerCapture(event.pointerId);
    document.body.classList.remove('is-resizing-columns');
  });
  consoleResizer.addEventListener('pointerdown', (event) => {
    consoleResizer.setPointerCapture(event.pointerId);
    document.body.classList.add('is-resizing-console');
  });
  consoleResizer.addEventListener('pointermove', (event) => {
    if (!consoleResizer.hasPointerCapture(event.pointerId)) return;
    const codePane = consoleResizer.parentElement?.getBoundingClientRect();
    if (!codePane) return;
    const height = Math.min(codePane.height * .58, Math.max(150, codePane.bottom - event.clientY - 52));
    shell.style.setProperty('--console-height', `${height}px`);
    localStorage.setItem('coggate:console-height', `${height}px`);
  });
  consoleResizer.addEventListener('pointerup', (event) => {
    consoleResizer.releasePointerCapture(event.pointerId);
    document.body.classList.remove('is-resizing-console');
  });
  const storedWidth = localStorage.getItem('coggate:problem-width');
  const storedHeight = localStorage.getItem('coggate:console-height');
  if (storedWidth) shell.style.setProperty('--problem-width', storedWidth);
  if (storedHeight) shell.style.setProperty('--console-height', storedHeight);
}

function setupInteractions(): void {
  element<HTMLSelectElement>('language').addEventListener('change', (event) => {
    setLanguage((event.target as HTMLSelectElement).value as Language);
  });
  element('reset-code').addEventListener('click', () => {
    if (!window.confirm(`Reset ${languageFiles[state.language]} to its starter template?`)) return;
    state.editor?.setValue(templates[state.language]);
    state.editor?.focus();
  });
  element('consent').addEventListener('change', updateSubmitButton);
  element('submit').addEventListener('click', () => void submit());
  element('clear-result').addEventListener('click', clearResult);
  element('copy-question').addEventListener('click', () => void copyPreviewQuestion());
  element('answer-checker').addEventListener('submit', (event) => {
    event.preventDefault();
    void verifyPreviewAnswer();
  });
  element('preview-answer').addEventListener('input', () => {
    const feedback = element('answer-feedback');
    feedback.className = 'answer-feedback';
    feedback.textContent = 'Enter an unpadded base64url answer to check it without using your submission quota.';
  });
  element('logout').addEventListener('click', async () => {
    await api<void>('/api/v1/logout', { method: 'POST' });
    state.me = null;
    renderAccount();
    showToast('Signed out of GitHub.');
  });
  document.querySelectorAll<HTMLElement>('[data-problem-tab]').forEach((tab) => {
    tab.addEventListener('click', () => activateProblemTab(tab.dataset.problemTab ?? 'challenge'));
  });
  document.querySelectorAll<HTMLElement>('[data-console-tab]').forEach((tab) => {
    tab.addEventListener('click', () => activateConsoleTab(tab.dataset.consoleTab ?? 'result'));
  });
  setupResizers();
}

function setupArenaEvents(): void {
  const events = new EventSource('/api/v1/arena/events');
  events.addEventListener('arena_solved', () => {
    void loadArena();
    showToast('A solver has cleared the challenge. The arena is closed.');
  });
}

async function initialize(): Promise<void> {
  await loadArena();
  setupEditor();
  setupInteractions();
  await Promise.all([loadMe(), loadPreview()]);
  setupArenaEvents();
  window.setInterval(() => void loadArena().catch(() => undefined), 5000);
  element('app').setAttribute('aria-busy', 'false');
  restorePendingSubmission();
}

void initialize().catch((error: unknown) => {
  console.error(error);
  element('app').setAttribute('aria-busy', 'false');
  showToast('Page initialization failed. Refresh and try again.', 'error');
});
