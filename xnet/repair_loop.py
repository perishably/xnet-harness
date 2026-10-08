"""Model-agnostic repair loop. The caller owns inference; candidates remain inert AST data.

Public feedback is the only revision input. Held-out grading follows an immutable
choice freeze. Local evidence is authoritative; optional Rust CAS mirroring may
fail without discarding a completed attempt. This is a development fixture loop,
not SWE-bench Verified or a model runner.
"""
from __future__ import annotations
import ast
import copy
import hashlib
import json
import math
import marshal
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import types
import uuid

from .brains import _exclusive_file_lock
from .protocol import canonical, digest, sha256
from .relay_log import _no_links
from .swe_repair_evaluator import (bundle_hashes, declared_import_graph, evaluate_bundle,
                                   public_feedback, repair_capability_contract, validate_baseline)
from .swe_repair_suite import public_task, build_swe_repair_suite

PINNED_SOURCES = ('repair_loop.py', 'repair_evaluator.py', 'swe_repair_evaluator.py',
                  'swe_repair_suite.py', 'swe_repair_additions.py', 'protocol.py', 'brains.py', 'relay_log.py')

class PendingAttempt(RuntimeError):
    """A reserved generation needs explicit reconciliation, never a blind rerun."""

class PendingPublicContext(PendingAttempt):
    """A reserved context callback needs reconciliation before any inference."""


PUBLIC_CONTEXT_SCHEMA = 'xnet.repair-public-context.v1'
PUBLIC_CONTEXT_KINDS = ('bridge-source', 'rag-slice', 'frozen-fetch')


def _public_context_policy(value, tasks, models):
    """Freeze independently selected PUBLIC text/source/receipt pins, not authority."""
    if type(value) is not dict or set(value) != {'schema','preparer_id','preparer_artifacts','tasks','model_ids','max_bytes'}:
        raise ValueError('invalid public context policy fields')
    if (value['schema'] != 'xnet.repair-public-context-policy.v1'
        or type(value['preparer_id']) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', value['preparer_id'])
        or type(value['max_bytes']) is not int or not 128 <= value['max_bytes'] <= 16384
        or type(value['tasks']) is not dict or set(value['tasks']) != set(tasks)
        or type(value['model_ids']) is not list or not value['model_ids']
        or any(type(model) is not str or model not in models for model in value['model_ids'])
        or len(set(value['model_ids'])) != len(value['model_ids'])
        or type(value['preparer_artifacts']) is not list or not 1 <= len(value['preparer_artifacts']) <= 16):
        raise ValueError('invalid bounded public context selection')
    artifacts = []
    for row in value['preparer_artifacts']:
        if (type(row) is not dict or set(row) != {'path','sha256'} or type(row['path']) is not str
            or not Path(row['path']).is_absolute() or type(row['sha256']) is not str
            or not re.fullmatch(r'[0-9a-f]{64}', row['sha256'])):
            raise ValueError('public context preparer source pin required')
        _no_links(Path(row['path']))
        artifacts.append({'path':os.path.abspath(row['path']), 'sha256':row['sha256']})
    if len({os.path.normcase(row['path']) for row in artifacts}) != len(artifacts):
        raise ValueError('duplicate public context artifact')
    selected = {}
    fields = {'record_id','kind','classification','source_sha256','text_sha256','receipt_sha256'}
    for task_id, rows in value['tasks'].items():
        if type(rows) is not list or len(rows) > 16:
            raise ValueError('public context task requires at most sixteen records')
        ids = set()
        selected[task_id] = []
        for row in rows:
            if (type(row) is not dict or set(row) != fields or row['classification'] != 'public'
                or row['kind'] not in PUBLIC_CONTEXT_KINDS or type(row['record_id']) is not str
                or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', row['record_id']) or row['record_id'] in ids
                or any(type(row[key]) is not str or not re.fullmatch(r'[0-9a-f]{64}', row[key])
                       for key in ('source_sha256','text_sha256','receipt_sha256'))):
                raise ValueError('invalid independently approved public context record')
            ids.add(row['record_id'])
            selected[task_id].append(dict(row))
    policy = {'schema':value['schema'], 'preparer_id':value['preparer_id'], 'max_bytes':value['max_bytes'],
              'model_ids':sorted(value['model_ids']),
              'preparer_artifacts':sorted(artifacts,key=lambda row:os.path.normcase(row['path'])), 'tasks':selected}
    if len(canonical(policy)) > 128000:
        raise ValueError('public context policy exceeds bound')
    _verify_public_context_artifacts(policy)
    return json.loads(canonical(policy))


def _verify_public_context_artifacts(policy):
    if policy is None:
        return
    for row in policy['preparer_artifacts']:
        path = Path(row['path'])
        try:
            _no_links(path)
            if not stat.S_ISREG(path.lstat().st_mode) or _artifact_sha256(path) != row['sha256']:
                raise ValueError('public context preparer artifact changed')
        except (OSError, ValueError) as error:
            raise ValueError('public context preparer source changed or unavailable; use a new run root') from error


def _public_context_input(request):
    return sha256(canonical({'task':request['task'], 'public_feedback':request['public_feedback']}))


def _public_context_callable(preparer, policy):
    function = getattr(preparer, '__func__', preparer)
    if not isinstance(function, types.FunctionType):
        raise ValueError('public context preparer must be a source-pinned Python function or method')
    path = os.path.abspath(function.__code__.co_filename)
    if os.path.normcase(path) not in {os.path.normcase(row['path']) for row in policy['preparer_artifacts']}:
        raise ValueError('public context preparer implementation is absent from selected artifact pins')
    return {'module':function.__module__, 'qualname':function.__qualname__, 'artifact_path':path,
            'code_sha256':sha256(marshal.dumps(function.__code__))}


def _admit_public_context(packet, request, policy):
    fields = {'schema','task_id','input_sha256','records','authority','work_performed','hidden_cases_used','context_only'}
    if (type(packet) is not dict or set(packet) != fields or packet['schema'] != PUBLIC_CONTEXT_SCHEMA
        or packet['task_id'] != request['task']['task_id'] or packet['input_sha256'] != _public_context_input(request)
        or packet['authority'] != 'none' or packet['work_performed'] is not False
        or packet['hidden_cases_used'] is not False or packet['context_only'] is not True
        or type(packet['records']) is not list):
        raise ValueError('public context task/input/source-only contract mismatch')
    approved = policy['tasks'][packet['task_id']]
    if len(packet['records']) != len(approved):
        raise ValueError('public context selection is incomplete or expanded')
    byte_count = 0
    for record, pin in zip(packet['records'], approved):
        if (type(record) is not dict or set(record) != {'record_id','kind','text','source_sha256','text_sha256','receipt_sha256'}
            or type(record['text']) is not str
            or any(record[key] != pin[key] for key in pin if key != 'classification')):
            raise ValueError('public context differs from independently approved text/source/receipt pins')
        try:
            raw = record['text'].encode('utf-8', 'strict')
        except UnicodeError as error:
            raise ValueError('public context must preserve exact UTF-8') from error
        byte_count += len(raw)
        if sha256(raw) != record['text_sha256']:
            raise ValueError('public context exact text hash mismatch')
    if byte_count > policy['max_bytes'] or len(canonical(packet)) > 32768:
        raise ValueError('public context byte budget exceeded; clipping is forbidden')
    result = {**json.loads(canonical(packet)), 'policy_sha256':digest(policy)}
    return {**result, 'context_sha256':digest(result)}

def _artifact_sha256(path):
    # Selected implementation libraries can be large; never load the bundle into RAM.
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def validate_run_identity(value, models, *, cas=None):
    """Normalize a caller's explicit runner/settings declaration without executing it.

    Artifact lists cover only the files the caller names. Tokenizer, template,
    settings and loaded model identity remain declarations, not server attestation.
    None keeps legacy callers compatible; new integrated callers supply the schema.
    """
    if value is None:
        return None

    def fields(item, expected):
        if type(item) is not dict or set(item) != set(expected):
            raise ValueError('invalid run identity fields')

    def label(item):
        if type(item) is not str or not item.strip() or len(item) > 256 or '\x00' in item:
            raise ValueError('invalid run identity declaration')

    def pin(item):
        if type(item) is not str or re.fullmatch(r'[0-9a-f]{64}', item) is None:
            raise ValueError('invalid run identity SHA256')

    def portable(item, depth=0):
        if depth > 12:
            raise ValueError('run identity nesting exceeds bound')
        if item is None or type(item) in (bool, int):
            return
        if type(item) is float and math.isfinite(item):
            return
        if type(item) is str and '\x00' not in item:
            return
        if type(item) is list and len(item) <= 256:
            for part in item: portable(part, depth+1)
            return
        if type(item) is dict and len(item) <= 256:
            for key, part in item.items():
                if type(key) is not str or not key or '\x00' in key:
                    raise ValueError('invalid run identity settings key')
                portable(part, depth+1)
            return
        raise ValueError('run identity must contain bounded portable JSON')

    def artifact(item):
        fields(item, ('path', 'sha256')); pin(item['sha256'])
        raw = item['path']
        if type(raw) is not str or not raw or '\x00' in raw or not Path(raw).is_absolute():
            raise ValueError('run identity artifact path must be absolute')
        # Inspect the supplied path before normalizing away any dot components.
        _no_links(Path(raw))
        return {'path':os.path.abspath(raw), 'sha256':item['sha256']}

    def artifacts(items):
        if type(items) is not list or not 1 <= len(items) <= 64:
            raise ValueError('run identity artifact list requires 1..64 files')
        result = [artifact(item) for item in items]
        paths = [os.path.normcase(item['path']) for item in result]
        if len(paths) != len(set(paths)):
            raise ValueError('duplicate run identity artifact path')
        return sorted(result, key=lambda item:os.path.normcase(item['path']))

    portable(value)
    try:
        encoded = canonical(value)
    except (UnicodeError, ValueError, OverflowError) as error:
        raise ValueError('run identity must contain portable JSON') from error
    if len(encoded) > 32768:
        raise ValueError('run identity exceeds bound')
    normalized = json.loads(encoded)
    fields(normalized, ('schema','adapter','runner','models','native'))
    if normalized['schema'] != 'xnet.repair-run-identity.v1':
        raise ValueError('unsupported run identity schema')
    normalized['adapter'] = artifact(normalized['adapter'])
    fields(normalized['runner'], ('source_revision','artifacts'))
    label(normalized['runner']['source_revision'])
    normalized['runner']['artifacts'] = artifacts(normalized['runner']['artifacts'])
    if type(normalized['models']) is not dict or set(normalized['models']) != set(models):
        raise ValueError('run identity model enum mismatch')
    runner_pins = {item['sha256'] for item in normalized['runner']['artifacts']}
    if any(type(model) is not dict or model.get('runner_sha256') not in runner_pins for model in models.values()):
        raise ValueError('run identity runner bundle omits declared model runner')
    for item in normalized['models'].values():
        fields(item, ('decoding','transport','tokenizer','template'))
        if type(item['decoding']) is not dict or type(item['transport']) is not dict:
            raise ValueError('run identity settings must be objects')
        for key in ('tokenizer','template'):
            fields(item[key], ('id','sha256')); label(item[key]['id'])
            if item[key]['sha256'] is not None: pin(item[key]['sha256'])
    native = normalized['native']
    if native is not None:
        fields(native, ('binary','sdk_artifacts'))
        native['binary'] = artifact(native['binary'])
        native['sdk_artifacts'] = artifacts(native['sdk_artifacts'])
    elif cas is not None:
        raise ValueError('run identity requires native artifacts for borrowed CAS')
    if len(canonical(normalized)) > 32768:
        raise ValueError('normalized run identity exceeds bound')
    verify_run_identity_artifacts(normalized, cas=cas)
    return normalized


def verify_run_identity_artifacts(identity, *, cas=None):
    """Rehash selected frozen files only; never import code or inspect a model server."""
    if identity is None:
        return
    selected = [identity['adapter'], *identity['runner']['artifacts']]
    native = identity['native']
    if native is not None:
        selected.extend([native['binary'], *native['sdk_artifacts']])
    if cas is not None:
        if native is None:
            raise ValueError('run identity requires native artifacts for borrowed CAS')
        binary_pin = getattr(cas, 'binary_sha256', None)
        if binary_pin is not None and binary_pin != native['binary']['sha256']:
            raise ValueError('run identity native binary differs from borrowed CAS')
    for item in selected:
        path = Path(item['path'])
        try:
            _no_links(path)
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError('run identity artifact must be a regular file')
            current = _artifact_sha256(path)
        except (OSError, ValueError) as error:
            raise ValueError('run identity artifact changed or unavailable; use a new run root') from error
        if current != item['sha256']:
            raise ValueError('run identity artifact changed; use a new run root')

def is_noop_patch(before, after):
    if before == after:
        return True
    if set(before) != set(after):
        return False
    try:
        return all(ast.dump(ast.parse(before[name]), include_attributes=False) ==
                   ast.dump(ast.parse(after[name]), include_attributes=False) for name in before)
    except (SyntaxError, ValueError, RecursionError):
        return False

def _read(path):
    _no_links(path, regular_file=True)
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out: raise ValueError('duplicate evidence field')
            out[key] = value
        return out
    data = path.read_bytes()
    if len(data) > 512000: raise ValueError('evidence file exceeds bound')
    value = json.loads(data, object_pairs_hook=unique)
    expected = value.pop('receipt_sha256')
    if digest(value) != expected: raise ValueError('evidence hash mismatch')
    return {**value, 'receipt_sha256': expected}

def _save(path, value):
    _no_links(path, regular_file=True)
    value = {**value, 'receipt_sha256': digest(value)}
    data = canonical(value) + b'\n'
    if len(data) > 512000: raise ValueError('evidence file exceeds bound')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.repair-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        _no_links(path, regular_file=True)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    return value

def _patch(text, task, base):
    if type(text) is not str or len(text.encode('utf-8')) > 32768:
        raise ValueError('proposal text exceeds bound')
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out: raise ValueError('duplicate patch field')
            out[key] = value
        return out
    value = json.loads(text, object_pairs_hook=unique)
    if type(value) is not dict or set(value) != {'files'} or type(value['files']) is not dict:
        raise ValueError('require exactly a files map')
    edits = value['files']
    if not edits or set(edits) - set(task['editable_files']): raise ValueError('undeclared or empty patch')
    for source in edits.values():
        if type(source) is not str or '\x00' in source or len(source.encode('utf-8')) > task['api_contract']['replacement_limit_bytes']:
            raise ValueError('invalid replacement source')
    return {**base, **edits}

class RepairLoop:
    """Borrow an optional XNET client; never start or stop a model, Jcode or a sibling.

    generate(request) is a caller-owned bounded transport. It must return
    model_id/model_sha256/text/usage. A transport exception leaves a pending
    reservation. Supply the returned output to reconcile() after confirming the
    old generation finished. Re-entry never repeats an uncertain inference.
    """
    def __init__(self, root, tasks, models, references, *, cas=None, eval_timeout=3, run_identity=None,
                 context_preparer=None, public_context_policy=None):
        self.root = Path(root).absolute(); _no_links(self.root)
        self.tasks = {task['task_id']: copy.deepcopy(task) for task in tasks}
        if not 1 <= len(tasks) <= 50 or len(self.tasks) != len(tasks): raise ValueError('unique 1..50 tasks required')
        if any(not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', name) for name in self.tasks): raise ValueError('invalid task ID')
        if not 1 <= len(models) <= 16 or any(not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', name) for name in models):
            raise ValueError('invalid model enum')
        for model in models.values():
            if set(model) != {'model_sha256','runner_sha256'} or any(not re.fullmatch(r'[0-9a-f]{64}', item) for item in model.values()):
                raise ValueError('model and runner artifact pins required')
        if type(eval_timeout) not in (int,float) or not 0 < eval_timeout <= 10: raise ValueError('invalid evaluator deadline')
        if set(references) != set(self.tasks): raise ValueError('every task needs a trusted reference bundle')
        self.models, self.cas, self.eval_timeout = copy.deepcopy(models), cas, eval_timeout
        self.run_identity = validate_run_identity(run_identity, self.models, cas=cas)
        if (context_preparer is None) != (public_context_policy is None) or (context_preparer is not None and not callable(context_preparer)):
            raise ValueError('public context requires both caller preparer and pinned policy')
        self.context_preparer = context_preparer
        self.public_context_policy = _public_context_policy(public_context_policy, self.tasks, self.models) if context_preparer is not None else None
        self.context_preparer_identity = _public_context_callable(context_preparer, self.public_context_policy) if context_preparer is not None else None
        self.root.mkdir(parents=True, exist_ok=True)
        config = {'schema':'xnet.repair-loop.v1', 'tasks_sha256':digest(tasks), 'models':self.models,
                  'reference_sha256':digest(references), 'max_attempts':2, 'eval_timeout':eval_timeout,
                  'sources':{name:sha256(Path(__file__).with_name(name).read_bytes()) for name in PINNED_SOURCES},
                  'candidate_execution':False, 'generation_owner':'caller', 'benchmark':'local development fixtures'}
        if self.run_identity is not None:
            config.update(run_identity=copy.deepcopy(self.run_identity), run_identity_sha256=digest(self.run_identity))
        if self.public_context_policy is not None:
            config.update(public_context_policy=copy.deepcopy(self.public_context_policy),
                          public_context_policy_sha256=digest(self.public_context_policy),
                          context_preparer_identity=copy.deepcopy(self.context_preparer_identity))
        with self._lock():
            manifest = self.root/'manifest.json'
            if manifest.exists():
                self.manifest = _read(manifest)
                if self.manifest['config'] != config: raise ValueError('resume identity changed')
                validation = _read(self.root/'selftest.json')
                if validation['receipt_sha256'] != self.manifest['selftest_sha256']:
                    raise ValueError('selftest receipt changed')
            else:
                if any(path.name != 'run.lock' for path in self.root.iterdir()):
                    raise ValueError('nonempty uninitialized trial requires operator recovery')
                validation = []
                for task in self.tasks.values():
                    baseline = validate_baseline(task, timeout_seconds=eval_timeout)
                    options = dict(allowed_files=task['files'], import_graph=declared_import_graph(task['files']), timeout_seconds=eval_timeout)
                    reports = [evaluate_bundle(references[task['task_id']], task['entry_file'], task['entry_function'], task[key], **options)
                               for key in ('public_cases','hidden_cases')]
                    if not baseline['valid'] or not all(report['resolved'] and report['status']=='evaluated' for report in reports):
                        raise ValueError('buggy/reference selftest gate failed: '+task['task_id'])
                    validation.append({'task_id':task['task_id'], 'baseline':baseline, 'reference_reports':reports})
                validated = _save(self.root/'selftest.json', {'checks':validation, 'passed':True})
                self.manifest = _save(manifest, {'config':config, 'selftest_sha256':validated['receipt_sha256']})

    def _lock(self):
        _no_links(self.root/'run.lock')
        return _exclusive_file_lock(self.root/'run.lock', timeout=1)

    def _verify_source_identity(self):
        """Keep every attempt and evaluator boundary on this run's frozen sources."""
        try:
            current = {name:sha256(Path(__file__).with_name(name).read_bytes()) for name in PINNED_SOURCES}
        except OSError as error:
            raise ValueError('source identity changed or unavailable; use a new run root for changed code') from error
        if current != self.manifest['config']['sources']:
            raise ValueError('source identity changed; use a new run root for changed code')
        expected = self.manifest['config'].get('run_identity')
        if self.run_identity != expected or (expected is not None and
                digest(self.run_identity) != self.manifest['config']['run_identity_sha256']):
            raise ValueError('run identity changed; use a new run root')
        verify_run_identity_artifacts(expected, cas=self.cas)
        selected_context = self.manifest['config'].get('public_context_policy')
        if (self.public_context_policy != selected_context or (selected_context is not None
                and digest(self.public_context_policy) != self.manifest['config']['public_context_policy_sha256'])):
            raise ValueError('public context policy changed; use a new run root')
        _verify_public_context_artifacts(selected_context)
        if selected_context is not None:
            current_preparer = _public_context_callable(self.context_preparer, selected_context)
            if current_preparer != self.manifest['config']['context_preparer_identity']:
                raise ValueError('public context callback identity changed; use a new run root')

    def _prepare_public_context(self, request, directory):
        """Reserve a caller callback once; never give it hidden task/reference data."""
        if self.public_context_policy is None or request['model_id'] not in self.public_context_policy['model_ids']:
            return request
        self._verify_source_identity()
        started, returned = directory/'public-context-started.json', directory/'public-context-returned.json'
        if started.exists():
            saved = _read(started)
            original = saved['request']
            # Nonces/CAS receipts may differ on reconstruction; the immutable
            # saved request is reused only if the complete public case is equal.
            keys = ('model_id','model_sha256','manifest_sha256','task','attempt','base_files','public_feedback',
                    'max_output_tokens','max_attempts','hidden_cases_used','contract','run_identity','run_identity_sha256')
            if (any(original.get(key) != request.get(key) for key in keys)
                or saved['policy_sha256'] != digest(self.public_context_policy)):
                raise ValueError('reserved public context request changed')
            request = original
            if not returned.exists():
                raise PendingPublicContext(str(started))
            result = _read(returned)
            if result['started_sha256'] != saved['receipt_sha256'] or result.get('status') != 'returned':
                raise PendingPublicContext('public context callback needs explicit recovery: '+str(started))
            packet = result['packet']
        else:
            saved = _save(started, {'schema':'xnet.repair-public-context-reservation.v1', 'request':request,
                                   'policy_sha256':digest(self.public_context_policy), 'status':'reserved',
                                   'inference_started':False})
            packet = self.context_preparer(copy.deepcopy(request))
            # Record bounded returned data before its admission. Oversized or
            # non-JSON returns keep the existing reservation, never a retry.
            try:
                encoded = canonical(packet)
            except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError) as error:
                _save(returned, {'started_sha256':saved['receipt_sha256'], 'status':'invalid-return',
                                 'error_type':type(error).__name__, 'inference_started':False})
                raise ValueError('public context callback returned invalid JSON') from error
            if len(encoded) > 32768:
                _save(returned, {'started_sha256':saved['receipt_sha256'], 'status':'oversized-return',
                                 'returned_sha256':sha256(encoded), 'inference_started':False})
                raise ValueError('public context callback returned an oversized packet')
            _save(returned, {'started_sha256':saved['receipt_sha256'], 'status':'returned',
                             'packet':json.loads(encoded), 'inference_started':False})
            packet = json.loads(encoded)
        self._verify_source_identity()
        context = _admit_public_context(packet, request, self.public_context_policy)
        return {**request, 'public_context':context}

    def reconcile_public_context(self, model, task, attempt, nonce, packet):
        """Supply the established result of a reserved preparer; never call it again."""
        if (model not in self.models or task not in self.tasks or attempt not in (1,2) or self.public_context_policy is None
                or model not in self.public_context_policy['model_ids']):
            raise ValueError('unknown public context reservation')
        with self._lock():
            self._verify_source_identity()
            directory = self._case(model, task, attempt)
            if (self.root/'choices.json').exists() or (directory/'reservation.json').exists():
                raise ValueError('public context already dispatched or trial frozen')
            saved = _read(directory/'public-context-started.json')
            if saved['request']['nonce'] != nonce or saved['policy_sha256'] != digest(self.public_context_policy):
                raise ValueError('public context reconciliation identity changed')
            returned = directory/'public-context-returned.json'
            if returned.exists():
                raise ValueError('public context callback already has a return; preserve the original evidence')
            _admit_public_context(packet, saved['request'], self.public_context_policy)
            return _save(returned, {'started_sha256':saved['receipt_sha256'], 'status':'returned',
                                   'packet':copy.deepcopy(packet), 'reconciled':True, 'inference_started':False})

    def _case(self, model, task, attempt):
        return self.root/'attempts'/model/task/str(attempt)

    def _rows(self, model, task):
        rows = []
        for attempt in (1,2):
            path = self._case(model,task,attempt)/'result.json'
            if path.exists():
                row = _read(path)
                if (row['manifest_sha256'] != self.manifest['receipt_sha256'] or row['model_id'] != model
                    or row['task_id'] != task or row['attempt'] != attempt): raise ValueError('attempt identity changed')
                rows.append(row)
        return rows

    def _request(self, model, task, attempt, prior):
        base = prior['files'] if prior and prior['candidate_valid'] else task['files']
        public = public_task(task); public['files'] = base
        feedback = public_feedback(prior['public_evaluation']) if prior else None
        if prior and prior['no_op']: feedback['host_reason']='PATCH_WAS_A_NO_OP: change the failed implementation'
        request = {'nonce':uuid.uuid4().hex, 'model_id':model, 'model_sha256':self.models[model]['model_sha256'],
                'manifest_sha256':self.manifest['receipt_sha256'], 'task':public, 'attempt':attempt,
                'base_files':base, 'public_feedback':feedback, 'max_output_tokens':650,
                'max_attempts':2, 'hidden_cases_used':False,
                'contract':'Return only {"files":{"editable.py":"complete source"}}. Preserve declared local imports and the API. No tools, host imports, filesystem, network or subprocess. ' + repair_capability_contract()}
        if self.run_identity is not None:
            request.update(run_identity=copy.deepcopy(self.run_identity), run_identity_sha256=digest(self.run_identity))
        text = canonical({'task':public, 'public_feedback':feedback}).decode('utf-8')
        context = {'status':'not-requested', 'raw_public_sha256':sha256(text.encode('utf-8')), 'context_only':True}
        if self.cas is not None:
            try:
                packet = self.cas.pack_context([{'id':context['raw_public_sha256'],'kind':'raw','text':text}],max_bytes=32768)
                if (type(packet) is not dict or packet.get('work_performed') is not False or packet.get('authority')!='none'
                    or packet['pack']['context_only'] is not True or packet['pack']['omitted']
                    or packet['pack']['records'] != [{'id':context['raw_public_sha256'],'kind':'raw','text':text}]):
                    raise ValueError('Oroboros context differs from complete public input')
                context.update(status='sealed', packet=packet)
            except Exception as error:
                context.update(status='pending',error=type(error).__name__+': '+str(error)[:200])
        request['oroboros_context'] = context
        return request

    def _mirror(self, directory, row):
        status = {'record_sha256':row['receipt_sha256'], 'status':'not-requested', 'seals':[]}
        if self.cas is not None:
            try:
                text = canonical(row).decode('utf-8')
                for start in range(0,len(text),14000):
                    chunk = text[start:start+14000]
                    seal = self.cas.seal(chunk)
                    if seal.get('digest') != sha256(chunk.encode('utf-8')): raise ValueError('CAS mirror hash mismatch')
                    status['seals'].append(seal)
                status['status'] = 'sealed'
            except Exception as error:
                status.update(status='pending', error=type(error).__name__+': '+str(error)[:200])
        _save(directory/'mirror.json', status)

    def _finish(self, directory, request, output_record):
        # The actual returned output was saved before this gate. Code drift is
        # a run-identity error, never a candidate failure or a reason to infer again.
        self._verify_source_identity()
        task = self.tasks[request['task']['task_id']]
        if request['manifest_sha256'] != self.manifest['receipt_sha256']: raise ValueError('reservation identity changed')
        if (request.get('run_identity') != self.manifest['config'].get('run_identity') or
                request.get('run_identity_sha256') != self.manifest['config'].get('run_identity_sha256') or
                (self.run_identity is not None and
                 digest(request.get('run_identity')) != self.manifest['config']['run_identity_sha256'])):
            raise ValueError('reservation run identity changed')
        if self.public_context_policy is not None and request['model_id'] in self.public_context_policy['model_ids']:
            started = _read(directory/'public-context-started.json')
            returned = _read(directory/'public-context-returned.json')
            original_request = {key:value for key,value in request.items() if key not in ('public_context','receipt_sha256')}
            if (started['request'] != original_request or returned.get('status') != 'returned'
                    or returned['started_sha256'] != started['receipt_sha256']):
                raise ValueError('public context return/reservation linkage changed')
            expected_context = _admit_public_context(returned['packet'], request, self.public_context_policy)
            if request.get('public_context') != expected_context:
                raise ValueError('reserved public context changed')
        elif 'public_context' in request:
            raise ValueError('unrequested public context in generation reservation')
        output = output_record['output']; tick = time.monotonic()
        row = {'manifest_sha256':self.manifest['receipt_sha256'], 'model_id':request['model_id'],
               'task_id':task['task_id'], 'attempt':request['attempt'], 'request':request,
               'output_record':output_record, 'candidate_valid':False, 'candidate_execution':False,
               'files':None, 'no_op':False, 'hidden_cases_used':False}
        rejection = {'schema_version':'xnet.swe-repair-evaluation.v1', 'visibility':'public',
                     'status':'rejected', 'resolved':False, 'passed':0, 'total':len(task['public_cases']), 'cases':[]}
        row['public_evaluation'] = rejection
        try:
            if type(output) is not dict or set(output) != {'model_id','model_sha256','text','usage'}:
                raise ValueError('unexpected generation envelope')
            if output['model_id'] != request['model_id'] or output['model_sha256'] != request['model_sha256']:
                raise ValueError('model enum or artifact pin mismatch')
            if type(output['usage']) is not dict: raise ValueError('usage must be portable metadata')
            files = _patch(output['text'], task, request['base_files'])
            row.update(files=files, changed_files=sorted(name for name in files if files[name]!=request['base_files'][name]),
                       bundle_hashes=bundle_hashes(files), no_op=is_noop_patch(request['base_files'],files))
            if row['no_op']: raise ValueError('PATCH_WAS_A_NO_OP')
            report = evaluate_bundle(files, task['entry_file'], task['entry_function'], task['public_cases'],
                allowed_files=task['files'], import_graph=declared_import_graph(task['files']), timeout_seconds=self.eval_timeout)
            public_feedback(report)  # assert public-only before saving feedback
            row.update(public_evaluation=report, candidate_valid=report['status']=='evaluated')
        except Exception as error:
            row['public_evaluation'] = {**rejection, 'error':type(error).__name__+': '+str(error)[:200]}
        self._verify_source_identity()
        row['evaluation_and_persist_preparation_seconds'] = time.monotonic()-tick
        row = _save(directory/'result.json', row)  # complete local evidence before optional mirror
        self._mirror(directory,row)
        return row

    def run_lane(self, model, generate, *, task_ids=None):
        if model not in self.models: raise ValueError('model outside declared enum')
        if task_ids is None:
            selected_tasks = list(self.tasks)
        else:
            if (type(task_ids) not in (list,tuple) or not task_ids or len(task_ids) > len(self.tasks)
                    or any(type(task_id) is not str or task_id not in self.tasks for task_id in task_ids)
                    or len(set(task_ids)) != len(task_ids)):
                raise ValueError('task selection must be unique exact manifest IDs')
            selected_tasks = list(task_ids)
        with self._lock():
            self._verify_source_identity()
            if (self.root/'choices.json').exists(): raise ValueError('trial already frozen')
            for task_id in selected_tasks:
                task = self.tasks[task_id]
                for attempt in (1,2):
                    rows = self._rows(model,task['task_id'])
                    if rows and rows[-1]['public_evaluation']['resolved']: break
                    if any(row['attempt']==attempt for row in rows): continue
                    directory = self._case(model,task['task_id'],attempt)
                    reservation = directory/'reservation.json'
                    if reservation.exists():
                        request = _read(reservation)
                        if not (directory/'output.json').exists(): raise PendingAttempt(str(reservation))
                    else:
                        self._verify_source_identity()
                        started = directory/'public-context-started.json'
                        if started.exists() and not (directory/'public-context-returned.json').exists():
                            raise PendingPublicContext(str(started))
                        request = self._request(model,task,attempt,rows[-1] if rows else None)
                        request = self._prepare_public_context(request, directory)
                        request = _save(reservation,request)
                        self._verify_source_identity()
                        tick = time.monotonic()
                        output = generate(copy.deepcopy(request))  # caller owns transport and model lifetime
                        if len(canonical(output)) > 65536: raise ValueError('generation envelope exceeds bound; reservation remains pending')
                        _save(directory/'output.json', {'nonce':request['nonce'], 'output':output,
                              'generation_request_seconds':time.monotonic()-tick})
                    output = _read(directory/'output.json')
                    if output['nonce'] != request['nonce']: raise ValueError('output nonce mismatch')
                    self._finish(directory,request,output)
            return [row for task in selected_tasks for row in self._rows(model,task)]

    def reconcile(self, model, task, attempt, nonce, output):
        if model not in self.models or task not in self.tasks or attempt not in (1,2): raise ValueError('unknown reservation')
        with self._lock():
            self._verify_source_identity()
            if (self.root/'choices.json').exists(): raise ValueError('trial already frozen')
            directory = self._case(model,task,attempt); request = _read(directory/'reservation.json')
            if request['nonce'] != nonce: raise ValueError('wrong reconciliation nonce')
            if (directory/'output.json').exists() or (directory/'result.json').exists(): raise ValueError('reservation already has output')
            if len(canonical(output)) > 65536: raise ValueError('generation envelope exceeds bound')
            _save(directory/'output.json', {'nonce':nonce, 'output':output, 'generation_request_seconds':None,
                                          'reconciled':True, 'timing_available':False})

    def mirror_pending(self):
        with self._lock():
            for model in self.models:
                for task in self.tasks:
                    for row in self._rows(model,task):
                        directory=self._case(model,task,row['attempt'])
                        path=directory/'mirror.json'
                        if not path.exists() or _read(path)['status']!='sealed': self._mirror(directory,row)

    def freeze(self):
        with self._lock():
            self._verify_source_identity()
            path=self.root/'choices.json'
            if path.exists(): return _read(path)
            choices=[]
            for model in self.models:
                for task in self.tasks:
                    rows=self._rows(model,task)
                    if not rows or len(rows)<2 and not rows[-1]['public_evaluation']['resolved']:
                        raise ValueError('unfinished lane or pending attempt')
                    valid=[row for row in rows if row['candidate_valid']]
                    best=max(valid,key=lambda row:(row['public_evaluation']['passed'],row['attempt'])) if valid else None
                    choices.append({'model_id':model,'task_id':task,'attempt':best['attempt'] if best else None,
                                    'result_sha256':best['receipt_sha256'] if best else None,
                                    'attempt_receipts':[row['receipt_sha256'] for row in rows]})
            self._verify_source_identity()
            return _save(path,{'manifest_sha256':self.manifest['receipt_sha256'],'choices':choices})

    def grade(self):
        with self._lock():
            self._verify_source_identity()
            frozen=_read(self.root/'choices.json'); scores=[]
            if frozen['manifest_sha256']!=self.manifest['receipt_sha256']: raise ValueError('freeze identity changed')
            for choice in frozen['choices']:
                rows=self._rows(choice['model_id'],choice['task_id'])
                if choice['attempt_receipts']!=[row['receipt_sha256'] for row in rows]: raise ValueError('attempts changed after freeze')
                selected=next((row for row in rows if row['attempt']==choice['attempt']),None)
                if selected and selected['receipt_sha256']!=choice['result_sha256']: raise ValueError('selected result changed')
                task=self.tasks[choice['task_id']]
                self._verify_source_identity()
                report=evaluate_bundle(selected['files'],task['entry_file'],task['entry_function'],task['hidden_cases'],
                    allowed_files=task['files'],import_graph=declared_import_graph(task['files']),timeout_seconds=self.eval_timeout) if selected else None
                scores.append({**choice,'first_public_resolved':rows[0]['public_evaluation']['resolved'],
                               'hidden_resolved':bool(report and report['resolved']),
                               'resolved':bool(selected and selected['public_evaluation']['resolved'] and report and report['resolved']),
                               'hidden_report':report})
            self._verify_source_identity()
            return _save(self.root/'score.json',{'choices_sha256':frozen['receipt_sha256'],'scores':scores,
                          'benchmark_claim':'held-out local fixtures only; not SWE-bench Verified'})

def pilot_battery():
    """Ten existing XNET fixtures plus trusted host reference patches, not Kimi's battery."""
    repairs = [
        ('metered-tiers','helpers.py','max(0, units - limit) * base_rate','max(0, units - limit) * excess_rate'),
        ('coupon-threshold','helpers.py','subtotal > minimum','subtotal >= minimum'),
        ('per-line-tax','helpers.py','cents * basis_points // 10000','(cents * basis_points + 5000) // 10000'),
        ('available-credit','api.py','remaining_balance(line_cents, [])','remaining_balance(line_cents, prior_credits)'),
        ('service-proration','helpers.py','monthly * days // period','(2 * monthly * days + period) // (2 * period)'),
        ('live-reservations','helpers.py','expires >= now','expires > now'),
        ('bundle-bottleneck','helpers.py','stock.get(part, 0)','stock.get(part, 0) // required'),
        ('returned-units','helpers.py',"kind == 'receipt'","kind in ['receipt', 'return']"),
        ('reorder-deficit','api.py','target - on_hand, pack_size','target - on_hand - inbound, pack_size'),
        ('cooldown-start','helpers.py','return previous_end','return previous_end + cooldown'),
    ]
    suite=build_swe_repair_suite();tasks=[];references={}
    for slug, name, old, new in repairs:
        task=next(item for item in suite if item['task_id'].endswith('--'+slug))
        if task['files'][name].count(old)!=1: raise ValueError('pilot reference anchor changed')
        reference=dict(task['files']);reference[name]=reference[name].replace(old,new)
        tasks.append(task);references[task['task_id']]=reference
    return tasks,references
