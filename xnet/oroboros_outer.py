"""One bounded owner for existing Oroboros peers; no model/daemon ownership.

Each callback is borrowed and source-bound. Stage completion records execution,
not correctness or model learning. Independent evaluators and provider download
receipts retain their own authority. Unknown callbacks remain reserved; an outer
reconciliation never authorizes repeating an uncertain inner model request.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
import time
import types
import uuid

from .brains import _exclusive_file_lock
from .context_callable_identity_v2 import code_sha256
from .ledger import Ledger
from .nullclaw import NullClaw
from .protocol import canonical, digest, make_event, sha256
from .relay_log import _no_links
from .scope import ScopeAuthority
from .workflow import ToolRegistry

STAGES = ('intake','context','session','work','freeze','validate','learn','archive','commit')
SCHEMA = 'xnet.oroboros-outer-config.v1'
MAX_BYTES = 65536
_ID = re.compile(r'[A-Za-z0-9_.-]{1,128}')
_HEX = re.compile(r'[0-9a-f]{64}')
_SOURCES = ('oroboros_outer.py','protocol.py','ledger.py','scope.py','nullclaw.py','brains.py','workflow.py','context_callable_identity_v2.py')


class OuterError(ValueError):
    pass


class OuterPending(OuterError):
    pass


class OuterTools(ToolRegistry):
    METHODS = {name:False for name in ('outer_read','outer_enqueue','outer_step','outer_reconcile')}


def _bounded(value):
    raw = canonical(value)
    if len(raw)>MAX_BYTES:
        raise OuterError('outer frame exceeds 64 KiB')
    return raw


def _callbacks(callbacks):
    if type(callbacks) is not dict or set(callbacks)-set(STAGES[:-1]):
        raise OuterError('fixed borrowed stage callbacks only')
    result = {}
    for name, callback in callbacks.items():
        fn = getattr(callback,'__func__',callback)
        if not isinstance(fn,types.FunctionType):
            raise OuterError('source-defined borrowed callback required')
        path = Path(fn.__code__.co_filename).absolute()
        _no_links(path,regular_file=True)
        result[name]={'path':str(path),'sha256':sha256(path.read_bytes()),
                      'qualname':fn.__qualname__,'code_sha256':code_sha256(fn.__code__)}
    return result


def _pins():
    root=Path(__file__).parent
    return {name:sha256((root/name).read_bytes()) for name in _SOURCES}


def _stage_scopes(bindings):
    if type(bindings) is not dict:raise OuterError('operator binding object required')
    selected=bindings.get('stage_scopes',{})
    if (type(selected) is not dict or set(selected)-set(STAGES[:-1])
            or any(type(v) is not str or not _ID.fullmatch(v) for v in selected.values())):
        raise OuterError('fixed stage scope bindings required')
    return selected


class _ReadOnlyLedger(Ledger):
    """Observe an existing controller without initializing or migrating its DB."""
    def __init__(self,root):
        self.data_dir=Path(root);self.db_path=self.data_dir/'ledger'/'xnet.sqlite3'
        self.cas_dir=self.data_dir/'cas'/'sha256';self._snapshot_db=None
        _no_links(self.db_path,regular_file=True);_no_links(self.cas_dir)

    @contextmanager
    def snapshot(self):
        db=sqlite3.connect(self.db_path.as_uri()+'?mode=ro',uri=True,timeout=20)
        db.row_factory=sqlite3.Row;db.execute('BEGIN');self._snapshot_db=db
        try:yield
        finally:self._snapshot_db=None;db.close()

    @contextmanager
    def _conn(self):
        if self._snapshot_db is None:raise OuterError('read-only ledger snapshot required')
        yield self._snapshot_db

    def get_evidence(self,pin):
        if type(pin) is not str or not _HEX.fullmatch(pin):raise OuterError('exact evidence pointer required')
        _no_links(self.cas_dir/pin[:2]/pin,regular_file=True)
        return super().get_evidence(pin)


def inspect_outer_status(root):
    """Verify and inspect saved state without importing or invoking callbacks."""
    outer=OroborosOuter(root,{},_inspection=True)
    with outer.ledger.snapshot():
        result=outer.status()
    return result|{'inspection_only':True,'callbacks_invoked':0}


def bootstrap_outer(root, callbacks, *, disabled=None, bindings=None, budgets=None):
    """Create a new private signed controller; never initialize transport roots."""
    root=Path(root).absolute(); _no_links(root)
    if root.exists() and any(root.iterdir()):
        raise OuterError('fresh independent private outer root required')
    identities=_callbacks(callbacks); disabled=disabled or {}
    if (type(disabled) is not dict or set(disabled)&set(callbacks)
            or set(disabled)|set(callbacks)!=set(STAGES[:-1])
            or any(type(v) is not str or not 1<=len(v)<=512 for v in disabled.values())):
        raise OuterError('each stage needs a callback or explicit disabled reason')
    budget={'max_queue':128,'max_callback_calls':256,'max_run_ms':120000,
            **(budgets or {})}
    if (set(budget)!={'max_queue','max_callback_calls','max_run_ms'}
            or any(type(v) is not int or v<1 for v in budget.values())
            or budget['max_queue']>1024 or budget['max_callback_calls']>4096
            or budget['max_run_ms']>3600000):
        raise OuterError('bounded exact outer budgets required')
    binding=copy.deepcopy(bindings or {}); _bounded(binding);_stage_scopes(binding)
    root.mkdir(parents=True,exist_ok=True)
    authority=ScopeAuthority(root)
    scope=authority.create(program='XNET borrowed Oroboros outer coordinator',
        policy_url='local:xnet-outer-coordinator-v1',
        policy_capture=b'One bounded durable queue joins existing source, context, session, work, freeze, validation, learning and archive peers. Caller owns all callbacks and runtime lifecycles. Preserve completed replies and pending reservations. STOP and NullClaw precede dispatch. Outer completion is workflow evidence, never a model score. Private authorities/originals are not exportable transport content.',
        allowed_assets=['path:'+str(root)],methods=list(OuterTools.METHODS),
        fixture=True,allow_live_network=False,requests_per_minute=600,max_parallel=1)['scope_id']
    config={'schema':SCHEMA,'root':str(root),'scope_id':scope,'stages':list(STAGES),
            'callbacks':identities,'disabled':disabled,'bindings':binding,
            'budgets':budget,'source_pins':_pins()}
    config['signature_hmac_sha256']=hmac.new(authority._key(),canonical(config),hashlib.sha256).hexdigest()
    raw=_bounded(config)
    with (root/'config.json').open('xb') as stream:stream.write(raw)
    ledger=Ledger(root)
    ledger.append(make_event('outer-bootstrap',scope,'outer.bootstrap',
        {'config_sha256':sha256(raw)},source='oroboros-outer'))
    return config


class OroborosOuter:
    def __init__(self,root,callbacks,*,_inspection=False):
        self.root=Path(root).absolute(); _no_links(self.root)
        raw=(self.root/'config.json').read_bytes()
        if len(raw)>MAX_BYTES:raise OuterError('config frame too large')
        self.config=json.loads(raw)
        self._config_raw=raw;self._config_canonical=canonical(self.config)
        expected={'schema','root','scope_id','stages','callbacks','disabled','bindings','budgets','source_pins','signature_hmac_sha256'}
        if set(self.config)!=expected or self.config['schema']!=SCHEMA or self.config['root']!=str(self.root):
            raise OuterError('outer config binding mismatch')
        self.scopes=ScopeAuthority(self.root); self.scope_id=self.config['scope_id']
        unsigned={k:v for k,v in self.config.items() if k!='signature_hmac_sha256'}
        pin=hmac.new(self.scopes._key(),canonical(unsigned),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(pin,self.config['signature_hmac_sha256']):raise OuterError('outer config signature mismatch')
        self.callbacks=callbacks; self.tools=OuterTools(self.scopes);self._inspection=_inspection
        _stage_scopes(self.config['bindings'])
        if not (self.root/'ledger/xnet.sqlite3').is_file():raise OuterError('outer ledger missing; no silent reinitialization')
        self.ledger=_ReadOnlyLedger(self.root) if _inspection else Ledger(self.root)
        self.nullclaw=NullClaw(self.root,self.ledger)
        self.lock=self.root/'outer.lock';self._guard('outer_read')
        if not _inspection:self._state()

    def _guard(self,method,task_id=None):
        self._check_config()
        if self._inspection and method!='outer_read':raise OuterError('inspection cannot mutate or dispatch')
        self.tools.gate(self.scope_id,method,'path:'+str(self.root))
        _no_links(self.root)
        if self._inspection:
            for identity in self.config['callbacks'].values():
                path=Path(identity['path']);_no_links(path,regular_file=True)
                if sha256(path.read_bytes())!=identity['sha256']:raise OuterError('callback source drift')
        if self.config['source_pins']!=_pins() or (not self._inspection and self.config['callbacks']!=_callbacks(self.callbacks)):
            raise OuterError('outer/callback source drift; new identity required')
        if task_id and self.nullclaw.is_cancelled(task_id):raise OuterError('NullClaw task cancelled')
        if not self._inspection and self.nullclaw.is_contained('oroboros-outer'):raise OuterError('NullClaw outer source contained')

    def _check_config(self):
        _no_links(self.root/'config.json',regular_file=True)
        if ((self.root/'config.json').read_bytes()!=self._config_raw
                or canonical(self.config)!=self._config_canonical
                or self.config['root']!=str(self.root) or self.config['scope_id']!=self.scope_id):
            raise OuterError('signed outer configuration drift')

    def _put(self,value):
        return self.ledger.put_evidence(_bounded(value),source='oroboros-outer-private',scope_id=self.scope_id,
            metadata={'visibility':'private','cloud_export':False})

    def _get(self,pin):
        if type(pin) is not str or not _HEX.fullmatch(pin):raise OuterError('exact evidence pointer required')
        raw=self.ledger.get_evidence(pin)
        if len(raw)>MAX_BYTES or sha256(raw)!=pin:raise OuterError('outer evidence mismatch')
        return json.loads(raw)

    def _write(self,kind,task_id,body):
        wrapper={'schema':'xnet.oroboros-outer-record.v1','config_sha256':sha256((self.root/'config.json').read_bytes()),
                 'kind':kind,'body':body}
        pin=self._put(wrapper)
        return self.ledger.append(make_event(task_id,self.scope_id,'outer.'+kind,
            {'record_sha256':pin},source='oroboros-outer'))

    def _state(self):
        self._check_config()
        chain=self.ledger.verify_chain(); jobs={}; content={}; calls=0
        events=self.ledger.events(); boots=[e for e in events if e['kind']=='outer.bootstrap']
        config_pin=sha256((self.root/'config.json').read_bytes())
        if len(boots)!=1 or boots[0]['scope_id']!=self.scope_id or boots[0]['payload']!={'config_sha256':config_pin}:
            raise OuterError('outer bootstrap mismatch')
        for event in events:
            if not event['kind'].startswith('outer.') or event['kind']=='outer.bootstrap':continue
            if event['scope_id']!=self.scope_id or event['source']!='oroboros-outer' or set(event['payload'])!={'record_sha256'}:
                raise OuterError('outer event binding mismatch')
            wrapper=self._get(event['payload']['record_sha256']);kind=event['kind'][6:];body=wrapper.get('body')
            if (set(wrapper)!={'schema','config_sha256','kind','body'} or wrapper['schema']!='xnet.oroboros-outer-record.v1'
                    or wrapper['config_sha256']!=config_pin or wrapper['kind']!=kind or type(body) is not dict):
                raise OuterError('outer record binding mismatch')
            task=event['task_id']
            if kind=='enqueued':
                if task in jobs or body['content_sha256'] in content or set(body)!={'payload_sha256','content_sha256'}:
                    raise OuterError('duplicate outer admission')
                payload=self._get(body['payload_sha256'])
                if digest(payload)!=body['content_sha256']:raise OuterError('queued payload identity differs')
                jobs[task]={'task_id':task,**body,'cursor':0,'pending':None,'outputs':{},'status':'queued'}
                content[body['content_sha256']]=task;continue
            job=jobs.get(task)
            if job is None or job['cursor']>=len(STAGES):raise OuterError('transition after absent/completed job')
            stage=STAGES[job['cursor']]
            if body.get('stage')!=stage:raise OuterError('out-of-order outer transition')
            if kind=='reserved':
                if job['pending'] is not None or stage=='commit':raise OuterError('duplicate stage reservation')
                request=self._get(body['request_sha256'])
                expected_request={'schema':'xnet.oroboros-outer-request.v1','task_id':task,'stage':stage,
                    'scope_id':self.scope_id,'reservation_id':body['reservation_id'],
                    'stage_scope_id':_stage_scopes(self.config['bindings']).get(stage,self.scope_id),
                    'payload':self._get(job['payload_sha256']),
                    'previous_sha256':job['outputs'],
                    'previous':{s:self._get(p) for s,p in job['outputs'].items()},
                    'budgets':{'remaining_callback_calls':self.config['budgets']['max_callback_calls']-calls}}
                if (request!=expected_request or type(body['reservation_id']) is not str
                        or not re.fullmatch(r'[0-9a-f]{32}',body['reservation_id'])):
                    raise OuterError('reserved request binding mismatch')
                job['pending']=body;job['status']='reserved';calls+=1
            elif kind=='waiting':
                if not job['pending'] or body['reservation_id']!=job['pending']['reservation_id']:
                    raise OuterError('waiting reservation mismatch')
                if 'response_sha256' in body:self._get(body['response_sha256'])
                job['status']='waiting';job['waiting_reason']=body['reason']
            elif kind in ('completed','disabled','reconciled'):
                if kind=='disabled':
                    if stage not in self.config['disabled'] or job['pending'] is not None:
                        raise OuterError('undeclared disabled stage')
                elif stage!='commit':
                    if not job['pending'] or body.get('reservation_id')!=job['pending']['reservation_id']:
                        raise OuterError('completion reservation mismatch')
                elif job['pending'] is not None:raise OuterError('commit cannot have a callback reservation')
                result=self._get(body['result_sha256'])
                if result.get('status')!=('disabled' if kind=='disabled' else 'completed'):
                    raise OuterError('pending or undeclared disabled result cannot advance')
                if (result.get('task_id')!=task or result.get('stage')!=stage):raise OuterError('stage result task mismatch')
                if kind=='disabled' and result.get('reason')!=self.config['disabled'][stage]:
                    raise OuterError('disabled reason differs from declaration')
                if stage=='commit' and (result.get('stage_receipts')!=job['outputs']
                        or result.get('disabled_stages')!=list(self.config['disabled'])
                        or result.get('correctness_claim') is not False or result.get('learning_gain_claim') is not False):
                    raise OuterError('outer closure proof differs from completed stage receipts')
                if kind=='reconciled':
                    proof=self._get(body['reconciliation_sha256'])
                    if (set(proof)!={'evidence_sha256','justification','reservation_id','nested_recovery_required'}
                            or proof['reservation_id']!=job['pending']['reservation_id']
                            or result.get('outer_reservation_id')!=proof['reservation_id']
                            or proof['nested_recovery_required'] is not True
                            or type(proof['justification']) is not str or not 1<=len(proof['justification'])<=1024
                            or canonical(self._get(proof['evidence_sha256']))!=canonical(result)):
                        raise OuterError('reconciliation replay proof mismatch')
                job['outputs'][stage]=body['result_sha256'];job['cursor']+=1;job['pending']=None
                job.pop('waiting_reason',None);job['status']='completed' if job['cursor']==len(STAGES) else 'ready'
            else:raise OuterError('unknown outer transition')
        return {'jobs':jobs,'content':content,'calls':calls,'chain':chain}

    def enqueue(self,task_id,payload,*,expected_head=None):
        if type(task_id) is not str or not _ID.fullmatch(task_id) or type(payload) is not dict:
            raise OuterError('bounded task ID and operator payload required')
        _bounded(payload);self._guard('outer_enqueue',task_id)
        with _exclusive_file_lock(self.lock):
            state=self._state()
            if expected_head is not None and expected_head!=state['chain']['head']:raise OuterError('stale outer expected_head')
            content_pin=digest(payload)
            if task_id in state['jobs']:
                if state['jobs'][task_id]['content_sha256']!=content_pin:raise OuterError('task ID already binds different input')
                return {'task_id':task_id,'idempotent_replay':True,'head':state['chain']['head']}
            if content_pin in state['content']:
                return {'task_id':state['content'][content_pin],'idempotent_replay':True,'duplicate_input':True,'head':state['chain']['head']}
            if sum(j['status']!='completed' for j in state['jobs'].values())>=self.config['budgets']['max_queue']:
                raise OuterError('outer queue full')
            payload_pin=self._put(copy.deepcopy(payload));event=self._write('enqueued',task_id,
                {'payload_sha256':payload_pin,'content_sha256':content_pin})
            return {'task_id':task_id,'idempotent_replay':False,'head':event['receipt_hash']}

    def status(self):
        self._guard('outer_read');state=self._state()
        return {'schema':'xnet.oroboros-outer-status.v1','scope_id':self.scope_id,
            'head':state['chain']['head'],'events':state['chain']['events'],'callback_calls':state['calls'],
            'stages':list(STAGES),'completed_cycles':sum(j['status']=='completed' for j in state['jobs'].values()),
            'jobs':[{k:j[k] for k in ('task_id','status','cursor','outputs')}
                    | {'stage':STAGES[j['cursor']] if j['cursor']<len(STAGES) else None,
                       'pending_reservation':j['pending']['reservation_id'] if j['pending'] else None,
                       'waiting_reason':j.get('waiting_reason')} for j in state['jobs'].values()],
            'disabled_stages':copy.deepcopy(self.config['disabled']),
            'outer_contained':self.nullclaw.is_contained('oroboros-outer'),
            'daemon_started':False,'remote_provider_verified_by_outer':False}

    def step(self,*,control='RUN',expected_head=None):
        if control not in ('RUN','STOP'):raise OuterError('explicit RUN/STOP required')
        self._guard('outer_step')
        if control=='STOP':return {'status':'stopped','head':self._state()['chain']['head']}
        with _exclusive_file_lock(self.lock):
            state=self._state()
            if expected_head is not None and expected_head!=state['chain']['head']:raise OuterError('stale outer expected_head')
            job=next((j for j in state['jobs'].values() if j['status']!='completed'),None)
            if job is None:return {'status':'idle','head':state['chain']['head']}
            task=job['task_id'];self._guard('outer_step',task);stage=STAGES[job['cursor']]
            if job['pending']:raise OuterPending('pending '+stage+' requires nested recovery and explicit outer reconciliation')
            if stage in self.config['disabled']:
                result={'status':'disabled','task_id':task,'stage':stage,'reason':self.config['disabled'][stage]}
                event=self._write('disabled',task,{'stage':stage,'result_sha256':self._put(result)})
                return result|{'head':event['receipt_hash']}
            if stage=='commit':
                result={'status':'completed','stage':stage,'task_id':task,'stage_receipts':job['outputs'],
                        'disabled_stages':list(self.config['disabled']),'correctness_claim':False,'learning_gain_claim':False}
                event=self._write('completed',task,{'stage':stage,'result_sha256':self._put(result)})
                return result|{'head':event['receipt_hash']}
            if state['calls']>=self.config['budgets']['max_callback_calls']:
                return {'status':'budget_exhausted','task_id':task,'stage':stage,'head':state['chain']['head']}
            reservation=uuid.uuid4().hex
            request={'schema':'xnet.oroboros-outer-request.v1','task_id':task,'stage':stage,
                'scope_id':self.scope_id,'reservation_id':reservation,'payload':self._get(job['payload_sha256']),
                'stage_scope_id':_stage_scopes(self.config['bindings']).get(stage,self.scope_id),
                'previous_sha256':copy.deepcopy(job['outputs']),
                'previous':{s:self._get(p) for s,p in job['outputs'].items()},
                'budgets':{'remaining_callback_calls':self.config['budgets']['max_callback_calls']-state['calls']}}
            request_pin=self._put(request)
            self._write('reserved',task,{'stage':stage,'reservation_id':reservation,'request_sha256':request_pin})
            started=time.monotonic()
            raw_response=None;elapsed_ms=None
            try:
                response=self.callbacks[stage](copy.deepcopy(request))
                elapsed_ms=round((time.monotonic()-started)*1000)
                raw_response=self._put(response)
                self._guard('outer_step',task) # Preserve returned bytes even if cancellation arrived.
                if type(response) is not dict or response.get('status') not in ('completed','waiting','disabled'):
                    raise OuterError('bounded structured stage result required')
                if response.get('task_id')!=task or response.get('stage')!=stage:
                    raise OuterError('borrowed callback returned another task or stage')
                if response['status']!='completed':
                    reason='callback waiting: '+str(response.get('reason',response.get('status')))[:768]
                    self._write('waiting',task,{'stage':stage,'reservation_id':reservation,'reason':reason,
                        'response_sha256':raw_response,'elapsed_ms':elapsed_ms})
                    return {'status':'waiting','task_id':task,'stage':stage,'reservation_id':reservation,
                            'response_sha256':raw_response,'reason':reason}
                event=self._write('completed',task,{'stage':stage,'reservation_id':reservation,
                    'result_sha256':raw_response,'elapsed_ms':elapsed_ms})
                return {'status':'completed','task_id':task,'stage':stage,'result_sha256':raw_response,
                        'elapsed_ms':elapsed_ms,'head':event['receipt_hash']}
            except Exception as error:
                retained={'stage':stage,'reservation_id':reservation,
                    'reason':type(error).__name__+': '+str(error)[:768]}
                if raw_response is not None:retained.update(response_sha256=raw_response,elapsed_ms=elapsed_ms)
                self._write('waiting',task,retained)
                raise

    def retain_reconciliation_evidence(self,result):
        """Seal a confirmed pending response privately, without advancing or dispatch."""
        if type(result) is not dict or result.get('status')!='completed':
            raise OuterError('confirmed completed nested result required')
        task=result.get('task_id')
        if type(task) is not str or not _ID.fullmatch(task):raise OuterError('bounded pending task required')
        self._guard('outer_reconcile',task)
        with _exclusive_file_lock(self.lock):
            state=self._state();job=state['jobs'].get(task)
            if (not job or not job['pending'] or result.get('stage')!=STAGES[job['cursor']]
                    or result.get('outer_reservation_id')!=job['pending']['reservation_id']):
                raise OuterError('confirmed result must bind current pending task/stage/reservation')
            return self._put(copy.deepcopy(result))

    def reconcile(self,task_id,result,*,evidence_sha256,justification,expected_head=None):
        self._guard('outer_reconcile',task_id)
        if type(justification) is not str or not 1<=len(justification)<=1024:raise OuterError('recovery justification required')
        evidence=self._get(evidence_sha256)
        if type(result) is not dict or result.get('status')!='completed':raise OuterError('confirmed completed nested result required')
        if canonical(evidence)!=canonical(result):raise OuterError('recovery evidence must bind exact confirmed result')
        with _exclusive_file_lock(self.lock):
            state=self._state();job=state['jobs'].get(task_id)
            if expected_head is not None and expected_head!=state['chain']['head']:raise OuterError('stale outer expected_head')
            if not job or not job['pending']:raise OuterError('known pending outer reservation required')
            stage=STAGES[job['cursor']]
            if (result.get('task_id')!=task_id or result.get('stage')!=stage
                    or result.get('outer_reservation_id')!=job['pending']['reservation_id']):
                raise OuterError('reconciled result/task/reservation mismatch')
            recovery=self._put({'evidence_sha256':evidence_sha256,'justification':justification,
                'reservation_id':job['pending']['reservation_id'],'nested_recovery_required':True})
            event=self._write('reconciled',task_id,{'stage':stage,'reservation_id':job['pending']['reservation_id'],
                'result_sha256':self._put(result),'reconciliation_sha256':recovery})
            return {'status':'reconciled','task_id':task_id,'stage':stage,'head':event['receipt_hash']}

    def run(self,*,max_steps=9,control='RUN'):
        if type(max_steps) is not int or not 1<=max_steps<=1024:raise OuterError('bounded max_steps required')
        start=time.monotonic();results=[]
        for _ in range(max_steps):
            if (time.monotonic()-start)*1000>=self.config['budgets']['max_run_ms']:
                results.append({'status':'budget_exhausted','reason':'run wall budget'});break
            action=control() if callable(control) else control
            result=self.step(control=action);results.append(result)
            if result['status'] in ('waiting','idle','stopped','budget_exhausted'):break
        return {'schema':'xnet.oroboros-outer-run.v1','results':results,'state':self.status()}
