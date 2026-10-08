"""Durable caller-owned fresh-session handshake over the native context gateway.

No model runner, HTTP transport or candidate execution lives here. The caller
reports current occupancy and owns fresh-session creation. An uncertain callback
is reserved durably and can only be reconciled, never blindly repeated.
"""
from __future__ import annotations
import copy
import json
import math
from pathlib import Path
import re

from xnet_sdk import ContextPeer, XnetError
from .brains import _exclusive_file_lock
from .protocol import canonical, digest, sha256
from .relay_log import _no_links
from .repair_loop import _read, _save, validate_run_identity, verify_run_identity_artifacts

_HEX = re.compile(r'[0-9a-f]{64}')
_ID = re.compile(r'[A-Za-z0-9_-]{1,128}')

class PendingHandoff(RuntimeError):
    """The caller must establish the old callback's outcome and reconcile it."""

class OroborosSession:
    """One declared session owner; borrow the same gateway used by other peers.

    Other peers append context using ContextPeer. This owner binds and reports
    the worker session. Model/runner pins and current token counts are caller
    declarations, not proof of server weights or tokenizer state.
    """
    def __init__(self, root, peer: ContextPeer, *, model_sha256, runner_sha256, window, reserve,
                 run_identity=None, model_id=None):
        if any(type(pin) is not str or not _HEX.fullmatch(pin) for pin in (model_sha256,runner_sha256)):
            raise ValueError('declared model/runner SHA256 pins required')
        if type(window) is not int or type(reserve) is not int or not 0 < reserve < window:
            raise ValueError('positive window and output reservation required')
        if run_identity is None:
            if model_id is not None: raise ValueError('model_id requires a complete run identity')
            identity=None
        else:
            if type(model_id) is not str or not _ID.fullmatch(model_id):
                raise ValueError('one selected model ID required for session run identity')
            identity=validate_run_identity(run_identity,
                {model_id:{'model_sha256':model_sha256,'runner_sha256':runner_sha256}},cas=peer.client)
        self.root=Path(root).absolute();_no_links(self.root)
        self.peer=peer
        self.config={'schema':'xnet.oroboros-session.v1','task_id':peer.task_id,'peer':peer.peer,
                     'model_sha256':model_sha256,'runner_sha256':runner_sha256,'window':window,'reserve':reserve,
                     'gateway_root':str(peer.client.root),'gateway_binary_sha256':peer.client.binary_sha256,
                     'implementation_sha256':sha256(Path(__file__).read_bytes()),
                     'occupancy_basis':'caller_reported_current_snapshot','model_process_owned':False}
        if identity is not None:
            self.config.update(model_id=model_id,run_identity=identity,run_identity_sha256=digest(identity))
        self.root.mkdir(parents=True,exist_ok=True)
        with self._lock():
            manifest=self.root/'manifest.json'
            if manifest.exists():
                if _read(manifest)['config']!=self.config: raise ValueError('session-controller resume identity changed')
            else:
                if any(path.name!='dispatch.lock' for path in self.root.iterdir()):
                    raise ValueError('nonempty controller root requires operator recovery')
                _save(manifest,{'config':self.config})

    def _lock(self):
        _no_links(self.root/'dispatch.lock')
        return _exclusive_file_lock(self.root/'dispatch.lock',timeout=1)

    def bind(self, session_id):
        self._verify_current_identity()
        return self.peer.bind(session_id,**{key:self.config[key] for key in ('model_sha256','runner_sha256','window','reserve')})

    def _verify_current_identity(self):
        if sha256(Path(__file__).read_bytes())!=self.config['implementation_sha256']:
            raise ValueError('session controller source changed; use a new reviewed run')
        verify_run_identity_artifacts(self.config.get('run_identity'),cas=self.peer.client)

    def _directory(self, plan_id):
        if type(plan_id) is not str or not _HEX.fullmatch(plan_id): raise ValueError('invalid handoff plan ID')
        return self.root/'handoffs'/plan_id

    def _validate_plan(self, plan):
        self._verify_current_identity()
        if type(plan) is not dict: raise ValueError('invalid handoff plan')
        self._directory(plan.get('plan_id'))
        for key in ('task_id','peer','model_sha256','runner_sha256','window','reserve'):
            if plan.get(key)!=self.config[key]: raise ValueError('handoff owner or declaration changed')
        packet=plan['capsule'];pack=packet['pack']
        if packet.get('work_performed') is not False or packet.get('authority')!='none' or pack.get('context_only') is not True:
            raise ValueError('handoff is not source-only context')
        stored=self.peer.client.fetch(packet['seal']['digest'])['text']
        if len(stored.encode('utf-8'))!=packet['seal']['bytes'] or canonical(json.loads(stored))!=canonical(pack):
            raise ValueError('capsule differs from sealed bytes')
        seals={seal['digest'] for seal in packet['source_seals']}
        for record in pack['records']:
            if record['id']!=sha256(record['text'].encode('utf-8')) or record['id'] not in seals:
                raise ValueError('occurrence source binding failed')
            if self.peer.client.fetch(record['id'])['text']!=record['text']:
                raise ValueError('occurrence source changed')
            event=json.loads(record['text'])
            if event['task_id']!=self.peer.task_id or event['source_digest']!=sha256(event['text'].encode('utf-8')):
                raise ValueError('cross-task or altered raw source')
            if self.peer.client.fetch(event['source_digest'])['text']!=event['text']:
                raise ValueError('raw history differs from handoff')
        return plan

    def _validate_reply(self, plan, reply):
        fields={'plan_id','new_session_id','model_sha256','runner_sha256','capsule_digest','prompt_sha256','used','fresh_context'}
        if type(reply) is not dict or set(reply)!=fields or len(canonical(reply))>65536:
            raise ValueError('unexpected fresh-session reply')
        for key in ('plan_id','model_sha256','runner_sha256'):
            if reply[key]!=plan[key]: raise ValueError('fresh-session reply identity mismatch')
        if reply['capsule_digest']!=plan['capsule']['seal']['digest'] or reply['fresh_context'] is not True:
            raise ValueError('exact bootstrap and fresh-context declaration required')
        if (type(reply['new_session_id']) is not str or not _ID.fullmatch(reply['new_session_id'])
            or reply['new_session_id']==plan['old_session_id'] or type(reply['prompt_sha256']) is not str
            or not _HEX.fullmatch(reply['prompt_sha256']) or type(reply['used']) is not int
            or not 0 < reply['used'] < plan['window'] or reply['used']+plan['reserve']>plan['window']
            or reply['used']*100>=plan['window']*80):
            raise ValueError('invalid new session or current bootstrap occupancy')
        return reply

    def _ack(self, plan, reply):
        self._validate_plan(plan)
        self._validate_reply(plan,reply)
        state=self.peer.acknowledge(**{key:reply[key] for key in ('plan_id','new_session_id','capsule_digest','prompt_sha256','used')})
        if (state['pending'] is not None or state['session']['session_id']!=reply['new_session_id']
            or state['session']['used']!=reply['used']):
            raise XnetError('native acknowledgment state differs from caller reply')
        _save(self._directory(plan['plan_id'])/'ack.json',{'plan_id':plan['plan_id'],'reply_sha256':digest(reply),
              'native_state':state,'attestation':'caller-reported; not independent runner verification'})
        # An exact ACK replay may return its original committed snapshot. Query
        # current state separately instead of presenting that snapshot as live.
        return {'status':'acknowledged','plan_id':plan['plan_id'],'acknowledged_state':state,
                'state':self.peer.state()}

    def deliver(self, plan, open_fresh):
        """Invoke a caller once. Callback exceptions leave an uncertain reservation.

        open_fresh(plan) must create a distinct empty worker session, load the
        exact capsule as context data and measure the complete bootstrap prompt
        (including its template/system text). It owns all actual runner actions.
        No old-session cancellation or process shutdown is inferred here.
        """
        with self._lock():
            directory=self._directory(plan.get('plan_id'))
            started=directory/'started.json';reply_path=directory/'reply.json'
            if started.exists():
                saved=_read(started)
                if canonical(saved['plan'])!=canonical(plan): raise ValueError('reserved handoff plan changed')
                if not reply_path.exists(): raise PendingHandoff(str(started))
                return self._ack(saved['plan'],_read(reply_path)['reply'])
            self._validate_plan(plan)
            native=self.peer.state()
            if canonical(native['pending'])!=canonical(plan):
                raise ValueError('plan is not the currently prepared native handoff')
            snapshot={key:native['session'][key] for key in ('session_id','revision','used','prompt_sha256')}
            _save(started,{'plan':plan,'snapshot':snapshot,'status':'callback-reserved','model_calls_owned_by_caller':True})
            reply=open_fresh(copy.deepcopy(plan))
            # Persist the actual returned envelope even when it fails admission.
            # Never silently invoke a second fresh-session callback.
            if len(canonical(reply))>65536: raise ValueError('fresh-session envelope exceeds bound; reservation remains pending')
            _save(reply_path,{'plan_id':plan['plan_id'],'reply':reply,'reconciled':False})
            return self._ack(plan,reply)

    def reconcile(self, plan_id, reply):
        """Supply the actual outcome after confirming the reserved callback ended."""
        with self._lock():
            self._verify_current_identity()
            directory=self._directory(plan_id);saved=_read(directory/'started.json')
            if saved['plan']['plan_id']!=plan_id: raise ValueError('reserved plan ID changed')
            if (directory/'reply.json').exists(): raise ValueError('reserved callback already has a reply')
            self._validate_reply(saved['plan'],reply)
            _save(directory/'reply.json',{'plan_id':plan_id,'reply':reply,'reconciled':True})
            return self._ack(saved['plan'],reply)

    def _predictive_snapshot(self, state, snapshot):
        if (type(snapshot) is not dict or set(snapshot)!={'session_id','revision','used','prompt_sha256'}
            or type(snapshot['session_id']) is not str or not _ID.fullmatch(snapshot['session_id'])
            or type(snapshot['revision']) is not int or snapshot['revision']<0
            or type(snapshot['used']) is not int or not 0<=snapshot['used']<=self.config['window']
            or type(snapshot['prompt_sha256']) is not str or not _HEX.fullmatch(snapshot['prompt_sha256'])):
            raise ValueError('complete absolute occupancy snapshot required for prediction')
        session=state.get('session')
        if state.get('task_id')!=self.config['task_id'] or type(session) is not dict:
            raise ValueError('prediction requires the bound task session')
        if state.get('pending') is not None:
            raise PendingHandoff('prediction cannot replace a prepared native transition')
        for key in ('peer','model_sha256','runner_sha256','window','reserve'):
            if session.get(key)!=self.config[key]: raise ValueError('predictive session declaration changed')
        if any(session.get(key)!=snapshot[key] for key in snapshot):
            raise ValueError('prediction snapshot differs from current measured native state')
        if session.get('occupancy_basis')!='caller_reported_current_snapshot':
            raise ValueError('prediction cannot use cumulative billed token counts')

    def _predictive_history(self, directory, manifest):
        paths=sorted((directory/'observations').glob('*.json'))
        if len(paths)>=2048: raise ValueError('predictive observation capacity reached; use a new root')
        rows=[];previous=None
        for index,path in enumerate(paths):
            if path.name!=f'{index:06d}.json': raise ValueError('predictive journal sequence changed')
            row=_read(path)
            if (row.get('schema')!='xnet.oroboros-predictive-observation.v1'
                or row.get('ordinal')!=index or row.get('previous_receipt_sha256')!=previous
                or row.get('manifest_sha256')!=manifest['receipt_sha256']
                or row.get('task_id')!=self.config['task_id']):
                raise ValueError('predictive journal identity or chain changed')
            rows.append(row);previous=row['receipt_sha256']
        return rows

    def _predictive_prefetch(self, state, required_ids, max_bytes):
        selected={};after=0
        for _ in range(64):  # Native history admits at most 2048 occurrences, 32 per page.
            page=self.peer.history(after=after,limit=32)
            if (page.get('task_id')!=self.config['task_id']
                or page.get('history_head')!=state['history_head']
                or page.get('history_count')!=state['history_count']):
                raise ValueError('cross-task history or history-head drift during prefetch')
            for event in page['events']:
                if event['event_id'] in required_ids:
                    if event['event_id'] in selected: raise ValueError('ambiguous selected context ID')
                    selected[event['event_id']]=copy.deepcopy(event)
            cursor=page['next_after']
            if cursor is None: break
            if type(cursor) is not int or cursor<=after: raise ValueError('history cursor did not advance')
            after=cursor
        else:
            raise ValueError('task history exceeds predictive scan bound')
        if set(selected)!=set(required_ids): raise ValueError('required predictive context ID missing')
        records=[];sources=[];raw_bytes=0
        for event_id in required_ids:
            event=selected[event_id]
            text=self.peer.fetch_event(event)  # SDK verifies exact raw UTF-8 source SHA256.
            if type(text) is not str or sha256(text.encode('utf-8'))!=event['source_digest']:
                raise ValueError('prefetched raw source changed')
            raw_bytes+=len(text.encode('utf-8'))
            if raw_bytes>max_bytes: raise ValueError('prefetched raw source exceeds byte budget')
            envelope={'task_id':self.config['task_id'],**{key:event[key] for key in
                      ('seq','peer','event_id','kind','source_digest')},'text':text}
            encoded=canonical(envelope).decode('utf-8')
            records.append({'id':sha256(encoded.encode('utf-8')),'kind':'raw','text':encoded})
            sources.append({'event_id':event_id,'event_digest':event['event_digest'],
                            'source_digest':event['source_digest'],'bytes':len(text.encode('utf-8'))})
        packet=self.peer.client.pack_context(records,max_bytes=max_bytes)
        pack=packet['pack']
        if (packet.get('authority')!='none' or packet.get('work_performed') is not False
            or pack.get('context_only') is not True or pack.get('omitted')
            or canonical(pack.get('records'))!=canonical(records)
            or packet['seal']['bytes']>max_bytes):
            raise ValueError('predictive preview did not retain all selected raw sources')
        sealed=self.peer.client.fetch(packet['seal']['digest'])['text']
        if (sha256(sealed.encode('utf-8'))!=packet['seal']['digest']
            or len(sealed.encode('utf-8'))!=packet['seal']['bytes']
            or canonical(json.loads(sealed))!=canonical(pack)):
            raise ValueError('predictive preview capsule source binding changed')
        return packet,sources,raw_bytes

    def predictive_ring(self, snapshot, *, observation_id, observed_at_seconds, required_ids, max_bytes=8192):
        """Forecast and prefetch task-bound raw data, without preparing a rotation.

        Caller supplies a unique observation and monotonic measurement time.
        snapshot must already be the exact absolute native occupancy report.
        The latest eight observations of this same session estimate upper recent
        positive growth; estimates are advisory and never invoke a model callback.
        report_and_rotate uses actual measured RUN or insufficient output room.
        """
        if type(observation_id) is not str or not _ID.fullmatch(observation_id):
            raise ValueError('unique bounded predictive observation ID required')
        if (type(observed_at_seconds) not in (int,float) or not math.isfinite(observed_at_seconds)
            or observed_at_seconds<0): raise ValueError('finite monotonic observation time required')
        if (type(required_ids) is not list or not 1<=len(required_ids)<=16
            or any(type(value) is not str or not _ID.fullmatch(value) for value in required_ids)
            or len(set(required_ids))!=len(required_ids)):
            raise ValueError('one to sixteen unique task context IDs required')
        if type(max_bytes) is not int or not 128<=max_bytes<=32768:
            raise ValueError('bounded predictive context byte budget required')
        with self._lock():
            self._verify_current_identity()
            state=self.peer.state();self._predictive_snapshot(state,snapshot)
            directory=self.root/'predictive-ring';_no_links(directory)
            config={'schema':'xnet.oroboros-predictive-ring.v1','session_config_sha256':digest(self.config),
                    'task_id':self.config['task_id'],'history_length':8,'observation_capacity':2048,
                    'run_percent':80,'growth_policy':'maximum-positive-recent-absolute-difference',
                    'clock_basis':'caller-monotonic-observation-seconds','authority':'none',
                    'rotation_basis':'actual-native-current-occupancy-only','model_work':False}
            manifest_path=directory/'manifest.json'
            if manifest_path.exists():
                manifest=_read(manifest_path)
                if manifest['config']!=config: raise ValueError('predictive manifest identity changed')
            else:
                manifest=_save(manifest_path,{'config':config})
            history=self._predictive_history(directory,manifest)
            if any(row['observation_id']==observation_id for row in history):
                raise ValueError('duplicate predictive observation ID')
            if history and observed_at_seconds<=history[-1]['observed_at_seconds']:
                raise ValueError('observation times must increase strictly')
            session_rows=[row for row in history if row['snapshot']['session_id']==snapshot['session_id']]
            if session_rows and snapshot['revision']<=session_rows[-1]['snapshot']['revision']:
                raise ValueError('duplicate or stale measured session revision')
            recent=(session_rows+[{'snapshot':snapshot,'observed_at_seconds':observed_at_seconds}])[-8:]
            increments=[right['snapshot']['used']-left['snapshot']['used']
                        for left,right in zip(recent,recent[1:])]
            elapsed=[right['observed_at_seconds']-left['observed_at_seconds']
                     for left,right in zip(recent,recent[1:])]
            growing=bool(increments) and all(delta>=0 for delta in increments) and any(delta>0 for delta in increments)
            rate=max((delta/seconds for delta,seconds in zip(increments,elapsed)),default=0) if growing else None
            per_observation=max(increments) if growing else None
            if rate is not None and not math.isfinite(rate):
                raise ValueError('observation clock interval cannot produce a finite growth estimate')
            run_tokens=(self.config['window']*80+99)//100
            reserve_limit=self.config['window']-self.config['reserve']
            def estimate(target):
                remaining=max(0,target-snapshot['used'])
                return {'remaining_tokens':remaining,
                        'seconds':0 if remaining==0 else remaining/rate if rate else None,
                        'observations':0 if remaining==0 else math.ceil(remaining/per_observation) if per_observation else None}
            forecast={'basis':'caller-reported-absolute-snapshots','recent_observations':len(recent),
                      'trend':'growing' if growing else 'insufficient' if not increments else 'decreased-or-flat',
                      'tokens_per_second':rate,'tokens_per_observation':per_observation,
                      'run_threshold_tokens':run_tokens,'output_reserve_tokens':self.config['reserve'],
                      'output_reserve_limit_tokens':reserve_limit,'to_run':estimate(run_tokens),
                      'to_output_reserve_limit':estimate(reserve_limit),
                      'safe_headroom_tokens':max(0,min(run_tokens,reserve_limit)-snapshot['used']),
                      'measured_run_due':snapshot['used']*100>=self.config['window']*80}
            packet,sources,raw_bytes=self._predictive_prefetch(state,required_ids,max_bytes)
            self._verify_current_identity()
            if canonical(self.peer.state())!=canonical(state):
                raise ValueError('native snapshot/history drift during predictive prefetch')
            index=len(history);path=directory/'observations'/f'{index:06d}.json'
            if path.exists(): raise ValueError('predictive observation slot already exists')
            return _save(path,{'schema':'xnet.oroboros-predictive-observation.v1','ordinal':index,
                'observation_id':observation_id,'observed_at_seconds':observed_at_seconds,
                'task_id':self.config['task_id'],'snapshot':copy.deepcopy(snapshot),
                'history_head':state['history_head'],'history_count':state['history_count'],
                'manifest_sha256':manifest['receipt_sha256'],
                'previous_receipt_sha256':history[-1]['receipt_sha256'] if history else None,
                'forecast':forecast,'required_ids':list(required_ids),'prefetched_sources':sources,
                'prefetched_raw_bytes':raw_bytes,'max_bytes':max_bytes,'preview_capsule':packet,
                'authority':'none','work_performed':False,'native_transition_prepared':False})

    def report_and_rotate(self, snapshot, open_fresh, *, required_ids, max_bytes=8192):
        """Prepare/deliver at measured RUN or when output reserve cannot fit.

        snapshot is absolute current occupancy, not billed/cumulative usage.
        Exact used + reserve == window fits; forecasts never trigger a handoff.
        A pending native handoff accepts only the same frozen old snapshot.
        """
        if type(snapshot) is not dict or set(snapshot)!={'session_id','revision','used','prompt_sha256'}:
            raise ValueError('complete current-session snapshot required')
        self._verify_current_identity()
        # Discover a reply saved before a lost ACK response/local completion.
        # Recovery invokes only the native idempotent ACK, never open_fresh.
        recover=None
        with self._lock():
            handoffs=self.root/'handoffs';_no_links(handoffs)
            for started in handoffs.glob('*/started.json'):
                if (started.parent/'ack.json').exists(): continue
                saved=_read(started)
                if canonical(saved['snapshot'])==canonical(snapshot):
                    if recover is not None: raise ValueError('ambiguous reserved handoff snapshot')
                    recover=saved['plan']
        if recover is not None: return self.deliver(recover,open_fresh)
        state=self.peer.state()
        if state['pending'] is not None:
            session=state['session']
            if any(snapshot[key]!=session[key] for key in ('session_id','revision','used','prompt_sha256')):
                raise PendingHandoff('another snapshot cannot replace the prepared handoff')
            plan=state['pending']
        else:
            state=self.peer.occupancy(**snapshot)
            session=state['session']
            if (session['depth']!='Run'
                and session['used']+session['reserve']<=session['window']):
                return {'status':'not-due','state':state}
            plan=self.peer.prepare(snapshot['session_id'],required_ids=required_ids,max_bytes=max_bytes,
                                   expected_head=state['history_head'])
        return self.deliver(plan,open_fresh)
