"""Actual native handoff/controller checks. Trusted metadata callbacks, zero models."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_native_public import BINARY as RUST
import hashlib

def pin(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

from xnet_sdk import Client, ContextPeer
from xnet.oroboros_session import OroborosSession, PendingHandoff
from xnet.protocol import canonical, sha256
from xnet.repair_loop import _read

MODEL='a'*64  # Synthetic declared artifact pins, not a model score/run.
RUNNER='b'*64

def reply(plan, session='fresh-2'):
    return {'plan_id':plan['plan_id'],'new_session_id':session,'model_sha256':MODEL,
            'runner_sha256':RUNNER,'capsule_digest':plan['capsule']['seal']['digest'],
            'prompt_sha256':sha256(canonical({'fixture_bootstrap':plan['capsule']['pack']})),
            'used':25,'fresh_context':True}

def fixture_identity(root, runtime):
    root.mkdir()
    adapter=root/'adapter.py';adapter.write_bytes(b'# inert metadata callback fixture\n')
    server=root/'server.exe';server.write_bytes(b'fixture launcher; never executed')
    dll=root/'server-impl.dll';dll.write_bytes(b'fixture implementation; never loaded')
    def artifact(path): return {'path':str(path.absolute()),'sha256':pin(path)}
    package=Path(__file__).resolve().parents[1]/'xnet_sdk'
    model='deepseek-coder-v2-lite'
    identity={'schema':'xnet.repair-run-identity.v1','adapter':artifact(adapter),
              'runner':{'source_revision':'trusted-inert-fixture','artifacts':[artifact(server),artifact(dll)]},
              'models':{model:{'decoding':{'temperature':0.1},'transport':{'kind':'metadata-fixture'},
                         'tokenizer':{'id':'fixture-not-measured','sha256':None},
                         'template':{'id':'fixture-not-measured','sha256':None}}},
              'native':{'binary':artifact(runtime.binary),
                        'sdk_artifacts':[artifact(package/name) for name in ('__init__.py','client.py','context.py')]}}
    return identity,model,server,dll,adapter

@unittest.skipUnless(RUST.is_file(),'Build the native history operations first')
class OroborosSessionTests(unittest.TestCase):
    def setup_case(self, runtime, root, *, window=1000, reserve=100):
        task='deepseek-lite-fixture'
        for peer,event,text in [('operator','intent','Keep the exact API'),('assistant','fabric','Context passes data only'),('peer','runner','DeepSeek Lite only for local model testing')]:
            ContextPeer(runtime,task_id=task,peer=peer).append(event,text)
        peer=ContextPeer(runtime,task_id=task,peer='peer')
        controller=OroborosSession(root,peer,model_sha256=MODEL,runner_sha256=RUNNER,window=window,reserve=reserve)
        controller.bind('old-1')
        snapshot={'session_id':'old-1','revision':1,'used':850,'prompt_sha256':sha256(b'trusted fixture current prompt')}
        return peer,controller,snapshot

    def test_threshold_uses_current_report_then_exact_context_callback(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            peer,controller,snapshot=self.setup_case(runtime,Path(tmp)/'dispatch')
            callback=Mock(side_effect=reply)
            low={**snapshot,'used':450}
            self.assertEqual(controller.report_and_rotate(low,callback,required_ids=['intent'])['status'],'not-due')
            self.assertEqual(callback.call_count,0)
            observed={**snapshot,'revision':2}
            result=controller.report_and_rotate(observed,callback,required_ids=['intent','fabric'])
            self.assertEqual(result['status'],'acknowledged');self.assertEqual(callback.call_count,1)
            self.assertEqual(result['state']['session']['used'],25)
            self.assertEqual(result['state']['session']['depth'],'Swim')
            self.assertIsNone(result['state']['pending'])
            self.assertTrue(runtime.call('verify')['ok'])

    def test_reserve_trigger_exact_fit_and_prediction_never_prepares(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            peer,controller,snapshot=self.setup_case(runtime,Path(tmp)/'dispatch',window=2048,reserve=650)
            callback=Mock(side_effect=reply)
            fit={**snapshot,'used':1398}
            result=controller.report_and_rotate(fit,callback,required_ids=['intent'])
            self.assertEqual(result['status'],'not-due')
            self.assertEqual(result['state']['session']['depth'],'Bike')
            self.assertEqual(callback.call_count,0)
            controller.predictive_ring(fit,observation_id='exact-fit',observed_at_seconds=10,required_ids=['intent'])
            insufficient={**fit,'revision':2,'used':1399}
            peer.occupancy(**insufficient)
            with patch.object(peer,'prepare',side_effect=AssertionError('forecast prepared a transition')):
                prediction=controller.predictive_ring(insufficient,observation_id='no-room',
                    observed_at_seconds=20,required_ids=['intent'])
            self.assertEqual(prediction['forecast']['to_run']['remaining_tokens'],240)
            self.assertEqual(prediction['forecast']['to_output_reserve_limit']['remaining_tokens'],0)
            self.assertFalse(prediction['native_transition_prepared'])
            self.assertIsNone(peer.state()['pending'])
            result=controller.report_and_rotate(insufficient,callback,required_ids=['intent'])
            self.assertEqual(result['status'],'acknowledged')
            self.assertEqual(callback.call_count,1)
            self.assertEqual(result['state']['session']['used'],25)

    def test_reserve_trigger_uncertain_callback_survives_restart_without_repeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);callback=Mock(side_effect=TimeoutError('caller session outcome unknown'))
            with Client(RUST,root/'XNET',sha256=pin(RUST)) as runtime:
                peer,controller,snapshot=self.setup_case(runtime,root/'dispatch',window=2048,reserve=650)
                insufficient={**snapshot,'used':1399}
                with self.assertRaises(TimeoutError):
                    controller.report_and_rotate(insufficient,callback,required_ids=['intent'])
                plan=peer.state()['pending'];self.assertIsNotNone(plan)
                self.assertEqual(peer.state()['session']['depth'],'Bike')
            with Client(RUST,root/'XNET',sha256=pin(RUST)) as runtime:
                peer=ContextPeer(runtime,task_id='deepseek-lite-fixture',peer='peer')
                controller=OroborosSession(root/'dispatch',peer,model_sha256=MODEL,
                    runner_sha256=RUNNER,window=2048,reserve=650)
                self.assertEqual(peer.state()['pending'],plan)
                with self.assertRaises(PendingHandoff):
                    controller.report_and_rotate(insufficient,callback,required_ids=['intent'])
                self.assertEqual(callback.call_count,1)
                result=controller.reconcile(plan['plan_id'],reply(plan))
                self.assertEqual(result['status'],'acknowledged')
                self.assertEqual(callback.call_count,1)

    def test_reserve_trigger_fresh_reply_must_fit_and_saved_rejection_is_not_replaced(self):
        for used,accepted in ((1398,True),(1399,False)):
            with self.subTest(bootstrap_used=used), tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
                peer,controller,snapshot=self.setup_case(runtime,Path(tmp)/'dispatch',window=2048,reserve=650)
                insufficient={**snapshot,'used':1399}
                callback=Mock(side_effect=lambda plan:{**reply(plan),'used':used})
                if accepted:
                    result=controller.report_and_rotate(insufficient,callback,required_ids=['intent'])
                    self.assertEqual(result['status'],'acknowledged')
                    self.assertEqual(result['state']['session']['used'],1398)
                    self.assertEqual(result['state']['session']['depth'],'Bike')
                else:
                    with self.assertRaisesRegex(ValueError,'bootstrap occupancy'):
                        controller.report_and_rotate(insufficient,callback,required_ids=['intent'])
                    plan=peer.state()['pending']
                    saved=_read(controller.root/'handoffs'/plan['plan_id']/'reply.json')
                    self.assertEqual(saved['reply']['used'],1399)
                    with self.assertRaisesRegex(ValueError,'bootstrap occupancy'):
                        controller.report_and_rotate(insufficient,callback,required_ids=['intent'])
                self.assertEqual(callback.call_count,1)

    def test_timeout_reservation_survives_native_and_controller_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);callback=Mock(side_effect=TimeoutError('caller session outcome unknown'))
            with Client(RUST,root/'XNET',sha256=pin(RUST)) as runtime:
                peer,controller,snapshot=self.setup_case(runtime,root/'dispatch')
                with self.assertRaises(TimeoutError): controller.report_and_rotate(snapshot,callback,required_ids=['intent'])
                plan=peer.state()['pending'];self.assertIsNotNone(plan)
            with Client(RUST,root/'XNET',sha256=pin(RUST)) as runtime:
                peer=ContextPeer(runtime,task_id='deepseek-lite-fixture',peer='peer')
                controller=OroborosSession(root/'dispatch',peer,model_sha256=MODEL,runner_sha256=RUNNER,window=1000,reserve=100)
                self.assertEqual(peer.state()['pending'],plan)
                with self.assertRaises(PendingHandoff): controller.report_and_rotate(snapshot,callback,required_ids=['intent'])
                self.assertEqual(callback.call_count,1)
                controller.reconcile(plan['plan_id'],reply(plan))
                receipts=runtime.call('health')['receipt_count']
                controller.deliver(plan,callback)
                self.assertEqual(runtime.call('health')['receipt_count'],receipts)
                self.assertEqual(callback.call_count,1)

    def test_saved_callback_reply_is_reused_after_ack_transport_outage(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            peer,controller,snapshot=self.setup_case(runtime,Path(tmp)/'dispatch')
            callback=Mock(side_effect=reply)
            with patch.object(peer,'acknowledge',side_effect=ConnectionError('ack response unavailable')):
                with self.assertRaises(ConnectionError): controller.report_and_rotate(snapshot,callback,required_ids=['intent'])
            plan=peer.state()['pending'];self.assertEqual(callback.call_count,1)
            self.assertEqual(controller.deliver(plan,callback)['status'],'acknowledged')
            self.assertEqual(callback.call_count,1)

    def test_lost_ack_response_after_native_commit_recovers_automatically(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            peer,controller,snapshot=self.setup_case(runtime,Path(tmp)/'dispatch')
            callback=Mock(side_effect=reply);native_ack=peer.acknowledge
            def commit_then_lose_response(**fields):
                native_ack(**fields)
                raise ConnectionError('native ACK committed; response lost')
            with patch.object(peer,'acknowledge',side_effect=commit_then_lose_response):
                with self.assertRaises(ConnectionError): controller.report_and_rotate(snapshot,callback,required_ids=['intent'])
            self.assertIsNone(peer.state()['pending'])
            receipts=runtime.call('health')['receipt_count']
            self.assertEqual(controller.report_and_rotate(snapshot,callback,required_ids=['intent'])['status'],'acknowledged')
            self.assertEqual(runtime.call('health')['receipt_count'],receipts)
            self.assertEqual(callback.call_count,1)

    def test_rejected_reply_is_preserved_and_never_reopens_a_session(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            peer,controller,snapshot=self.setup_case(runtime,Path(tmp)/'dispatch')
            callback=Mock(side_effect=lambda plan:{**reply(plan),'model_sha256':'c'*64})
            with self.assertRaises(ValueError): controller.report_and_rotate(snapshot,callback,required_ids=['intent'])
            plan=peer.state()['pending']
            self.assertTrue((controller._directory(plan['plan_id'])/'reply.json').is_file())
            with self.assertRaises(ValueError): controller.deliver(plan,callback)
            self.assertEqual(callback.call_count,1)
            self.assertEqual(peer.state()['session']['session_id'],'old-1')

    def test_config_identity_and_wrong_pending_snapshot_refuse_before_callback(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            peer,controller,snapshot=self.setup_case(runtime,Path(tmp)/'dispatch')
            with self.assertRaises(ValueError): OroborosSession(controller.root,peer,model_sha256='c'*64,runner_sha256=RUNNER,window=1000,reserve=100)
            peer.occupancy(**snapshot)
            peer.prepare('old-1',required_ids=['intent'])
            callback=Mock(side_effect=reply)
            with self.assertRaises(PendingHandoff): controller.report_and_rotate({**snapshot,'used':200},callback,required_ids=['intent'])
            self.assertEqual(callback.call_count,0)

    def test_forged_packet_cannot_reach_caller(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            peer,controller,snapshot=self.setup_case(runtime,Path(tmp)/'dispatch')
            peer.occupancy(**snapshot);plan=peer.prepare('old-1',required_ids=['intent'])
            forged=copy.deepcopy(plan);forged['capsule']['pack']['records'][0]['text']='invented source'
            callback=Mock(side_effect=reply)
            with self.assertRaises(ValueError): controller.deliver(forged,callback)
            self.assertEqual(callback.call_count,0)

    def test_complete_identity_refuses_adapter_drift_before_reporting_or_callback(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            root=Path(tmp);identity,model,server,dll,adapter=fixture_identity(root/'artifacts',runtime)
            peer=ContextPeer(runtime,task_id='identity-fixture',peer='peer')
            peer.append('intent','Use the frozen caller adapter')
            controller=OroborosSession(root/'dispatch',peer,model_sha256=MODEL,runner_sha256=pin(server),
                window=1000,reserve=100,run_identity=identity,model_id=model)
            controller.bind('old-1');callback=Mock()
            adapter.write_bytes(b'# changed adapter\n')
            snapshot={'session_id':'old-1','revision':1,'used':850,'prompt_sha256':sha256(b'fixture')}
            with self.assertRaisesRegex(ValueError,'artifact changed'):
                controller.report_and_rotate(snapshot,callback,required_ids=['intent'])
            self.assertEqual(callback.call_count,0)
            self.assertIsNone(peer.state()['session']['used'])
            self.assertIsNone(peer.state()['pending'])

    def test_dll_drift_after_callback_preserves_reply_without_repeat(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            root=Path(tmp);identity,model,server,dll,adapter=fixture_identity(root/'artifacts',runtime)
            runner=pin(server);original=dll.read_bytes()
            peer=ContextPeer(runtime,task_id='identity-fixture',peer='peer');peer.append('intent','Exact context')
            controller=OroborosSession(root/'dispatch',peer,model_sha256=MODEL,runner_sha256=runner,
                window=1000,reserve=100,run_identity=identity,model_id=model)
            controller.bind('old-1')
            def actual_reply(plan):
                dll.write_bytes(b'changed implementation')
                return {**reply(plan),'runner_sha256':runner}
            callback=Mock(side_effect=actual_reply)
            snapshot={'session_id':'old-1','revision':1,'used':850,'prompt_sha256':sha256(b'fixture')}
            with self.assertRaisesRegex(ValueError,'artifact changed'):
                controller.report_and_rotate(snapshot,callback,required_ids=['intent'])
            plan=peer.state()['pending']
            self.assertTrue((controller._directory(plan['plan_id'])/'reply.json').is_file())
            with self.assertRaisesRegex(ValueError,'artifact changed'): controller.deliver(plan,callback)
            self.assertEqual(callback.call_count,1)
            dll.write_bytes(original)
            self.assertEqual(controller.deliver(plan,callback)['status'],'acknowledged')
            self.assertEqual(callback.call_count,1)

    def test_settings_resume_identity_is_exact_and_caller_dictionary_is_copied(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            root=Path(tmp);identity,model,server,dll,adapter=fixture_identity(root/'artifacts',runtime)
            peer=ContextPeer(runtime,task_id='identity-fixture',peer='peer')
            settings=dict(model_sha256=MODEL,runner_sha256=pin(server),window=1000,reserve=100,model_id=model)
            controller=OroborosSession(root/'dispatch',peer,run_identity=identity,**settings)
            identity['models'][model]['decoding']['temperature']=0.9
            self.assertEqual(controller.config['run_identity']['models'][model]['decoding']['temperature'],0.1)
            with self.assertRaisesRegex(ValueError,'resume identity changed'):
                OroborosSession(root/'dispatch',peer,run_identity=identity,**settings)

    def test_predictive_ring_forecasts_from_absolute_samples_without_preparing_rotation(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            peer,controller,snapshot=self.setup_case(runtime,Path(tmp)/'dispatch')
            first={**snapshot,'used':400}
            peer.occupancy(**first)
            before=peer.state()
            with patch.object(peer,'prepare',side_effect=AssertionError('prediction prepared a transition')):
                observation=controller.predictive_ring(first,observation_id='measurement-1',
                    observed_at_seconds=10,required_ids=['intent','fabric'])
            self.assertIsNone(observation['forecast']['to_run']['seconds'])
            self.assertEqual(peer.state(),before)
            self.assertFalse(observation['native_transition_prepared'])
            second={**first,'revision':2,'used':600,'prompt_sha256':sha256(b'second absolute prompt')}
            peer.occupancy(**second)
            before=peer.state()
            with patch.object(peer,'prepare',side_effect=AssertionError('prediction prepared a transition')):
                next_observation=controller.predictive_ring(second,observation_id='measurement-2',
                    observed_at_seconds=20,required_ids=['intent','fabric'])
            forecast=next_observation['forecast']
            self.assertEqual(forecast['tokens_per_second'],20)
            self.assertEqual(forecast['tokens_per_observation'],200)
            self.assertEqual(forecast['to_run'],{'remaining_tokens':200,'seconds':10,'observations':1})
            self.assertEqual(forecast['to_output_reserve_limit']['remaining_tokens'],300)
            self.assertEqual(forecast['safe_headroom_tokens'],200)
            self.assertFalse(forecast['measured_run_due'])
            self.assertEqual(peer.state(),before)
            self.assertEqual(next_observation['previous_receipt_sha256'],observation['receipt_sha256'])
            packet=next_observation['preview_capsule']
            envelopes=[json.loads(record['text']) for record in packet['pack']['records']]
            self.assertEqual([event['event_id'] for event in envelopes],['intent','fabric'])
            self.assertEqual([event['text'] for event in envelopes],['Keep the exact API','Context passes data only'])
            self.assertTrue(all(event['task_id']==peer.task_id for event in envelopes))
            self.assertEqual(packet['authority'],'none')
            self.assertTrue(runtime.call('verify')['ok'])

    def test_predictive_ring_duplicate_revision_clock_and_snapshot_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            peer,controller,snapshot=self.setup_case(runtime,Path(tmp)/'dispatch')
            first={**snapshot,'used':450};peer.occupancy(**first)
            controller.predictive_ring(first,observation_id='unique-1',observed_at_seconds=10,required_ids=['intent'])
            for changed,identity,when in ((first,'unique-1',11),(first,'unique-2',11),
                    ({**first,'used':451},'unique-3',12)):
                with self.subTest(identity=identity),self.assertRaises(ValueError):
                    controller.predictive_ring(changed,observation_id=identity,
                        observed_at_seconds=when,required_ids=['intent'])
            second={**first,'revision':2,'used':500};peer.occupancy(**second)
            for when in (10,9,float('nan')):
                with self.subTest(time=when),self.assertRaises(ValueError):
                    controller.predictive_ring(second,observation_id='unique-4',
                        observed_at_seconds=when,required_ids=['intent'])
            self.assertEqual(len(list((controller.root/'predictive-ring/observations').glob('*.json'))),1)
            self.assertIsNone(peer.state()['pending'])

    def test_predictive_ring_prefetch_rejects_foreign_history_bad_hash_and_byte_overflow(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            peer,controller,snapshot=self.setup_case(runtime,Path(tmp)/'dispatch')
            first={**snapshot,'used':450};peer.occupancy(**first)
            before=peer.state()
            history=peer.history()
            with patch.object(peer,'history',return_value={**history,'task_id':'another-task'}):
                with self.assertRaisesRegex(ValueError,'cross-task'):
                    controller.predictive_ring(first,observation_id='foreign',observed_at_seconds=10,required_ids=['intent'])
            with patch.object(peer,'fetch_event',return_value='changed original bytes'):
                with self.assertRaisesRegex(ValueError,'raw source changed'):
                    controller.predictive_ring(first,observation_id='bad-hash',observed_at_seconds=10,required_ids=['intent'])
            with self.assertRaises(ValueError):
                controller.predictive_ring(first,observation_id='missing',observed_at_seconds=10,required_ids=['unknown'])
            peer.append('large','x'*9000)
            before=peer.state()
            with self.assertRaisesRegex(ValueError,'byte budget'):
                controller.predictive_ring(first,observation_id='overflow',observed_at_seconds=10,
                                          required_ids=['large'],max_bytes=8192)
            self.assertEqual(peer.state(),before)
            self.assertEqual(len(list((controller.root/'predictive-ring/observations').glob('*.json'))),0)

    def test_predictive_ring_has_eight_sample_history_and_unknown_forecast_after_decrease(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            peer,controller,snapshot=self.setup_case(runtime,Path(tmp)/'dispatch')
            last=None
            for revision in range(1,10):
                used=100 if revision==1 else 600+revision*10
                measured={**snapshot,'revision':revision,'used':used,
                          'prompt_sha256':sha256(canonical({'revision':revision,'used':used}))}
                peer.occupancy(**measured)
                last=controller.predictive_ring(measured,observation_id='observation-'+str(revision),
                    observed_at_seconds=revision*10,required_ids=['intent'])
            self.assertEqual(last['forecast']['recent_observations'],8)
            self.assertEqual(last['forecast']['tokens_per_observation'],10)
            self.assertEqual(last['forecast']['tokens_per_second'],1)
            decreased={**measured,'revision':10,'used':650,'prompt_sha256':sha256(b'actual smaller prompt')}
            peer.occupancy(**decreased)
            unknown=controller.predictive_ring(decreased,observation_id='actual-decrease',
                observed_at_seconds=100,required_ids=['intent'])
            self.assertEqual(unknown['forecast']['trend'],'decreased-or-flat')
            self.assertIsNone(unknown['forecast']['to_run']['seconds'])
            self.assertIsNone(unknown['forecast']['to_run']['observations'])
            self.assertEqual(len(list((controller.root/'predictive-ring/observations').glob('*.json'))),10)
            self.assertEqual(_read(controller.root/'predictive-ring/observations/000009.json'),unknown)

    def test_predictive_ring_state_drift_pending_and_actual_run_rotation_remain_separate(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            peer,controller,snapshot=self.setup_case(runtime,Path(tmp)/'dispatch')
            low={**snapshot,'used':600};peer.occupancy(**low)
            real_fetch=peer.fetch_event
            def fetch_then_append(event):
                text=real_fetch(event)
                peer.append('changed-history','new task-bound raw note')
                return text
            with patch.object(peer,'fetch_event',side_effect=fetch_then_append):
                with self.assertRaisesRegex(ValueError,'snapshot/history drift'):
                    controller.predictive_ring(low,observation_id='drift',observed_at_seconds=10,required_ids=['intent'])
            self.assertFalse(list((controller.root/'predictive-ring/observations').glob('*.json')))
            controller.predictive_ring(low,observation_id='stable',observed_at_seconds=10,required_ids=['intent'])
            callback=Mock(side_effect=reply)
            self.assertEqual(controller.report_and_rotate(low,callback,required_ids=['intent'])['status'],'not-due')
            self.assertEqual(callback.call_count,0)
            run={**snapshot,'revision':2};peer.occupancy(**run)
            plan=peer.prepare(run['session_id'],required_ids=['intent'])
            with self.assertRaises(PendingHandoff):
                controller.predictive_ring(run,observation_id='pending',observed_at_seconds=20,required_ids=['intent'])
            self.assertEqual(controller.deliver(plan,callback)['status'],'acknowledged')
            self.assertEqual(callback.call_count,1)

if __name__=='__main__': unittest.main()
