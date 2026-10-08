"""No model calls. Trusted references exercise the bounded worker and durable loop."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from xnet.repair_loop import (RepairLoop, PendingAttempt, pilot_battery, is_noop_patch, _read,
                              validate_run_identity, verify_run_identity_artifacts, _artifact_sha256)
from xnet.protocol import canonical, digest, sha256
from xnet.swe_repair_evaluator import repair_capability_contract

MODELS = {'ds-lite':{'model_sha256':'a'*64,'runner_sha256':sha256(b'inert launcher')},
          'qw35b':{'model_sha256':'c'*64,'runner_sha256':sha256(b'inert launcher')}}

def output(request, files):
    return {'model_id':request['model_id'],'model_sha256':request['model_sha256'],
            'text':json.dumps({'files':files}), 'usage':{'output_tokens':30}}

class RepairLoopTests(unittest.TestCase):
    @staticmethod
    def run_identity(directory, *, native=False):
        def artifact(name, body):
            path=Path(directory)/name;path.write_bytes(body)
            return {'path':str(path.absolute()),'sha256':sha256(body)}
        result={'schema':'xnet.repair-run-identity.v1',
                'adapter':artifact('caller_adapter.py',b'# inert caller fixture\n'),
                'runner':{'source_revision':'fixture-server-v1','artifacts':[
                    artifact('llama-server.exe',b'inert launcher'),
                    artifact('llama-server-impl.dll',b'inert implementation')]},
                'models':{'ds-lite':{'decoding':{'temperature':0.0,'seed':7,'max_tokens':650,'stop':['END']},
                    'transport':{'protocol':'fixture-only','timeout_seconds':30},
                    'tokenizer':{'id':'declared-embedded-tokenizer','sha256':None},
                    'template':{'id':'declared-chat-template','sha256':'e'*64}}},'native':None}
        if native:
            result['native']={'binary':artifact('xnet.exe',b'inert gateway'), 'sdk_artifacts':[
                artifact('sdk.py',b'# inert SDK\n'),artifact('sdk_helpers.py',b'# inert SDK helper\n')]}
        return result

    @staticmethod
    def source_drift_read(original, *, enabled=lambda: True):
        def read(path):
            data = original(path)
            if enabled() and path.name == 'swe_repair_evaluator.py':
                return data + b'\n# fixture-only source identity drift\n'
            return data
        return read

    def test_ten_task_selftest_both_lanes_freeze_hidden_grade_and_resume(self):
        tasks, references=pilot_battery()
        requests=[]
        def generate(request):
            requests.append(copy.deepcopy(request))
            self.assertNotIn('hidden_cases',request['task'])
            self.assertNotIn('reference',json.dumps(request))
            self.assertTrue(request['contract'].endswith(repair_capability_contract()))
            return output(request,references[request['task']['task_id']])
        with tempfile.TemporaryDirectory() as tmp:
            loop=RepairLoop(Path(tmp)/'trial',tasks,MODELS,references)
            with self.assertRaises(FileNotFoundError): loop.grade()
            for model in MODELS: self.assertEqual(len(loop.run_lane(model,generate)),10)
            self.assertEqual(len(requests),20)
            frozen=loop.freeze();score=loop.grade()
            self.assertEqual(len(frozen['choices']),20)
            self.assertTrue(all(row['hidden_resolved'] for row in score['scores']))
            resumed=RepairLoop(Path(tmp)/'trial',tasks,MODELS,references)
            self.assertEqual(resumed.freeze(),frozen)
            with self.assertRaises(ValueError): resumed.run_lane('ds-lite',generate)
            self.assertEqual(len(requests),20)

    def test_noop_retry_and_receipt_outage_preserve_complete_attempt_then_mirror(self):
        tasks,refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        bad_cas=Mock();bad_cas.seal.side_effect=RuntimeError('receipt service offline')
        requests=[]
        def generate(request):
            requests.append(request)
            if request['attempt']==1: return output(request,request['base_files'])
            self.assertIn('PATCH_WAS_A_NO_OP',request['public_feedback']['host_reason'])
            return output(request,refs[request['task']['task_id']])
        with tempfile.TemporaryDirectory() as tmp:
            loop=RepairLoop(Path(tmp)/'trial',tasks,{'ds-lite':MODELS['ds-lite']},refs,cas=bad_cas)
            rows=loop.run_lane('ds-lite',generate)
            self.assertEqual(len(rows),2);self.assertTrue(rows[0]['no_op'])
            self.assertFalse(rows[0]['candidate_valid']);self.assertTrue(rows[1]['public_evaluation']['resolved'])
            directory=loop._case('ds-lite',tasks[0]['task_id'],2)
            self.assertEqual(_read(directory/'mirror.json')['status'],'pending')
            self.assertEqual(_read(directory/'result.json')['output_record']['output']['usage'],{'output_tokens':30})
            chunks=[]
            class CAS:
                def seal(self,text):
                    chunks.append(text);return {'digest':sha256(text.encode('utf-8')),'bytes':len(text.encode('utf-8'))}
            loop.cas=CAS();loop.mirror_pending()
            self.assertEqual(_read(directory/'mirror.json')['status'],'sealed')
            self.assertIn(rows[1]['output_record']['output']['text'],[json.loads(text)['output_record']['output']['text'] for text in chunks])

    def test_pending_generation_cannot_repeat_and_reconciles_without_a_model_call(self):
        tasks,refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        generate=Mock(side_effect=TimeoutError('transport state uncertain'))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'trial';loop=RepairLoop(root,tasks,{'ds-lite':MODELS['ds-lite']},refs)
            with self.assertRaises(TimeoutError): loop.run_lane('ds-lite',generate)
            resumed=RepairLoop(root,tasks,{'ds-lite':MODELS['ds-lite']},refs)
            with self.assertRaises(PendingAttempt): resumed.run_lane('ds-lite',generate)
            self.assertEqual(generate.call_count,1)
            request=_read(resumed._case('ds-lite',tasks[0]['task_id'],1)/'reservation.json')
            with self.assertRaises(ValueError): resumed.reconcile('ds-lite',tasks[0]['task_id'],1,'wrong',output(request,refs[tasks[0]['task_id']]))
            resumed.reconcile('ds-lite',tasks[0]['task_id'],1,request['nonce'],output(request,refs[tasks[0]['task_id']]))
            self.assertTrue(resumed.run_lane('ds-lite',generate)[0]['public_evaluation']['resolved'])
            self.assertEqual(generate.call_count,1)

    def test_resume_rejects_changed_identity_and_tampered_completed_attempt(self):
        tasks,refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'trial';loop=RepairLoop(root,tasks,{'ds-lite':MODELS['ds-lite']},refs)
            changed=copy.deepcopy(MODELS['ds-lite']);changed['model_sha256']='d'*64
            with self.assertRaises(ValueError): RepairLoop(root,tasks,{'ds-lite':changed},refs)
            loop.run_lane('ds-lite',lambda request:output(request,refs[tasks[0]['task_id']]))
            path=loop._case('ds-lite',tasks[0]['task_id'],1)/'result.json'
            path.write_bytes(path.read_bytes().replace(b'"candidate_valid":true',b'"candidate_valid":false'))
            with self.assertRaises(ValueError): loop.freeze()

    def test_enum_mismatch_and_candidate_host_import_are_failed_not_executed(self):
        tasks,refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        with tempfile.TemporaryDirectory() as tmp:
            loop=RepairLoop(Path(tmp)/'trial',tasks,{'ds-lite':MODELS['ds-lite']},refs)
            def generate(request):
                if request['attempt']==1:
                    result=output(request,refs[tasks[0]['task_id']]);result['model_id']='hallucinated-model';return result
                return output(request,{'helpers.py':'import os\ndef usage_charge(a,b,c,d):\n    return 0\n'})
            rows=loop.run_lane('ds-lite',generate)
            self.assertTrue(all(not row['candidate_valid'] for row in rows))
            self.assertIn('enum',rows[0]['public_evaluation']['error'])
            self.assertEqual(rows[1]['public_evaluation']['status'],'rejected')
            self.assertTrue(all(row['candidate_execution'] is False for row in rows))

    def test_reference_gate_rejects_invalid_battery_before_generation(self):
        tasks,refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:tasks[0]['files']}
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            RepairLoop(Path(tmp)/'trial',tasks,{'ds-lite':MODELS['ds-lite']},refs)

    def test_timeout_report_is_failure_and_receives_public_retry_feedback(self):
        tasks,refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        from xnet import repair_loop as module
        actual=module.evaluate_bundle
        calls=[]
        with tempfile.TemporaryDirectory() as tmp:
            loop=RepairLoop(Path(tmp)/'trial',tasks,{'ds-lite':MODELS['ds-lite']},refs)
            def evaluate(*args,**kwargs):
                if not calls:
                    calls.append(True)
                    return {'schema_version':'xnet.swe-repair-evaluation.v1','visibility':'public','status':'timed-out',
                            'resolved':False,'passed':0,'total':2,'cases':[],'error':'fixed evaluator timeout'}
                return actual(*args,**kwargs)
            def generate(request):
                if request['attempt']==2: self.assertEqual(request['public_feedback']['status'],'timed-out')
                return output(request,refs[tasks[0]['task_id']])
            with patch.object(module,'evaluate_bundle',side_effect=evaluate): rows=loop.run_lane('ds-lite',generate)
            self.assertFalse(rows[0]['public_evaluation']['resolved']);self.assertTrue(rows[1]['public_evaluation']['resolved'])

    def test_noop_ast_comparison_does_not_merge_whitespace_inside_strings(self):
        self.assertTrue(is_noop_patch({'a.py':'def f():\n return 1\n'}, {'a.py':'# format\ndef f():\n    return 1\n'}))
        self.assertFalse(is_noop_patch({'a.py':'def f():\n return "a  b"\n'}, {'a.py':'def f():\n return "a b"\n'}))

    def test_actual_infinite_loop_is_bounded_and_retry_keeps_prior_patch(self):
        tasks,refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        infinite='def usage_charge(units, limit, base_rate, excess_rate):\n    while True:\n        units += 1\n'
        def generate(request):
            if request['attempt']==1: return output(request,{'helpers.py':infinite})
            self.assertFalse(request['public_feedback']['resolved'])
            return output(request,refs[tasks[0]['task_id']])
        with tempfile.TemporaryDirectory() as tmp:
            loop=RepairLoop(Path(tmp)/'trial',tasks,{'ds-lite':MODELS['ds-lite']},refs,eval_timeout=1)
            rows=loop.run_lane('ds-lite',generate)
            self.assertFalse(rows[0]['public_evaluation']['resolved'])
            self.assertTrue(rows[1]['public_evaluation']['resolved'])
            self.assertTrue(all(row['candidate_execution'] is False for row in rows))

    def test_source_drift_before_generation_rejects_without_callback_or_reservation(self):
        tasks, refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        generate=Mock()
        with tempfile.TemporaryDirectory() as tmp:
            loop=RepairLoop(Path(tmp)/'trial',tasks,{'ds-lite':MODELS['ds-lite']},refs)
            manifest=(loop.root/'manifest.json').read_bytes()
            with patch.object(Path,'read_bytes',self.source_drift_read(Path.read_bytes)):
                with self.assertRaisesRegex(ValueError,'source identity changed.*new run root'):
                    loop.run_lane('ds-lite',generate)
            generate.assert_not_called()
            self.assertFalse((loop._case('ds-lite',tasks[0]['task_id'],1)/'reservation.json').exists())
            self.assertEqual((loop.root/'manifest.json').read_bytes(),manifest)

    def test_source_drift_after_callback_keeps_returned_output_and_refuses_evaluation(self):
        tasks, refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        drift=[False];requests=[]
        def generate(request):
            requests.append(request);drift[0]=True
            return output(request,refs[tasks[0]['task_id']])
        with tempfile.TemporaryDirectory() as tmp:
            loop=RepairLoop(Path(tmp)/'trial',tasks,{'ds-lite':MODELS['ds-lite']},refs)
            directory=loop._case('ds-lite',tasks[0]['task_id'],1)
            with patch.object(Path,'read_bytes',self.source_drift_read(Path.read_bytes,enabled=lambda:drift[0])), \
                 patch('xnet.repair_loop.evaluate_bundle') as evaluate:
                with self.assertRaisesRegex(ValueError,'source identity changed'):
                    loop.run_lane('ds-lite',generate)
                evaluate.assert_not_called()
                self.assertEqual(_read(directory/'output.json')['output'],output(requests[0],refs[tasks[0]['task_id']]))
                self.assertFalse((directory/'result.json').exists())
                with self.assertRaisesRegex(ValueError,'source identity changed'):
                    loop.run_lane('ds-lite',generate)
            self.assertEqual(len(requests),1)
            # Restoring the exact pinned bytes permits finishing saved evidence,
            # without another inference or rewriting the frozen run identity.
            never_generate=Mock(side_effect=AssertionError('saved output must be reused'))
            rows=loop.run_lane('ds-lite',never_generate)
            never_generate.assert_not_called()
            self.assertTrue(rows[0]['public_evaluation']['resolved'])

    def test_source_drift_refuses_freeze_and_heldout_grade_preserving_frozen_choices(self):
        tasks, refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        with tempfile.TemporaryDirectory() as tmp:
            loop=RepairLoop(Path(tmp)/'trial',tasks,{'ds-lite':MODELS['ds-lite']},refs)
            loop.run_lane('ds-lite',lambda request:output(request,refs[tasks[0]['task_id']]))
            with patch.object(Path,'read_bytes',self.source_drift_read(Path.read_bytes)):
                with self.assertRaisesRegex(ValueError,'source identity changed'): loop.freeze()
                self.assertFalse((loop.root/'choices.json').exists())
            loop.freeze();frozen=(loop.root/'choices.json').read_bytes()
            with patch.object(Path,'read_bytes',self.source_drift_read(Path.read_bytes)), \
                 patch('xnet.repair_loop.evaluate_bundle') as evaluate:
                with self.assertRaisesRegex(ValueError,'source identity changed'): loop.grade()
                with self.assertRaisesRegex(ValueError,'source identity changed'): loop.freeze()
                evaluate.assert_not_called()
                self.assertFalse((loop.root/'score.json').exists())
            self.assertEqual((loop.root/'choices.json').read_bytes(),frozen)

    def test_source_drift_refuses_reconciliation_without_changing_reservation(self):
        tasks, refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        generate=Mock(side_effect=TimeoutError('uncertain callback'))
        with tempfile.TemporaryDirectory() as tmp:
            loop=RepairLoop(Path(tmp)/'trial',tasks,{'ds-lite':MODELS['ds-lite']},refs)
            with self.assertRaises(TimeoutError): loop.run_lane('ds-lite',generate)
            directory=loop._case('ds-lite',tasks[0]['task_id'],1)
            saved=(directory/'reservation.json').read_bytes();request=_read(directory/'reservation.json')
            with patch.object(Path,'read_bytes',self.source_drift_read(Path.read_bytes)):
                with self.assertRaisesRegex(ValueError,'source identity changed'):
                    loop.reconcile('ds-lite',tasks[0]['task_id'],1,request['nonce'],output(request,refs[tasks[0]['task_id']]))
            self.assertEqual((directory/'reservation.json').read_bytes(),saved)
            self.assertFalse((directory/'output.json').exists());self.assertEqual(generate.call_count,1)

    def test_run_identity_binds_manifest_requests_and_resumes_canonically(self):
        tasks, refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        with tempfile.TemporaryDirectory() as tmp:
            identity=self.run_identity(tmp);original=copy.deepcopy(identity)
            loop=RepairLoop(Path(tmp)/'trial',tasks,{'ds-lite':MODELS['ds-lite']},refs,run_identity=identity)
            expected=validate_run_identity(original,{'ds-lite':MODELS['ds-lite']})
            self.assertEqual(loop.manifest['config']['run_identity'],expected)
            self.assertEqual(loop.manifest['config']['run_identity_sha256'],digest(expected))
            # The caller's original object and callback request cannot mutate the frozen declaration.
            identity['models']['ds-lite']['decoding']['temperature']=0.9
            seen=[]
            def generate(request):
                seen.append(copy.deepcopy(request))
                request['run_identity']['models']['ds-lite']['transport']['timeout_seconds']=1
                return output(request,refs[tasks[0]['task_id']])
            rows=loop.run_lane('ds-lite',generate)
            self.assertEqual(seen[0]['run_identity'],expected)
            self.assertEqual(seen[0]['run_identity_sha256'],digest(expected))
            self.assertEqual(rows[0]['request']['run_identity'],expected)
            self.assertEqual(set(rows[0]['output_record']['output']),{'model_id','model_sha256','text','usage'})
            # Canonical identity bytes are exact even when Python equates 0 and 0.0.
            changed_request=copy.deepcopy(rows[0]['request'])
            changed_request['run_identity']['models']['ds-lite']['decoding']['temperature']=0
            with self.assertRaisesRegex(ValueError,'reservation run identity changed'):
                loop._finish(loop._case('ds-lite',tasks[0]['task_id'],1),changed_request,rows[0]['output_record'])
            original['runner']['artifacts'].reverse()
            resumed=RepairLoop(loop.root,tasks,{'ds-lite':MODELS['ds-lite']},refs,run_identity=original)
            self.assertEqual(resumed.manifest,loop.manifest)
            never_generate=Mock();self.assertEqual(resumed.run_lane('ds-lite',never_generate),rows)
            never_generate.assert_not_called()

    def test_run_identity_settings_and_pins_change_require_new_root(self):
        tasks, refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        with tempfile.TemporaryDirectory() as tmp:
            identity=self.run_identity(tmp)
            loop=RepairLoop(Path(tmp)/'trial',tasks,{'ds-lite':MODELS['ds-lite']},refs,run_identity=identity)
            manifest=(loop.root/'manifest.json').read_bytes()
            changes=[('decoding','temperature',0.5),('transport','timeout_seconds',99),
                     ('tokenizer','id','other-tokenizer'),('template','sha256','f'*64)]
            for section,key,new in changes:
                changed=copy.deepcopy(identity);changed['models']['ds-lite'][section][key]=new
                with self.subTest(section=section), self.assertRaisesRegex(ValueError,'resume identity changed'):
                    RepairLoop(loop.root,tasks,{'ds-lite':MODELS['ds-lite']},refs,run_identity=changed)
            with self.assertRaisesRegex(ValueError,'resume identity changed'):
                RepairLoop(loop.root,tasks,{'ds-lite':MODELS['ds-lite']},refs)
            loop.run_identity['models']['ds-lite']['decoding']['temperature']=0.4
            generate=Mock()
            with self.assertRaisesRegex(ValueError,'run identity changed'): loop.run_lane('ds-lite',generate)
            generate.assert_not_called()
            self.assertFalse((loop.root/'attempts').exists())
            self.assertEqual((loop.root/'manifest.json').read_bytes(),manifest)

    def test_run_identity_rejects_malformed_constructor_before_creating_root(self):
        tasks, refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        with tempfile.TemporaryDirectory() as tmp:
            identity=self.run_identity(tmp);invalid=[]
            bad=copy.deepcopy(identity);bad['unexpected']=True;invalid.append(bad)
            bad=copy.deepcopy(identity);bad['adapter']['sha256']='A'*64;invalid.append(bad)
            bad=copy.deepcopy(identity);bad['adapter']['path']='relative.py';invalid.append(bad)
            bad=copy.deepcopy(identity);bad['adapter']['sha256']='f'*64;invalid.append(bad)
            bad=copy.deepcopy(identity);bad['runner']['artifacts']=[];invalid.append(bad)
            bad=copy.deepcopy(identity);bad['runner']['artifacts']=bad['runner']['artifacts'][1:];invalid.append(bad)
            bad=copy.deepcopy(identity);bad['runner']['artifacts']*=2;invalid.append(bad)
            bad=copy.deepcopy(identity);bad['runner']['source_revision']=' ';invalid.append(bad)
            bad=copy.deepcopy(identity);bad['models']['ds-lite']['decoding']['temperature']=float('nan');invalid.append(bad)
            bad=copy.deepcopy(identity);bad['models']['ds-lite']['transport']={'arbitrary':object()};invalid.append(bad)
            bad=copy.deepcopy(identity);bad['models']['ds-lite']['template']['id']='';invalid.append(bad)
            bad=copy.deepcopy(identity);bad['models']['other']=bad['models'].pop('ds-lite');invalid.append(bad)
            bad=copy.deepcopy(identity);bad['models']['ds-lite']['decoding']={1:'non-string key'};invalid.append(bad)
            for index,bad in enumerate(invalid):
                root=Path(tmp)/('invalid-'+str(index))
                with self.subTest(index=index), self.assertRaises(ValueError):
                    RepairLoop(root,tasks,{'ds-lite':MODELS['ds-lite']},refs,run_identity=bad)
                self.assertFalse(root.exists())
            with self.assertRaisesRegex(ValueError,'requires native artifacts'):
                RepairLoop(Path(tmp)/'invalid-cas',tasks,{'ds-lite':MODELS['ds-lite']},refs,
                           cas=object(),run_identity=identity)
            self.assertFalse((Path(tmp)/'invalid-cas').exists())

    def test_adapter_drift_before_dispatch_or_resume_never_calls_generator(self):
        tasks, refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        with tempfile.TemporaryDirectory() as tmp:
            identity=self.run_identity(tmp)
            loop=RepairLoop(Path(tmp)/'trial',tasks,{'ds-lite':MODELS['ds-lite']},refs,run_identity=identity)
            adapter=Path(identity['adapter']['path'])
            def drift(path):
                return 'f'*64 if path==adapter else _artifact_sha256(path)
            generate=Mock()
            with patch('xnet.repair_loop._artifact_sha256',side_effect=drift):
                with self.assertRaisesRegex(ValueError,'run identity artifact changed'):
                    loop.run_lane('ds-lite',generate)
                with self.assertRaisesRegex(ValueError,'run identity artifact changed'):
                    RepairLoop(loop.root,tasks,{'ds-lite':MODELS['ds-lite']},refs,run_identity=identity)
            generate.assert_not_called();self.assertFalse((loop.root/'attempts').exists())

    def test_runner_dll_drift_after_callback_preserves_complete_raw_output(self):
        tasks, refs=pilot_battery();tasks=tasks[:1];refs={tasks[0]['task_id']:refs[tasks[0]['task_id']]}
        with tempfile.TemporaryDirectory() as tmp:
            identity=self.run_identity(tmp)
            loop=RepairLoop(Path(tmp)/'trial',tasks,{'ds-lite':MODELS['ds-lite']},refs,run_identity=identity)
            dll=Path(identity['runner']['artifacts'][1]['path']);changed=[False]
            generated=[]
            def drift(path):
                return 'f'*64 if changed[0] and path==dll else _artifact_sha256(path)
            def generate(request):
                reply=output(request,refs[tasks[0]['task_id']])
                reply['text']=' \n'+reply['text']+'\n '
                reply['usage']['raw_transport_receipt']={'count':21,'opaque':'kept exactly'}
                generated.append(copy.deepcopy(reply));changed[0]=True
                return reply
            directory=loop._case('ds-lite',tasks[0]['task_id'],1)
            with patch('xnet.repair_loop._artifact_sha256',side_effect=drift), patch('xnet.repair_loop.evaluate_bundle') as evaluate:
                with self.assertRaisesRegex(ValueError,'run identity artifact changed'):
                    loop.run_lane('ds-lite',generate)
                evaluate.assert_not_called();self.assertFalse((directory/'result.json').exists())
                self.assertEqual(_read(directory/'output.json')['output'],generated[0])
                with self.assertRaisesRegex(ValueError,'run identity artifact changed'):
                    loop.run_lane('ds-lite',generate)
            self.assertEqual(len(generated),1)
            never_generate=Mock(side_effect=AssertionError('saved raw output must be reused'))
            rows=loop.run_lane('ds-lite',never_generate)
            never_generate.assert_not_called()
            self.assertTrue(rows[0]['public_evaluation']['resolved'])
            self.assertEqual(rows[0]['output_record']['output'],generated[0])

    def test_run_identity_native_binary_and_sdk_artifacts_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            identity=self.run_identity(tmp,native=True)
            class CAS:
                binary_sha256=identity['native']['binary']['sha256']
            cas=CAS();normalized=validate_run_identity(identity,{'ds-lite':MODELS['ds-lite']},cas=cas)
            cas.binary_sha256='0'*64
            with self.assertRaisesRegex(ValueError,'native binary differs'):
                verify_run_identity_artifacts(normalized,cas=cas)
            cas.binary_sha256=identity['native']['binary']['sha256']
            sdk=Path(identity['native']['sdk_artifacts'][1]['path'])
            def drift(path):
                return 'f'*64 if path==sdk else _artifact_sha256(path)
            with patch('xnet.repair_loop._artifact_sha256',side_effect=drift), self.assertRaisesRegex(ValueError,'artifact changed'):
                verify_run_identity_artifacts(normalized,cas=cas)
            bad=copy.deepcopy(identity);bad['native']['sdk_artifacts']=[]
            with self.assertRaises(ValueError): validate_run_identity(bad,{'ds-lite':MODELS['ds-lite']},cas=cas)

    def test_read_only_hardlinked_artifact_is_accepted_but_changed_bytes_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            identity=self.run_identity(tmp,native=True)
            binary=Path(identity['native']['binary']['path']);alias=Path(tmp)/'cargo-deps-xnet.exe'
            alias.hardlink_to(binary)
            self.assertGreater(binary.stat().st_nlink,1)
            normalized=validate_run_identity(identity,{'ds-lite':MODELS['ds-lite']})
            verify_run_identity_artifacts(normalized)
            alias.write_bytes(b'changed inert hardlinked executable')
            with self.assertRaisesRegex(ValueError,'artifact changed'):
                verify_run_identity_artifacts(normalized)

if __name__=='__main__': unittest.main()
