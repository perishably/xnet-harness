"""Optional repair context controls. Public fixtures and fake inference only."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from xnet.protocol import canonical, digest, sha256
from xnet.repair_loop import (RepairLoop, PendingPublicContext, pilot_battery,
                              _read, _save, _admit_public_context)


MODELS = {name:{'model_sha256':'a'*64,'runner_sha256':'b'*64} for name in ('lite-raw','lite-xnet')}


def text_record(kind, text, ordinal):
    return {'record_id':f'public-{ordinal}', 'kind':kind, 'text':text,
            'source_sha256':sha256(('source-'+str(ordinal)).encode()),
            'text_sha256':sha256(text.encode()), 'receipt_sha256':sha256(('receipt-'+str(ordinal)).encode())}


def packet(request, records):
    return {'schema':'xnet.repair-public-context.v1','task_id':request['task']['task_id'],
            'input_sha256':sha256(canonical({'task':request['task'],'public_feedback':request['public_feedback']})),
            'records':copy.deepcopy(records),'authority':'none','work_performed':False,
            'hidden_cases_used':False,'context_only':True}


def response(request, files):
    return {'model_id':request['model_id'],'model_sha256':request['model_sha256'],
            'text':json.dumps({'files':files}),'usage':{'input_tokens':10,'output_tokens':20}}


class RepairPublicContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        tasks, references = pilot_battery()
        self.tasks = tasks[:2]
        self.refs = {task['task_id']:references[task['task_id']] for task in self.tasks}
        self.records = [text_record(kind, 'Independent public note café 🧬\r\n'+kind, n)
                        for n, kind in enumerate(('bridge-source','rag-slice','frozen-fetch'))]
        source = Path(__file__).absolute()
        self.policy = {'schema':'xnet.repair-public-context-policy.v1','preparer_id':'public-notes-v1',
                       'preparer_artifacts':[{'path':str(source),'sha256':sha256(source.read_bytes())}],
                       'model_ids':['lite-xnet'],'max_bytes':2048,
                       'tasks':{task['task_id']:[{key:value for key,value in row.items() if key != 'text'} |
                                               {'classification':'public'} for row in self.records] for task in self.tasks}}

    def tearDown(self):
        self.tmp.cleanup()

    def loop(self, preparer, **kwargs):
        return RepairLoop(self.root/'trial',self.tasks,MODELS,self.refs,
                          context_preparer=preparer,public_context_policy=self.policy,**kwargs)

    def good_preparer(self, request):
        return packet(request,self.records)

    def generate(self, request):
        return response(request,self.refs[request['task']['task_id']])

    def test_public_context_preserves_complete_task_files_feedback_and_bytes(self):
        seen = []
        def preparer(request):
            seen.append(copy.deepcopy(request))
            self.assertNotIn('hidden_cases',request['task'])
            self.assertNotIn('reference',request)
            self.assertNotIn('public_context',request)
            return packet(request,self.records)
        loop = self.loop(preparer)
        generated = []
        def generate(request):
            generated.append(request)
            self.assertEqual(request['task'],seen[-1]['task'])
            self.assertEqual(request['base_files'],request['task']['files'])
            self.assertEqual(request['public_feedback'],seen[-1]['public_feedback'])
            self.assertEqual(request['contract'],seen[-1]['contract'])
            self.assertEqual((request['max_output_tokens'],request['max_attempts']),(650,2))
            context = request['public_context']
            self.assertEqual(context['records'],self.records)
            self.assertEqual(context['context_sha256'],digest({k:v for k,v in context.items() if k != 'context_sha256'}))
            return self.generate(request)
        rows = loop.run_lane('lite-xnet',generate,task_ids=[self.tasks[0]['task_id']])
        self.assertEqual((len(rows),len(seen),len(generated)),(1,1,1))
        self.assertIn('public_context',_read(loop._case('lite-xnet',self.tasks[0]['task_id'],1)/'result.json')['request'])

    def test_raw_lane_has_no_added_context_and_does_not_call_preparer(self):
        calls = []
        def preparer(request):
            calls.append(request)
            return packet(request,self.records)
        loop = self.loop(preparer)
        def generate(request):
            self.assertNotIn('public_context',request)
            return self.generate(request)
        self.assertEqual(len(loop.run_lane('lite-raw',generate,task_ids=[self.tasks[1]['task_id']])),1)
        self.assertEqual(calls,[])
        self.assertFalse((loop._case('lite-raw',self.tasks[1]['task_id'],1)/'public-context-started.json').exists())

    def test_legacy_default_and_exact_task_subset_keep_freeze_gate(self):
        loop = RepairLoop(self.root/'legacy',self.tasks,MODELS,self.refs)
        self.assertNotIn('public_context_policy',loop.manifest['config'])
        self.assertEqual(len(loop.run_lane('lite-raw',self.generate,task_ids=[self.tasks[1]['task_id']])),1)
        for ids in ([],['unknown'],[self.tasks[0]['task_id']]*2):
            with self.assertRaises(ValueError):
                loop.run_lane('lite-raw',self.generate,task_ids=ids)
        with self.assertRaises(ValueError):
            loop.freeze()
        self.assertEqual(len(loop.run_lane('lite-raw',self.generate)),2)

    def test_unknown_context_callback_is_once_and_can_only_reconcile(self):
        calls = []
        def preparer(request):
            calls.append(copy.deepcopy(request))
            raise TimeoutError('native context outcome unknown')
        loop = self.loop(preparer)
        generate = Mock()
        task = self.tasks[0]['task_id']
        with self.assertRaises(TimeoutError):
            loop.run_lane('lite-xnet',generate,task_ids=[task])
        with self.assertRaises(PendingPublicContext):
            loop.run_lane('lite-xnet',generate,task_ids=[task])
        self.assertEqual((len(calls),generate.call_count),(1,0))
        original = calls[0]
        with self.assertRaises(ValueError):
            loop.reconcile_public_context('lite-xnet',task,1,'wrong',packet(original,self.records))
        loop.reconcile_public_context('lite-xnet',task,1,original['nonce'],packet(original,self.records))
        self.assertEqual(len(loop.run_lane('lite-xnet',self.generate,task_ids=[task])),1)
        self.assertEqual(len(calls),1)

    def test_invalid_context_refuses_inference_and_retains_return_without_retry(self):
        calls = []
        def preparer(request):
            calls.append(request)
            result = packet(request,self.records)
            result['records'][0]['text'] = 'unapproved hidden payload'
            return result
        loop = self.loop(preparer)
        generate = Mock()
        task = self.tasks[0]['task_id']
        for _ in range(2):
            with self.assertRaises(ValueError):
                loop.run_lane('lite-xnet',generate,task_ids=[task])
        self.assertEqual((len(calls),generate.call_count),(1,0))
        directory = loop._case('lite-xnet',task,1)
        self.assertTrue((directory/'public-context-returned.json').exists())
        self.assertFalse((directory/'reservation.json').exists())

    def test_scope_authority_hidden_keys_wrong_task_receipt_and_missing_records_refused(self):
        loop = self.loop(self.good_preparer)
        request = loop._request('lite-xnet',self.tasks[0],1,None)
        good = packet(request,self.records)
        changes = []
        for key,value in (('authority','tools'),('task_id',self.tasks[1]['task_id']),('hidden_cases_used',True),
                          ('input_sha256','0'*64),('work_performed',True),('context_only',False)):
            bad = copy.deepcopy(good);bad[key]=value;changes.append(bad)
        bad=copy.deepcopy(good);bad['hidden_cases']=['not allowed'];changes.append(bad)
        bad=copy.deepcopy(good);bad['records'][0]['receipt_sha256']='0'*64;changes.append(bad)
        bad=copy.deepcopy(good);bad['records'][0]['source_sha256']='0'*64;changes.append(bad)
        bad=copy.deepcopy(good);bad['records']=bad['records'][:-1];changes.append(bad)
        bad=copy.deepcopy(good);bad['records'][0]['reference']='not allowed';changes.append(bad)
        for bad in changes:
            with self.assertRaises(ValueError):
                _admit_public_context(bad,request,loop.public_context_policy)

    def test_source_pin_policy_and_actual_callback_identity_are_frozen(self):
        loop = self.loop(self.good_preparer)
        loop.public_context_policy['max_bytes'] += 1
        with self.assertRaises(ValueError):
            loop.run_lane('lite-xnet',Mock())
        loop.public_context_policy = copy.deepcopy(loop.manifest['config']['public_context_policy'])
        def different(request):
            return packet(request,self.records)
        loop.context_preparer = different
        with self.assertRaisesRegex(ValueError,'callback identity'):
            loop.run_lane('lite-xnet',Mock())
        policy = copy.deepcopy(self.policy);policy['model_ids']=['unselected-model']
        with self.assertRaises(ValueError):
            RepairLoop(self.root/'bad',self.tasks,MODELS,self.refs,context_preparer=self.good_preparer,public_context_policy=policy)

    def test_preparer_artifact_change_is_rejected_before_dispatch(self):
        artifact = self.root/'public-helper.py';artifact.write_bytes(b'# public helper v1\n')
        self.policy['preparer_artifacts'].append({'path':str(artifact),'sha256':sha256(artifact.read_bytes())})
        loop = self.loop(self.good_preparer)
        artifact.write_bytes(b'# altered public helper\n')
        generate = Mock()
        with self.assertRaisesRegex(ValueError,'preparer source'):
            loop.run_lane('lite-xnet',generate)
        self.assertEqual(generate.call_count,0)

    def test_budget_overflow_refuses_unclipped_packet(self):
        self.policy['max_bytes']=128
        loop = self.loop(self.good_preparer)
        generate = Mock()
        with self.assertRaisesRegex(ValueError,'budget'):
            loop.run_lane('lite-xnet',generate,task_ids=[self.tasks[0]['task_id']])
        self.assertEqual(generate.call_count,0)

    def test_current_candidate_and_public_feedback_are_preserved_on_revision(self):
        loop = self.loop(self.good_preparer)
        task = self.tasks[0]
        requests=[]
        def generate(request):
            requests.append(request)
            return response(request,request['base_files'] if request['attempt']==1 else self.refs[task['task_id']])
        rows=loop.run_lane('lite-xnet',generate,task_ids=[task['task_id']])
        self.assertEqual(len(rows),2)
        self.assertIn('PATCH_WAS_A_NO_OP',requests[1]['public_feedback']['host_reason'])
        self.assertEqual(requests[1]['public_context']['input_sha256'],
                         sha256(canonical({'task':requests[1]['task'],'public_feedback':requests[1]['public_feedback']})))
        self.assertNotEqual(requests[0]['public_context']['input_sha256'],requests[1]['public_context']['input_sha256'])

    def test_raw_output_is_saved_before_post_generation_context_failure(self):
        loop=self.loop(self.good_preparer)
        task=self.tasks[0]['task_id']
        def generate(request):
            returned=loop._case('lite-xnet',task,1)/'public-context-returned.json'
            evidence=_read(returned);evidence['packet']['records'][0]['text']='changed after generation'
            _save(returned,{k:v for k,v in evidence.items() if k!='receipt_sha256'})
            return self.generate(request)
        with self.assertRaises(ValueError):
            loop.run_lane('lite-xnet',generate,task_ids=[task])
        output=_read(loop._case('lite-xnet',task,1)/'output.json')
        self.assertIn('text',output['output'])
        self.assertFalse((loop._case('lite-xnet',task,1)/'result.json').exists())


if __name__=='__main__':
    unittest.main()
