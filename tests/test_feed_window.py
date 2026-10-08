import copy
from pathlib import Path
import tempfile
import unittest
from adapters.loopback.feed_window import PracticeFeedWindow
from adapters.loopback.stream_index import canonical,digest,sha256,source_descriptor,IndexErrorClosed


class FeedWindowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.archive=self.root/'archive';self.archive.mkdir()
        raw=b'@@ -1 +1 @@\n-old\n+new\n';(self.archive/'source.patch').write_bytes(raw)
        self.row=source_descriptor(scope_id='practice-stream-r01',task_id='practice',source_id='change',
            adapter='archive-d',relative_path='source.patch',repo='demo/repo',revision='a'*40,
            source_sha256=sha256(raw),source_bytes=len(raw),language='rust',task_family='public-code-change',
            tags=['partial-patch','rust'],provenance='practice-stream',upstream_receipt_sha256='c'*64)
        self.value={'schema':'xnet.public-code-feed.projection-set.v1','generation':'demo',
            'provenance_class':'practice-stream','authority':'none','upstream_ledger_head':'b'*64,
            'descriptors':[self.row]}
        self.path=self.root/'generation.json'

    def tearDown(self):self.temp.cleanup()
    def open(self,value=None):
        self.path.write_bytes(canonical(value or self.value))
        return PracticeFeedWindow(self.root/'index',generation_path=self.path,
            expected_generation_sha256=sha256(self.path.read_bytes()),expected_upstream_head='b'*64,
            archive_root=self.archive)
    def test_prewarms_then_returns_partial_source(self):
        with self.open() as window:
            before=window.context('rust',repo='demo/repo',revision='a'*40)
            self.assertEqual(before['rows'],[])
            window.prewarm('rust',repo='demo/repo',revision='a'*40)
            value=window.context('rust',repo='demo/repo',revision='a'*40)
            self.assertEqual(value['rows'][0]['text'],(self.archive/'source.patch').read_text())
            self.assertFalse(value['evaluation_admission']);self.assertFalse(value['promotion_authority'])
            self.assertIn('partial',value['source_kind']);self.assertEqual(value['remote_reads'],0)
    def test_generation_tamper_refused(self):
        self.path.write_bytes(canonical(self.value))
        with self.assertRaises(IndexErrorClosed):
            PracticeFeedWindow(self.root/'index',generation_path=self.path,
                expected_generation_sha256='d'*64,expected_upstream_head='b'*64,archive_root=self.archive)
    def test_head_mismatch_refused(self):
        value=copy.deepcopy(self.value);value['upstream_ledger_head']='e'*64
        with self.assertRaises(IndexErrorClosed):self.open(value)
    def test_authority_claim_refused(self):
        value=copy.deepcopy(self.value);value['authority']='execute'
        with self.assertRaises(IndexErrorClosed):self.open(value)
    def test_evaluation_data_refused(self):
        value=copy.deepcopy(self.value);value['descriptors'][0]['provenance']='evaluation-source'
        with self.assertRaises(IndexErrorClosed):self.open(value)
    def test_partial_tag_required(self):
        value=copy.deepcopy(self.value);value['descriptors'][0]['tags']=['rust']
        with self.assertRaises(IndexErrorClosed):self.open(value)
    def test_unknown_field_refused(self):
        value=copy.deepcopy(self.value);value['answer']='answer'
        with self.assertRaises(IndexErrorClosed):self.open(value)
    def test_drift_before_prefetch_refused(self):
        with self.open() as window:
            (self.archive/'source.patch').write_bytes(b'changed')
            with self.assertRaises(IndexErrorClosed):window.prewarm('rust',repo='demo/repo',revision='a'*40)
    def test_cancel_has_no_hot_admission(self):
        with self.open() as window:
            window.prewarm('rust',repo='demo/repo',revision='a'*40,cancelled=lambda:True)
            self.assertEqual(window.context('rust',repo='demo/repo',revision='a'*40)['rows'],[])
    def test_revision_miss_stays_miss(self):
        with self.open() as window:
            window.prewarm('rust',repo='demo/repo',revision='a'*40)
            self.assertEqual(window.context('rust',repo='demo/repo',revision='f'*40)['rows'],[])
