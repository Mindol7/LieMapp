"""Synthetic unit tests only: these are not SGLang experiment evidence."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import torch

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'LieMappBench').is_dir())
PATH=ROOT/'Instrumented-LIE/siai/SGLang/python/sglang/liemapp_observer.py'
spec=importlib.util.spec_from_file_location('sglang_observer_unit_test',PATH)
observer=importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class ObserverTests(unittest.TestCase):
    def test_missing_control_is_inactive(self):
        with patch.dict(os.environ,{},clear=True):
            self.assertIsNone(observer.matching(['request-a']))

    def test_only_exact_single_native_id_matches(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'control.json'
            path.write_text(json.dumps({'active':True,'context':{'request_id':'request-a'}}))
            with patch.dict(os.environ,{'LIEMAPP_CONTROL':str(path)}):
                self.assertEqual(observer.matching(['request-a']),{'request_id':'request-a'})
                for rids in ([],['warmup'],['request-a','request-b'],['request-b','request-a']):
                    self.assertIsNone(observer.matching(rids))

    def test_inactive_control_does_not_collect_warmup(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'control.json'
            path.write_text(json.dumps({'active':False,'context':{'request_id':'request-a'}}))
            with patch.dict(os.environ,{'LIEMAPP_CONTROL':str(path)}):
                self.assertIsNone(observer.matching(['request-a']))

    def test_array_is_lossless_independent_copy(self):
        tensor=torch.tensor([[0.1,-0.2],[3.125,0]],dtype=torch.float32)
        value=observer.array(tensor.t())
        self.assertTrue(np.array_equal(value,tensor.t().numpy()))
        self.assertTrue(value.flags.c_contiguous)
        tensor.zero_()
        self.assertNotEqual(float(value[0,0]),0)

    def test_reject_lossy_bfloat16(self):
        with self.assertRaises(RuntimeError):
            observer.array(torch.ones(1,dtype=torch.bfloat16))

    def test_overlay_does_not_mutate_weights(self):
        root=ROOT/'Instrumented-LIE/siai/SGLang/.model-cpu-one-tile'
        record=json.loads((root/'liemapp-provenance.json').read_text())
        config=json.loads((root/'preprocessor_config.json').read_text())
        self.assertFalse(config['do_image_splitting'])
        self.assertFalse(config['do_resize'])
        weights=next(v for v in record['files'] if v['name']=='model.safetensors')
        self.assertTrue((root/'model.safetensors').is_symlink())
        self.assertEqual(weights['source_sha256'],weights['variant_sha256'])


if __name__=='__main__':
    unittest.main()
