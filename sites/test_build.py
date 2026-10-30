import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('build', Path(__file__).with_name('build.py'))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)

class BuildTests(unittest.TestCase):
    def test_clean_bilingual_routes_raw_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / 'stale.html').write_text('stale')
            build.build(out)
            self.assertFalse((out / 'stale.html').exists())
            for lang in ('en', 'es'):
                for slug in build.PAGES:
                    self.assertTrue((out / lang / 'development' / slug / 'index.html').is_file())
                    self.assertTrue((out / lang / 'development' / 'raw' / (slug + '.md')).is_file())
            self.assertEqual(json.loads((out / 'catalog.json').read_text())['releases'], [])
            self.assertTrue((out / 'source-manifest.json').is_file())
            build.validate(out)

    def test_renderer_escapes_html_and_converts_local_links(self):
        rendered = build.render('# Title\n\n<script>alert(1)</script>\n\n[API](api.md)\n\n```json\n{"x":"<"}\n```')
        self.assertNotIn('<script>', rendered)
        self.assertIn('../api/', rendered)
        self.assertIn('&lt;', rendered)

    def test_stale_translation_rejected(self):
        old = build.ROOT
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'docs/agents').mkdir(parents=True)
            (root / 'docs/es').mkdir(parents=True)
            (root / 'docs/agents/index.md').write_text('changed')
            (root / 'docs/es/index.md').write_text('translated')
            (root / 'docs/es/manifest.json').write_text('{"sources":{"index.md":"incorrect"}}')
            build.ROOT = root
            try:
                with self.assertRaisesRegex(ValueError, 'translation'):
                    build.check_translations()
            finally:
                build.ROOT = old

class ContractTests(unittest.TestCase):
    def test_translation_preserves_all_code_fences(self):
        import re
        for slug in build.PAGES:
            canonical = (build.ROOT / 'docs/agents' / (slug + '.md')).read_text()
            translated = (build.ROOT / 'docs/es' / (slug + '.md')).read_text()
            self.assertEqual(re.findall(r'```.*?```', canonical, re.S), re.findall(r'```.*?```', translated, re.S), slug)

    def test_no_release_snapshot_substitution(self):
        import shutil
        old = build.ROOT
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'source'
            shutil.copytree(old / 'docs/agents', root / 'docs/agents')
            shutil.copytree(old / 'docs/es', root / 'docs/es')
            (root / 'sites').mkdir()
            (root / 'sites/catalog.json').write_text('{"releases":[{"version":"v1.0.0"}]}')
            build.ROOT = root
            try:
                with self.assertRaisesRegex(ValueError, 'historical release'):
                    build.build(Path(tmp) / 'output')
            finally:
                build.ROOT = old

    def test_missing_local_link_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'index.html').write_text('<a href="missing/">Broken</a>')
            with self.assertRaisesRegex(ValueError, 'broken link'):
                build.validate(root)

if __name__ == '__main__':
    unittest.main()
