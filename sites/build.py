#!/usr/bin/env python3
"""Dependency-free, deterministic Development documentation renderer."""
import argparse
import hashlib
import html
import json
from pathlib import Path
import re
import shutil
from html.parser import HTMLParser
from urllib.parse import urlsplit, unquote

ROOT = Path(__file__).resolve().parents[1]
PAGES = ('index', 'quickstart', 'concepts', 'protocol', 'api', 'recipes', 'security', 'troubleshooting', 'migration', 'operations')
LABELS = {
'en': ('Overview', 'Quickstart', 'Concepts', 'Protocol', 'HTTP API', 'Recipes', 'Security and limits', 'Troubleshooting', 'Migration', 'AWS operations'),
'es': ('Resumen', 'Inicio rápido', 'Conceptos', 'Protocolo', 'API HTTP', 'Recetas', 'Seguridad y límites', 'Solución de problemas', 'Migración', 'Operación en AWS')}

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def check_translations():
    record = json.loads((ROOT / 'docs/es/manifest.json').read_text())
    for name, expected in record['sources'].items():
        if digest(ROOT / 'docs/agents' / name) != expected:
            raise ValueError('stale translation: ' + name)
    if set(record['sources']) != {s + '.md' for s in PAGES}:
        raise ValueError('missing translation provenance')

def inline(value):
    value = html.escape(value)
    def link(m):
        target = html.unescape(m[2])
        if target.endswith('.md') and '/' not in target:
            target = '../' + target[:-3] + '/'
        if urlsplit(target).scheme not in ('', 'https', 'http'):
            raise ValueError('unsupported URL scheme')
        return '<a href="' + html.escape(target, quote=True) + '">' + m[1] + '</a>'
    value = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', link, value)
    value = re.sub(r'`([^`]+)`', r'<code>\1</code>', value)
    return value

def render(source):
    lines = source.splitlines(); out = []; paragraph = []; code = None; language = ''; listing = False
    def flush():
        if paragraph:
            out.append('<p>' + inline(' '.join(paragraph)) + '</p>'); paragraph.clear()
    for line in lines:
        if line.startswith('```'):
            flush()
            if code is None:
                code = []; language = line[3:].strip()
            else:
                out.append('<pre><code class="language-' + html.escape(language, quote=True) + '">' + html.escape('\n'.join(code)) + '</code></pre>'); code = None
            continue
        if code is not None:
            code.append(line); continue
        if not line.startswith('- ') and listing:
            out.append('</ul>'); listing = False
        if line.startswith('#'):
            flush(); m = re.match(r'^(#{1,6}) (.*)$', line)
            if not m: raise ValueError('invalid heading')
            level = len(m[1]); anchor = re.sub(r'[^\w-]+', '-', m[2].lower()).strip('-')
            out.append(f'<h{level} id="{anchor}">{inline(m[2])}</h{level}>')
        elif line.startswith('- '):
            flush()
            if not listing: out.append('<ul>'); listing = True
            out.append('<li>' + inline(line[2:]) + '</li>')
        elif not line.strip(): flush()
        else: paragraph.append(line)
    flush()
    if listing: out.append('</ul>')
    if code is not None: raise ValueError('unclosed code fence')
    return '\n'.join(out)

class Links(HTMLParser):
    def __init__(self): super().__init__(); self.urls = []
    def handle_starttag(self, tag, attrs):
        self.urls.extend(v for k, v in attrs if k in ('href', 'src'))

def validate(out):
    for path in out.rglob('*.html'):
        links = Links(); links.feed(path.read_text())
        for link in links.urls:
            if urlsplit(link).scheme or link.startswith('#'): continue
            target = (path.parent / unquote(urlsplit(link).path)).resolve()
            if target.is_dir(): target = target / 'index.html'
            if not target.is_file(): raise ValueError(f'broken link: {path}: {link}')

def build(out):
    check_translations()
    source_catalog = json.loads((ROOT / 'sites/catalog.json').read_text())
    if source_catalog['releases']:
        raise ValueError('historical release rendering is not implemented; never substitute Development')
    if out.exists(): shutil.rmtree(out)
    out.mkdir(parents=True)
    shutil.copyfile(ROOT / 'sites/style.css', out / 'style.css')
    manifest = {'schema': 1, 'scope': 'Development', 'sources': {}}
    for pattern in ('protocol/*.go', 'service/*.go', 'attestation/*.go', 'awsstore/*.go', 'api/*.go', 'cmd/api/*.go', 'infra/*.go', 'docs/agents/*.md', 'docs/es/*.md', 'sites/*.py', 'sites/*.css', 'sites/*.json', 'docs/es/*.json', 'protocol/test-vectors/*.json', 'go.mod', 'go.sum'):
        for path in sorted(ROOT.glob(pattern)):
            manifest['sources'][str(path.relative_to(ROOT))] = digest(path)
    (out / 'source-manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    catalog = {'schema': 1, 'module': 'go.apexfission.aws.signature', 'releases': [], 'archiveBoundary': 'No confirmed releases recorded; Development only.', 'development': {'en': 'en/development/index/', 'es': 'es/development/index/'}}
    (out / 'catalog.json').write_text(json.dumps(catalog, indent=2) + '\n')
    (out / 'index.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><title>Sworn Ink — Development</title><h1>Sworn Ink</h1><p>No confirmed releases. / Sin versiones publicadas confirmadas.</p><p><a href="en/development/index/">English · Development</a> · <a href="es/development/index/">Español · Desarrollo</a></p><p><a href="catalog.json">Agent catalog / Catálogo para agentes</a></p></html>')
    for lang in ('en', 'es'):
        folder = ROOT / ('docs/agents' if lang == 'en' else 'docs/es')
        for slug, title in zip(PAGES, LABELS[lang]):
            route = out / lang / 'development' / slug; route.mkdir(parents=True)
            raw = route.parent / 'raw'; raw.mkdir(exist_ok=True)
            shutil.copyfile(folder / (slug + '.md'), raw / (slug + '.md'))
            other = 'es' if lang == 'en' else 'en'
            nav = ''.join('<li><a ' + ('aria-current="page" ' if s == slug else '') + 'href="../' + s + '/">' + t + '</a></li>' for s, t in zip(PAGES, LABELS[lang]))
            notice = 'Development source · No confirmed releases' if lang == 'en' else 'Código en desarrollo · Sin versiones confirmadas'
            skip = 'Skip to content' if lang == 'en' else 'Ir al contenido'
            body = render((folder / (slug + '.md')).read_text())
            page = f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} · Sworn Ink</title><link rel="stylesheet" href="../../../style.css"><link rel="alternate" hreflang="{other}" href="../../../{other}/development/{slug}/"></head><body><a class="skip" href="#content">{skip}</a><header><a href="../../../index.html">Sworn Ink</a><span>{notice}</span><a lang="{other}" href="../../../{other}/development/{slug}/">{ "Español" if other == "es" else "English"}</a></header><div class="layout"><nav aria-label="{ "Guides" if lang == "en" else "Guías"}"><ul>{nav}</ul><a href="../../../catalog.json">{ "Version catalog" if lang == "en" else "Catálogo de versiones"}</a></nav><main id="content">{body}<footer><a href="../raw/{slug}.md">Markdown</a> · <a href="../../../source-manifest.json">SHA-256</a></footer></main></div></body></html>'
            (route / 'index.html').write_text(page)
    validate(out)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, default=ROOT / 'sites/dist'); parser.add_argument('--check', action='store_true')
    args = parser.parse_args(); build(args.out)
    print('Built and validated Development documentation: ' + str(args.out))
