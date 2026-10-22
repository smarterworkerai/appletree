"""Repository-contained Markdown link, anchor, and disclosure guard."""
from __future__ import annotations
import re
from pathlib import Path
from .common import ContractError
LINK=re.compile(r'(?<!!)\[[^]]*\]\(([^)]+)\)')
PRIVATE=re.compile(r'(?<![0-9])(?:10\.[0-9.]+|192\.168\.[0-9.]+|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9.]+)(?![0-9])')
SECRET=re.compile(r"(?i)(?:api[_-]?key|token|password|secret)\s*[:=]\s*[\"']?[A-Za-z0-9+/_.-]{16,}")
def anchor(text:str)->str:
    text=re.sub(r'[^a-z0-9 _-]','',text.lower()); return re.sub(r'[ _]+','-',text).strip('-')
def validate_markdown(path:Path,root:Path)->None:
    text=path.read_text(encoding='utf-8')
    if PRIVATE.search(text) or SECRET.search(text): raise ContractError(f'disclosure hygiene failed: {path.relative_to(root)}')
    headings={anchor(m.group(1)) for m in re.finditer(r'^#{1,6}\s+(.+)$',text,re.M)}
    for target in LINK.findall(text):
        if target.startswith(('http://','https://','mailto:')): continue
        file_part,_,fragment=target.partition('#'); linked=path if not file_part else (path.parent/file_part)
        try: linked.resolve().relative_to(root.resolve())
        except ValueError as exc: raise ContractError('Markdown link escapes repository') from exc
        if not linked.is_file(): raise ContractError(f'Markdown link target missing: {target}')
        if fragment and linked==path and fragment not in headings: raise ContractError(f'Markdown anchor missing: {fragment}')
