"""Read exact image config digests from a Docker save stream across image stores.

This standard-library-only program also runs over SSH via python3 -c. Layers
are streamed past without extraction; only bounded JSON metadata is inspected.
"""
import hashlib
import json
import re
import subprocess
import sys
import tarfile


def identities(stream, references):
    configs = {}
    manifests = None
    with tarfile.open(fileobj=stream, mode='r|*') as archive:
        for member in archive:
            if not member.isfile() or not 0 < member.size <= 1024 * 1024:
                continue
            if member.name != 'manifest.json' and not re.fullmatch(r'(?:blobs/sha256/[0-9a-f]{64}|[0-9a-f]{64}\.json)', member.name):
                continue
            data = archive.extractfile(member).read()
            try:
                value = json.loads(data)
            except (ValueError, UnicodeError):
                continue
            if member.name == 'manifest.json':
                if manifests is not None or not isinstance(value, list):
                    raise ValueError('ambiguous archive manifest')
                manifests = value
            elif isinstance(value, dict) and all(key in value for key in ('os', 'architecture', 'rootfs')):
                if member.name in configs or len(configs) >= 1024:
                    raise ValueError('ambiguous or excessive archive configs')
                digest = hashlib.sha256(data).hexdigest()
                expected = member.name.removeprefix('blobs/sha256/').removesuffix('.json')
                if digest != expected:
                    raise ValueError('archive config digest differs')
                configs[member.name] = {'digest': 'sha256:' + digest,
                    'platform': value['os'] + '/' + value['architecture']}
    result = {}
    for reference in references:
        matches = [row for row in manifests or [] if reference in (row.get('RepoTags') or [])]
        if len(matches) != 1 or matches[0].get('Config') not in configs:
            raise ValueError('archive selection is absent or ambiguous')
        result[reference] = configs[matches[0]['Config']]
    return result


def main(references):
    archive = subprocess.Popen(['docker', 'image', 'save', *references],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        result = identities(archive.stdout, references)
        if archive.wait():
            raise ValueError('image archive failed')
        print(json.dumps(result))
    finally:
        archive.stdout.close()
        if archive.poll() is None:
            archive.terminate()
        archive.wait()


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception:
        print('image config identity unavailable', file=sys.stderr)
        raise SystemExit(21)
