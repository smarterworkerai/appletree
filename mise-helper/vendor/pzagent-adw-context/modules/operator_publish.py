"""Human release orchestration: ADW compilation, project packaging, OCI publication."""
from __future__ import annotations

from copy import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import shutil
from uuid import uuid4

from .common import project_dir
from .common import ContractError, FULL_SHA
from .execution import human
from .operator_credentials import clean_environment
from .operator_registry import inspect, read_manifest, oras
from .operator_sources import object_repository, resolve
from .operator_state import locked, new_operation, read, write
from .oras_registry import OrasRegistry
from .release_manifest import DIGEST_REF, release_kind, validate


def tool(argv, *, cwd=None, env=None, input=None):
    result = subprocess.run(argv, cwd=cwd, env=env, input=input, text=True, capture_output=True)
    if result.returncode:
        raise ContractError('release operation tool failed: ' + argv[0])
    return result.stdout


def source_snapshot(repo: Path, sha: str, remote: str, destination: Path):
    objects = object_repository(repo, sha, remote)
    result = subprocess.run(['git', 'archive', '--format=tar', sha], cwd=objects, capture_output=True)
    if result.returncode:
        raise ContractError('selected source archive unavailable')
    if destination.exists():
        raise ContractError('source snapshot already exists without completed selection')
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.source-', dir=destination.parent))
    try:
      with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
        for member in archive:
            relative = Path(member.name)
            if relative.is_absolute() or '..' in relative.parts or not (member.isfile() or member.isdir()):
                raise ContractError('source archive contains unsupported paths or links')
            if any(part in {'.git', 'handover'} or (part.startswith('.env') and not part.endswith('.example')) for part in relative.parts):
                continue
            target = staging / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
                target.chmod(member.mode & 0o777)
      staging.rename(destination)
    finally:
      if staging.exists():
        shutil.rmtree(staging)


def image_metadata(reference: str, sha: str, platform: str):
    """Check source and platform before reusing a component from the registry."""
    manifest = json.loads(oras('manifest', 'fetch', reference))
    if 'manifests' in manifest:
        matches = [entry for entry in manifest['manifests']
                   if entry.get('platform', {}).get('os', '') + '/' + entry.get('platform', {}).get('architecture', '') == platform]
        if len(matches) != 1:
            raise ContractError('published image platform is absent or ambiguous')
        repository = reference.split('@')[0]
        return image_metadata(repository + '@' + matches[0]['digest'], sha, platform)
    descriptor = manifest['config']
    data = oras('blob', 'fetch', '--output', '-', reference.split('@')[0] + '@' + descriptor['digest'], binary=True)
    if 'sha256:' + hashlib.sha256(data).hexdigest() != descriptor['digest']:
        raise ContractError('image config digest differs')
    config = json.loads(data)
    if (config.get('os', '') + '/' + config.get('architecture', '') != platform
            or (config.get('config', {}).get('Labels') or {}).get('org.opencontainers.image.revision') != sha):
        raise ContractError('published image source/platform differs')


def existing_components(adapter, kind_name, sha, platform):
    kind = release_kind(adapter, kind_name)
    result = {}
    for name, component in kind['components'].items():
        digest = OrasRegistry().resolve(component['package'] + ':sha-' + sha[:12])
        if digest:
            reference = component['package'] + '@' + digest
            image_metadata(reference, sha, platform)
            result[name] = reference
    return result


def component_inventory(adapter, kind_name: str, sha: str, platform: str) -> dict:
    """Return the closed read-only inventory used by advanced coordinators."""
    kind=release_kind(adapter,kind_name)
    reused=existing_components(adapter,kind_name,sha,platform)
    return {'schema_version':'1.0.0','status':'ok','detail':'components',
            'kind':kind_name,'source_sha':sha,'platform':platform,
            'reused':{name:reused[name] for name in sorted(reused)},
            'missing':sorted(set(kind['components'])-set(reused))}


def package(repo: Path, adapter, *, kind_name, build_dir: Path, output_dir: Path):
    build = read(build_dir / 'build.json')
    kind = release_kind(adapter, kind_name)
    if not FULL_SHA.fullmatch(build['source_sha']) or not set(build['components']) <= set(kind['components']):
        raise ContractError('build identity differs from release kind')
    config = json.loads((project_dir(repo) / 'pz-release.json').read_text())
    if 'package_hook' in config:
        argv = config['package_hook']
    elif config.get('hooks', {}).get('build') == 'bundle:release_build':
        # Fixed bundled entry point; publication binding/validation stays here.
        import sys
        argv = [sys.executable, str(Path(__file__).with_name('release_build.py')), 'package']
    else:
        raise ContractError('package hook declaration invalid')
    if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) and arg for arg in argv):
        raise ContractError('package hook declaration invalid')
    request = {'schema_version': '1.0.0', 'source_sha': build['source_sha'],
               'platform': build['platform'], 'components': build['components'],
               'build_dir': str(build_dir.resolve()), 'output_dir': str(output_dir.resolve())}
    env = clean_environment()
    env.pop('SSH_AUTH_SOCK', None)
    try:
        result = json.loads(tool(argv, cwd=repo, env=env, input=json.dumps(request)))
    except json.JSONDecodeError as exc:
        raise ContractError('package hook did not return JSON') from exc
    if (not isinstance(result, dict) or set(result) != {'images'}
            or not isinstance(result['images'], dict) or set(result['images']) != set(build['components'])):
        raise ContractError('packaging result differs from requested component set')
    record = {'schema_version': '1.0.0', 'kind': kind_name, 'source_sha': build['source_sha'],
              'platform': build['platform'], 'images': result['images']}
    for image in record['images'].values():
        if (not isinstance(image, dict) or set(image) != {'reference', 'image_id'}
                or not isinstance(image['image_id'], str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image['image_id'])
                or not isinstance(image['reference'], str) or not image['reference'] or image['reference'].startswith('-')):
            raise ContractError('package hook returned an invalid local image')
    write(output_dir / 'package.json', record)
    return record


def publish_components(adapter, record: dict, reused: dict, progress_path: Path) -> dict:
    """Shared create-only image publication; caller retains manifest/pointer policy."""
    kind = release_kind(adapter, record['kind'])
    sha, platform = record['source_sha'], record['platform']
    if not FULL_SHA.fullmatch(sha):
        raise ContractError('package source identity invalid')
    images = dict(reused)
    if set(images) & set(record['images']) or set(images) | set(record['images']) != set(kind['components']):
        raise ContractError('publication requires the complete non-overlapping component set')
    for name, reference in images.items():
        match = DIGEST_REF.fullmatch(reference) if isinstance(reference, str) else None
        if not match or match['repo'] != kind['components'][name]['package']:
            raise ContractError('reused component repository differs from release kind')
        image_metadata(reference, sha, platform)
    registry = OrasRegistry()
    for name, image in record['images'].items():
        repository = kind['components'][name]['package']
        tag = repository + ':sha-' + sha[:12]
        digest = registry.resolve(tag)
        if digest:
            # A previous attempt or another operator may have completed upload.
            image_metadata(repository + '@' + digest, sha, platform)
        else:
            local = json.loads(tool(['docker', 'image', 'inspect', image['reference']]))[0]
            if (local['Id'] != image['image_id'] or local['Os'] + '/' + local['Architecture'] != platform
                    or (local.get('Config', {}).get('Labels') or {}).get('org.opencontainers.image.revision') != sha):
                raise ContractError('packaged local image changed before publication')
            temporary = repository + ':upload-' + uuid4().hex
            tool(['docker', 'tag', image['reference'], temporary])
            tool(['docker', 'push', temporary])
            digest = registry.resolve(temporary)
            if digest is None:
                raise ContractError('uploaded component is unavailable')
            image_metadata(repository + '@' + digest, sha, platform)
            registry.copy_if_unchanged(repository + '@' + digest, tag, None)
        images[name] = repository + '@' + digest
        write(progress_path, {'schema_version': '1.0.0', 'source_sha': sha, 'images': images})
    return images


def publish(repo: Path, adapter, package_dir: Path, reused=None, *,
            authorization_file: Path | None=None,
            publication_pointer: str | None=None,
            expected_pointer_digest: str | None=None):
    record = read(package_dir / 'package.json')
    kind = release_kind(adapter, record['kind'])
    sha, platform = record['source_sha'], record['platform']
    if not FULL_SHA.fullmatch(sha):
        raise ContractError('package source identity invalid')
    if reused is None:
        reused = {name: reference for name, reference in existing_components(adapter, record['kind'], sha, platform).items()
                  if name not in record['images']}
    if ((publication_pointer is None)!=(expected_pointer_digest is None)
            or (publication_pointer is not None
                and publication_pointer not in kind.get('publication_pointers',[]))):
        raise ContractError('publication pointer selection is invalid')
    if expected_pointer_digest not in (None,'absent'):
        if (not isinstance(expected_pointer_digest,str)
                or not re.fullmatch(r'sha256:[0-9a-f]{64}',expected_pointer_digest)):
            raise ContractError('publication pointer expectation is invalid')
    if not human():
        if authorization_file is None:
            raise ContractError('CI publication requires an authorization receipt')
        from .ci.release_authorization import revalidate
        revalidate(authorization_file,adapter,kind_name=record['kind'],source_sha=sha,
                   publication_pointer=publication_pointer,
                   expected_pointer_digest=expected_pointer_digest)
    images = publish_components(adapter, record, reused, package_dir / 'publication.json')
    registry = OrasRegistry()
    manifest = validate({'schema': kind['schema'], 'source_sha': sha, 'source_tag': 'sha-' + sha[:12], 'images': images}, adapter, record['kind'])
    reference = kind['manifest_package'] + ':' + manifest['source_tag']
    digest = registry.resolve(reference)
    if digest:
        if read_manifest(kind['manifest_package'] + '@' + digest) != manifest:
            raise ContractError('existing immutable release differs; refusing overwrite')
    else:
        write(package_dir / 'manifest.json', manifest)
        temporary = kind['manifest_package'] + ':upload-' + uuid4().hex
        # ORAS content title is manifest.json, independent of the local directory.
        args = ['oras', 'push', temporary, '--artifact-type', kind['schema'], 'manifest.json:application/json']
        from .oras_registry import registry_args
        tool(registry_args(args), cwd=package_dir)
        digest = registry.resolve(temporary)
        if digest is None or read_manifest(kind['manifest_package'] + '@' + digest) != manifest:
            raise ContractError('uploaded release manifest differs')
        registry.copy_if_unchanged(kind['manifest_package'] + '@' + digest, reference, None)
    selected = inspect(adapter, record['kind'], source_sha=sha)
    if not selected['available']:
        raise ContractError('published release is incomplete')
    if publication_pointer is not None:
        target=kind['manifest_package']+':'+publication_pointer
        expected=None if expected_pointer_digest=='absent' else expected_pointer_digest
        registry.copy_if_unchanged(selected['release_reference'],target,expected)
        selected={**selected,'publication':{
            'schema_version':'1.0.0','pointer':target,
            'previous_digest':expected_pointer_digest,
            'digest':selected['release_reference'].rsplit('@',1)[1],
        }}
    write(package_dir / 'published.json', {'schema_version': '1.0.0', **selected})
    return selected


def workflow(repo: Path, adapter, args):
    if not human():
        raise ContractError('publication workflows require human mode')
    directory = (args.operation_dir or new_operation(repo)).resolve()
    with locked(directory):
        path = directory / 'operation.json'
        if path.exists():
            record = read(path)
            if args.command != 'workflow-resume' or record.get('workflow') not in {'publish', 'publish-deploy'}:
                raise ContractError('existing publication operation requires workflow resume')
        else:
            if not args.ref:
                raise ContractError('publication requires a selected source ref')
            kind = release_kind(adapter, args.kind)
            cfg = json.loads((project_dir(repo) / 'pz-release.json').read_text())
            if args.platform not in cfg['platforms']:
                raise ContractError('requested platform is not supported by this project')
            sha = resolve(repo, args.ref, args.remote)
            if args.command == 'workflow-publish-deploy':
                group = adapter['targets'].get(args.environment)
                if not group or (args.target or group['default']) not in group['items']:
                    raise ContractError('publish-deploy requires a valid target environment')
            record = {'schema_version': '1.0.0', 'workflow': args.command.removeprefix('workflow-'),
                      'kind': args.kind, 'source_sha': sha, 'platform': args.platform,
                      'environment': args.environment, 'target': args.target, 'remote': args.remote,
                      'sync_config': args.sync_config, 'config_ref': args.config_ref,
                      'verify': args.verify, 'phase': 'selected', 'results': {}}
            record['on_failure'] = getattr(args, 'on_failure', 'stop')
            write(path, record)
        try:
            existing = inspect(adapter, record['kind'], source_sha=record['source_sha'])
            if existing['available']:
                for reference in existing['manifest']['images'].values():
                    image_metadata(reference, record['source_sha'], record['platform'])
                selected = existing
            else:
                if 'reuse' not in record:
                    record['reuse'] = existing_components(adapter, record['kind'], record['source_sha'], record['platform'])
                    write(path, record)
                missing = sorted(set(release_kind(adapter, record['kind'])['components']) - set(record['reuse']))
                if missing:
                    if 'build' not in record['results']:
                        source = directory / 'source'
                        if not source.exists():
                            source_snapshot(repo, record['source_sha'], record['remote'], source)
                        environment = clean_environment()
                        environment.pop('SSH_AUTH_SOCK', None)
                        environment.update(PZ_ADW_SOURCE_ROOT=str(source), PZ_ADW_SOURCE_SHA=record['source_sha'],
                                           PZ_ADW_BUILD_DIR=str(directory / 'build'), PZ_ADW_PLATFORM=record['platform'],
                                           PZ_ADW_COMPONENTS=json.dumps(missing))
                        record['phase'] = 'build'; write(path, record)
                        for task in ('adw:install', 'adw:build'):
                            tool(['mise', 'run', task], cwd=repo, env=environment)
                        record['results']['build'] = {'completed': True}; write(path, record)
                    if 'package' not in record['results']:
                        record['phase'] = 'package'; write(path, record)
                        package(repo, adapter, kind_name=record['kind'], build_dir=directory / 'build', output_dir=directory / 'package')
                        record['results']['package'] = {'completed': True}; write(path, record)
                else:
                    write(directory / 'package/package.json', {'schema_version': '1.0.0', 'kind': record['kind'],
                          'source_sha': record['source_sha'], 'platform': record['platform'], 'images': {}})
                record['phase'] = 'publish'; write(path, record)
                selected = publish(repo, adapter, directory / 'package', record['reuse'])
            record['results']['publish'] = selected; write(path, record)
            if record['workflow'] == 'publish-deploy':
                from .operator_workflows import deploy_existing
                deploy_args = copy(args)
                for key in ('kind', 'environment', 'target', 'sync_config', 'config_ref', 'verify'):
                    setattr(deploy_args, key, record[key])
                deploy_args.on_failure = record.get('on_failure', 'stop')
                deploy_args.remote = record['remote']
                deploy_args.operation_dir = directory / 'deployment'
                deploy_args.command = 'workflow-resume' if (deploy_args.operation_dir / 'operation.json').exists() else 'workflow-deploy-existing'
                deploy_args.ref = None; deploy_args.release_ref = selected['release_reference']
                record['phase'] = 'deploy'; write(path, record)
                record['results']['deploy'] = deploy_existing(repo, adapter, deploy_args)
            record['phase'] = 'complete'; record['status'] = 'ok'; record.pop('reason', None)
            write(path, record)
        except Exception:
            record['status'] = 'incomplete'; write(path, record)
            raise
        return {'status': 'ok', 'operation_dir': str(directory), 'release_reference': selected['release_reference'], 'source_sha': record['source_sha']}
