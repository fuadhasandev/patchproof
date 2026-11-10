"""Check archives and install each extra independently outside the checkout."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import venv
import zipfile

root = Path(__file__).resolve().parents[1]
version = (root/'src/patchproof/_version.py').read_text().split('"')[1]
assert json.loads((root/'dashboard/package.json').read_text())['version'] == version
lock = json.loads((root/'dashboard/package-lock.json').read_text())
assert lock['version'] == lock['packages']['']['version'] == version
wheel = root/'dist'/f'patchproof-{version}-py3-none-any.whl'
sdist = root/'dist'/f'patchproof-{version}.tar.gz'
with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()
    required = {'patchproof/' + p.relative_to(root/'src/patchproof').as_posix() for p in (root/'src/patchproof').rglob('*.py')}
    assert required <= set(names)
    assert any(n.endswith('/licenses/LICENSE') for n in names)
with tarfile.open(sdist) as archive:
    names += archive.getnames()
    assert f'patchproof-{version}/dashboard/package-lock.json' in archive.getnames()
    assert f'patchproof-{version}/tests/conftest.py' in archive.getnames()
for name in names:
    parts = Path(name).parts
    assert not set(parts) & {'.venv', 'node_modules', '.next', '.patchproof', 'test-results', '__pycache__'}
    assert not any(p.startswith('.env') and p != '.env.example' for p in parts)
    assert not any(s in name for s in ('.sqlite', '.pem', '.log', '.pyc', '.tsbuildinfo'))
print('PASS archive contents and synchronized version', version, flush=True)
env = {k: v for k, v in os.environ.items() if k != 'PYTHONPATH' and not k.startswith('OPENROUTER_')}
with tempfile.TemporaryDirectory(prefix='patchproof-wheel-') as directory:
    work = Path(directory)
    for extra in ('core', 'api', 'browser', 'dev', 'hosted'):
        home = work/extra
        venv.EnvBuilder(with_pip=True).create(home)
        python = home/'bin/python'
        requirement = str(wheel) + (f'[{extra}]' if extra != 'core' else '')
        subprocess.run([str(python), '-m', 'pip', 'install', '--only-binary=:all:', '--disable-pip-version-check', requirement], cwd=work, env=env, check=True, stdout=subprocess.DEVNULL)
        subprocess.run([str(python), '-m', 'pip', 'check'], cwd=work, env=env, check=True)
        subprocess.run([str(python), str(root/'scripts/installed_smoke.py'), extra], cwd=work, env=env, check=True)
(root/'dist/SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in (wheel, sdist)))
