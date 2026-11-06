"""Create the shared local server credential once, without printing it."""
import os
from pathlib import Path
import secrets

root = Path(__file__).resolve().parents[1]
path = root / '.env.api'
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    print('.env.api already exists; leaving it unchanged.')
else:
    with os.fdopen(fd, 'w') as file:
        file.write('PATCHPROOF_API_TOKEN=' + secrets.token_hex(32) + '\n')
    print('Created .env.api with a private local API credential. Do not commit it.')
