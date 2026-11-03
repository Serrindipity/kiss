"""An isolated local server for browser tests; never touches competition data."""
import os
from pathlib import Path
import sys
import tempfile

import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

with tempfile.TemporaryDirectory(prefix='kiss-browser-') as directory:
    root = Path(directory)
    users = root / 'users.txt'
    users.write_text('sohee\nalex\n')
    config = root / 'config.toml'
    config.write_text('admin_username = "sohee"\n')
    os.environ['KISS_CONFIG_FILE'] = str(config)
    os.environ['KISS_DATA_DIR'] = str(root / 'data')
    os.environ['KISS_USERS_FILE'] = str(users)
    uvicorn.run('server.app:app', host='127.0.0.1', port=8765)
