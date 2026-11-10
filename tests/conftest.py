import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# keep test scans out of the real history database
os.environ.setdefault("SCA_DATA_DIR", tempfile.mkdtemp(prefix="sca-tests-"))
