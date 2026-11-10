import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# keep tests away from the real history database, learned rules and saved API settings
_TMP = tempfile.mkdtemp(prefix="sca-tests-")
os.environ["SCA_DATA_DIR"] = os.path.join(_TMP, "data")
os.environ["SCA_LEARNED_DIR"] = os.path.join(_TMP, "learned")
os.environ["SCA_ENV_FILE"] = os.path.join(_TMP, "env")
for _name in ("SCA_LLM_PROVIDER", "SCA_LLM_API_KEY", "SCA_LLM_BASE_URL", "SCA_LLM_MODEL"):
    os.environ.pop(_name, None)
