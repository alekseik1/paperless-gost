from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

source = os.environ.get("PAPERLESS_NGX_SRC")
if source:
    sys.path.insert(0, source)

from django.conf import settings

if not settings.configured:
    scratch_dir = Path(tempfile.mkdtemp(prefix="paperless-gost-tests-"))
    settings.configure(SCRATCH_DIR=scratch_dir)
