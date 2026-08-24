from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

source = os.environ.get("PAPERLESS_NGX_SRC")
if source:
    sys.path.insert(0, source)
else:
    from paperless_stubs import install_paperless_stubs

    install_paperless_stubs()

from django.conf import settings  # noqa: E402

if not settings.configured:
    scratch_dir = Path(tempfile.mkdtemp(prefix="paperless-gost-tests-"))
    settings.configure(SCRATCH_DIR=scratch_dir)
