import os
import tempfile

# Tests write throw-away projects: keep them out of the user's scan cache and desktop history.
os.environ.setdefault("ARMORIX_NO_CACHE", "1")
os.environ.setdefault("ARMORIX_HOME", tempfile.mkdtemp(prefix="armorix-test-home-"))
