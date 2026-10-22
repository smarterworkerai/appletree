#!/usr/bin/env python3
"""Internal cache utility; canonical ADW tasks still perform every build/check."""
from modules.dependency_cache import main

if __name__ == '__main__':
    raise SystemExit(main())
