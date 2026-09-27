"""Unit tests for the campaign scripts. Run: cd scripts && python3 -m unittest discover tests"""
import os
import sys

# Put scripts/ on the path so tests can `import <driver>` and `from lib import ...`
# no matter what directory unittest is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
