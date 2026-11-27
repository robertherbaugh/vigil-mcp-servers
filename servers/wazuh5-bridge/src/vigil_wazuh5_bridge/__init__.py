"""Forward Wazuh 5 findings to Vigil, with reviewed, narrow suppressions.

Wazuh keeps every event and finding. The bridge only decides what Vigil sees,
and counts what it held back, per suppression. See README.md.
"""

__version__ = "0.1.0"
