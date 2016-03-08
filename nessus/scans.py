from typing import Iterable

from nessus.base import LibNessusBase
from nessus.model import NessusScan


class LibNessusScans(LibNessusBase):
    def list(self) -> Iterable[NessusScan]:
        ans = self._get('scans')

        if ans.json()['scans'] is None:
            return set()

        return {NessusScan.from_json(elem) for elem in ans.json()['scans']}
