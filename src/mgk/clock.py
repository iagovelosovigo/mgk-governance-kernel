"""Injectable clocks make time-window gates deterministic and testable."""

import time
from dataclasses import dataclass


class SystemClock:
    def now(self) -> int:
        return int(time.time())


@dataclass
class FixedClock:
    value: int

    def now(self) -> int:
        return self.value

    def advance(self, seconds: int) -> None:
        if type(seconds) is not int:
            raise TypeError("seconds must be an integer")
        self.value += seconds
