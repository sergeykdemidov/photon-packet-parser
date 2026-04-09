import time


class SegmentedPackage:
    def __init__(self, total_length: int = 0, bytes_written: int = 0, total_payload: bytearray = None):
        self.total_length = total_length
        self.bytes_written = bytes_written
        self.total_payload = total_payload if total_payload is not None else bytearray(0)
        self.received_offsets: set = set()
        self.created_at: float = time.monotonic()
