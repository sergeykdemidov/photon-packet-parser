import io
import struct


class NumberSerializer:
    @staticmethod
    def deserialize_int(source: io.BytesIO) -> int:
        data = source.read(4)
        if len(data) < 4:
            return 0
        return struct.unpack('>I', data)[0]

    @staticmethod
    def deserialize_short(source: io.BytesIO) -> int:
        data = source.read(2)
        if len(data) < 2:
            return 0
        return struct.unpack('>H', data)[0]

    @staticmethod
    def serialize(value: int, target: io.BytesIO) -> None:
        target.write(struct.pack('>I', value & 0xFFFFFFFF))
