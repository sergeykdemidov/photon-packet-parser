import io
import struct
from photon_packet_parser.protocol16_type import Protocol16Type
from photon_packet_parser.operation_request import OperationRequest
from photon_packet_parser.operation_response import OperationResponse
from photon_packet_parser.event_data import EventData

_NULL_TYPE = 42
_UNKNOWN_TYPE = 0


class Protocol16Deserializer:

    @staticmethod
    def deserialize(input: io.BytesIO, type_code: int):
        if type_code == Protocol16Type.UNKNOWN.value or type_code == Protocol16Type.NULL.value:
            return None
        elif type_code == Protocol16Type.DICTIONARY.value:
            return Protocol16Deserializer.deserialize_dictionary(input)
        elif type_code == Protocol16Type.STRINGARRAY.value:
            return Protocol16Deserializer.deserialize_string_array(input)
        elif type_code == Protocol16Type.BYTE.value:
            return Protocol16Deserializer.deserialize_byte(input)
        elif type_code == Protocol16Type.DOUBLE.value:
            return Protocol16Deserializer.deserialize_double(input)
        elif type_code == Protocol16Type.EVENTDATA.value:
            return Protocol16Deserializer.deserialize_event_data(input)
        elif type_code == Protocol16Type.FLOAT.value:
            return Protocol16Deserializer.deserialize_float(input)
        elif type_code == Protocol16Type.INTEGER.value:
            return Protocol16Deserializer.deserialize_integer(input)
        elif type_code == Protocol16Type.HASHTABLE.value:
            return Protocol16Deserializer.deserialize_hash_table(input)
        elif type_code == Protocol16Type.SHORT.value:
            return Protocol16Deserializer.deserialize_short(input)
        elif type_code == Protocol16Type.LONG.value:
            return Protocol16Deserializer.deserialize_long(input)
        elif type_code == Protocol16Type.INTEGERARRAY.value:
            return Protocol16Deserializer.deserialize_integer_array(input)
        elif type_code == Protocol16Type.BOOLEAN.value:
            return Protocol16Deserializer.deserialize_boolean(input)
        elif type_code == Protocol16Type.OPERATIONRESPONSE.value:
            return Protocol16Deserializer.deserialize_operation_response(input)
        elif type_code == Protocol16Type.OPERATIONREQUEST.value:
            return Protocol16Deserializer.deserialize_operation_request(input)
        elif type_code == Protocol16Type.STRING.value:
            return Protocol16Deserializer.deserialize_string(input)
        elif type_code == Protocol16Type.BYTEARRAY.value:
            return Protocol16Deserializer.deserialize_byte_array(input)
        elif type_code == Protocol16Type.ARRAY.value:
            return Protocol16Deserializer.deserialize_array(input)
        elif type_code == Protocol16Type.OBJECTARRAY.value:
            return Protocol16Deserializer.deserialize_object_array(input)
        else:
            raise Exception("Unknown type code: " + str(type_code))

    @staticmethod
    def deserialize_event_data(input: io.BytesIO):
        code = Protocol16Deserializer.deserialize_byte(input)
        parameters = Protocol16Deserializer.deserialize_parameter_table(input)
        return EventData(code, parameters)

    @staticmethod
    def deserialize_parameter_table(input: io.BytesIO):
        dictionary_size = Protocol16Deserializer.deserialize_short(input)
        dictionary = {}

        for i in range(max(0, dictionary_size)):
            key = Protocol16Deserializer.deserialize_byte(input)
            value_type_code = Protocol16Deserializer.deserialize_byte(input)
            value = Protocol16Deserializer.deserialize(input, value_type_code)
            dictionary[key] = value

        return dictionary

    @staticmethod
    def deserialize_short(input: io.BytesIO) -> int:
        buffer = input.read(2)
        if len(buffer) < 2:
            return 0
        return struct.unpack('>h', buffer)[0]

    @staticmethod
    def deserialize_byte(input: io.BytesIO) -> int:
        data = input.read(1)
        return data[0] if data else 0

    @staticmethod
    def deserialize_boolean(input: io.BytesIO) -> bool:
        data = input.read(1)
        return data[0] != 0 if data else False

    @staticmethod
    def deserialize_integer(input: io.BytesIO) -> int:
        buffer = input.read(4)
        if len(buffer) < 4:
            return 0
        return struct.unpack('>i', buffer)[0]

    @staticmethod
    def deserialize_long(input: io.BytesIO) -> int:
        buffer = input.read(8)
        if len(buffer) < 8:
            return 0
        return struct.unpack('>q', buffer)[0]

    @staticmethod
    def deserialize_float(input: io.BytesIO) -> float:
        buffer = input.read(4)
        if len(buffer) < 4:
            return 0.0
        return struct.unpack('>f', buffer)[0]

    @staticmethod
    def deserialize_double(input: io.BytesIO) -> float:
        buffer = input.read(8)
        if len(buffer) < 8:
            return 0.0
        return struct.unpack('>d', buffer)[0]

    @staticmethod
    def deserialize_string(input: io.BytesIO) -> str:
        string_size = Protocol16Deserializer.deserialize_short(input)

        if string_size <= 0:
            return ""

        buffer = input.read(string_size)
        return buffer.decode('utf-8', errors='replace')

    @staticmethod
    def deserialize_byte_array(input: io.BytesIO):
        array_size = Protocol16Deserializer.deserialize_integer(input)

        if array_size <= 0:
            return b''

        return input.read(array_size)

    @staticmethod
    def deserialize_integer_array(input: io.BytesIO):
        array_size = Protocol16Deserializer.deserialize_integer(input)

        if array_size <= 0:
            return []

        return [Protocol16Deserializer.deserialize_integer(input) for _ in range(array_size)]

    @staticmethod
    def deserialize_string_array(input: io.BytesIO):
        array_size = Protocol16Deserializer.deserialize_short(input)

        if array_size <= 0:
            return []

        return [Protocol16Deserializer.deserialize_string(input) for _ in range(array_size)]

    @staticmethod
    def deserialize_object_array(input: io.BytesIO):
        array_size = Protocol16Deserializer.deserialize_short(input)

        if array_size <= 0:
            return []

        result = []
        for _ in range(array_size):
            type_code = Protocol16Deserializer.deserialize_byte(input)
            result.append(Protocol16Deserializer.deserialize(input, type_code))
        return result

    @staticmethod
    def deserialize_array(input: io.BytesIO):
        array_size = Protocol16Deserializer.deserialize_short(input)
        type_code = Protocol16Deserializer.deserialize_byte(input)

        if array_size <= 0:
            return []

        if type_code == Protocol16Type.ARRAY.value:
            return [Protocol16Deserializer.deserialize_array(input) for _ in range(array_size)]
        elif type_code == Protocol16Type.BYTEARRAY.value:
            return [Protocol16Deserializer.deserialize_byte_array(input) for _ in range(array_size)]
        elif type_code == Protocol16Type.DICTIONARY.value:
            return Protocol16Deserializer.deserialize_dictionary_array(input, array_size)
        else:
            return [Protocol16Deserializer.deserialize(input, type_code) for _ in range(array_size)]

    @staticmethod
    def deserialize_dictionary(input: io.BytesIO):
        key_type_code = Protocol16Deserializer.deserialize_byte(input)
        value_type_code = Protocol16Deserializer.deserialize_byte(input)
        dictionary_size = Protocol16Deserializer.deserialize_short(input)
        return Protocol16Deserializer.deserialize_dictionary_elements(
            input, max(0, dictionary_size), key_type_code, value_type_code
        )

    @staticmethod
    def deserialize_dictionary_elements(input: io.BytesIO, dictionary_size: int,
                                        key_type_code: int, value_type_code: int):
        output = {}
        _dynamic_key = key_type_code in (_UNKNOWN_TYPE, _NULL_TYPE)
        _dynamic_val = value_type_code in (_UNKNOWN_TYPE, _NULL_TYPE)

        for _ in range(dictionary_size):
            kt = Protocol16Deserializer.deserialize_byte(input) if _dynamic_key else key_type_code
            key = Protocol16Deserializer.deserialize(input, kt)
            vt = Protocol16Deserializer.deserialize_byte(input) if _dynamic_val else value_type_code
            value = Protocol16Deserializer.deserialize(input, vt)
            output[key] = value

        return output

    @staticmethod
    def deserialize_dictionary_array(input: io.BytesIO, size: int):
        key_type_code = Protocol16Deserializer.deserialize_byte(input)
        value_type_code = Protocol16Deserializer.deserialize_byte(input)
        _dynamic_key = key_type_code in (_UNKNOWN_TYPE, _NULL_TYPE)
        _dynamic_val = value_type_code in (_UNKNOWN_TYPE, _NULL_TYPE)
        output = []

        for _ in range(size):
            dictionary = {}
            array_size = Protocol16Deserializer.deserialize_short(input)

            for _ in range(max(0, array_size)):
                kt = Protocol16Deserializer.deserialize_byte(input) if _dynamic_key else key_type_code
                key = Protocol16Deserializer.deserialize(input, kt)
                vt = Protocol16Deserializer.deserialize_byte(input) if _dynamic_val else value_type_code
                value = Protocol16Deserializer.deserialize(input, vt)
                dictionary[key] = value

            output.append(dictionary)

        return output

    @staticmethod
    def deserialize_hash_table(input: io.BytesIO):
        size = Protocol16Deserializer.deserialize_short(input)
        return Protocol16Deserializer.deserialize_dictionary_elements(
            input, max(0, size), _UNKNOWN_TYPE, _UNKNOWN_TYPE
        )

    @staticmethod
    def deserialize_operation_request(input: io.BytesIO):
        code = Protocol16Deserializer.deserialize_byte(input)
        table = Protocol16Deserializer.deserialize_parameter_table(input)
        return OperationRequest(code, table)

    @staticmethod
    def deserialize_operation_response(input: io.BytesIO):
        code = Protocol16Deserializer.deserialize_byte(input)
        return_code = Protocol16Deserializer.deserialize_short(input)
        debug_message = Protocol16Deserializer.deserialize(input, Protocol16Deserializer.deserialize_byte(input))
        parameters = Protocol16Deserializer.deserialize_parameter_table(input)
        return OperationResponse(code, return_code, debug_message, parameters)
