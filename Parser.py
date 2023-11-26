from enum import Enum
import struct
from typing import List, Tuple, Any, Dict

class DNSType(Enum):
    DNS_TYPE_A = 1
    DNS_TYPE_NS = 2

class ByteReader:
    def __init__(self, data: bytearray):
        self.data = data
        self.index = 0

    def read(self, size: int) -> bytearray:
        result = self.data[self.index:self.index + size]
        self.index += size
        return result

    def read_int(self, size: int) -> int:
        return int.from_bytes(self.read(size), byteorder='big')

class Question:
    def __init__(self, name: List[bytes], type: int, _class: int):
        self.name = name
        self.type = type
        self._class = _class

    @property
    def NAME(self) -> str:
        return '.'.join(word.decode('utf-8') for word in self.name)

class Answer:
    def __init__(self, name: List[bytes], type: int, _class: int, ttl: int, length: int, rdata: Any):
        self.name = name
        self.type = type
        self._class = _class
        self.ttl = ttl
        self.length = length
        self.rdata = rdata

    @property
    def NAME(self) -> str:
        return ".".join(word.decode('utf-8') for word in self.name)

    @property
    def DATA(self) -> str:
        if self.type == DNSType.DNS_TYPE_A.value:
            return '.'.join(str(part) for part in bytearray(self.rdata))
        if self.type == DNSType.DNS_TYPE_NS.value:
            return '.'.join(part.decode('utf-8') for part in self.rdata[1])

class Package:
    def __init__(self, headers: Dict[str, Any], questions: List[Question], answers: List[Answer], authorities: List[Answer], additionals: List[Answer]):
        self.header = headers
        self.questions = questions
        self.answers = answers
        self.authorities = authorities
        self.additional = additionals

def parse_package(package: bytearray) -> Package:
    reader = ByteReader(package)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header['QDCOUNT'])]
    answers = [parse_data(reader) for _ in range(header['ANCOUNT'])]
    authority = [parse_data(reader) for _ in range(header['NSCOUNT'])]
    additional = [parse_data(reader) for _ in range(header['ARCOUNT'])]
    return Package(header, questions, answers, authority, additional)

def parse_header(reader: ByteReader) -> Dict[str, Any]:
    request_id = reader.read_int(2)
    flags = reader.read(2)
    counts = [reader.read_int(2) for _ in range(4)]
    return {'ID': request_id, 'FLAGS': flags, 'QDCOUNT': counts[0], 'ANCOUNT': counts[1], 'NSCOUNT': counts[2], 'ARCOUNT': counts[3]}

def parse_question(reader: ByteReader) -> Question:
    q_name = parse_name(reader)
    q_type = reader.read_int(2)
    q_class = reader.read_int(2)
    return Question(q_name, q_type, q_class)

def parse_name(reader: ByteReader) -> List[bytes]:
    name = []
    while True:
        data_len = reader.read(1)[0]
        if data_len < 64:
            name.append(reader.read(data_len))
        else:
            reader.index = (data_len % 64) + reader.read(1)[0]
            continue
        if reader.read(1)[0] == 0:
            break
    return name

def parse_data(reader: ByteReader) -> Answer:
    a_name = parse_name(reader)
    type = reader.read_int(2)
    _class = reader.read_int(2)
    ttl = reader.read_int(4)
    length = reader.read_int(2)
    rdata = reader.read(length) if type != DNSType.DNS_TYPE_NS.value else parse_name(reader)
    return Answer(a_name, type, _class, ttl, length, rdata)
