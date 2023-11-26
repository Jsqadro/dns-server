import threading
import socket
import struct
import os
from Parser import parse_package
import cachetools.func

MAX_WORKERS = 4
CACHE_SIZE = 128
CACHE_TTL = 10 * 60
DNS_PORT = 53
HEADER_FLAGS = b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
ANSWER_FLAGS = b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'

class DNS_Server:
    def __init__(self, host, port):
        self.address = (host, port)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def run(self):
        self.server_socket.bind(self.address)
        while True:
            data, address = self.server_socket.recvfrom(4096)
            threading.Thread(target=self.process_request, args=(data, address)).start()

    def process_request(self, data, address):
        try:
            package = parse_package(data)
            if not package.questions:
                return
            question = package.questions[0]
            request_id = package.header['ID']

            if 'multiply' in question.NAME:
                answer = self.create_answer(question.NAME, request_id, multiply(question.NAME))
            else:
                answer = self.get_ip(question.NAME, request_id)

            self.server_socket.sendto(answer, address)
        except Exception as e:
            logging.error(f"Error handling request: {e}")

    @cachetools.func.ttl_cache(maxsize=CACHE_SIZE, ttl=CACHE_TTL)
    def multiply(self, name):
        result = 1
        for number in name[:name.find('.multiply')].split('.'):
            result = (result * int(number)) % 256
        return '127.0.0.' + str(result)

    def get_ip(self, name, request_id):
        ip = '198.41.0.4'
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ips = []

        while ips:
            request = self.create_header_and_question(name, request_id)
            my_socket.sendto(request, (ip, DNS_PORT))

            response, addr = my_socket.recvfrom(4096)
            package = parse_package(response)

            for answer in package.answers:
                if answer.TYPE == 1:
                    return response

            for data_list in (package.additional, package.authorities):
                for item in data_list:
                    if item.TYPE == 1:
                        ips.append(item.data)

            ip = ips.pop(0)

    def create_header_and_question(self, name, req_id, flags_and_below=HEADER_FLAGS):
        request = bytearray()
        request += struct.pack('!H', req_id) + flags_and_below
        request += self.create_question(name)
        return request

    @cachetools.func.ttl_cache(maxsize=CACHE_SIZE, ttl=CACHE_TTL)
    def create_question(self, name):
        request = bytearray()
        for part in name.split('.'):
            request += struct.pack('!B', len(part.encode()))
            request += part.encode()
        request += struct.pack('!B2H', 0, 1, 1)
        return request

    def create_answer(self, name, req_id, ip):
        answer = self.create_header_and_question(name, req_id, ANSWER_FLAGS)
        answer += self.create_part_of_answer(name, ip)
        return answer

    @cachetools.func.ttl_cache(maxsize=CACHE_SIZE, ttl=CACHE_TTL)
    def create_part_of_answer(self, name, ip):
        answer = bytearray()
        ip_data = struct.pack('!4B', *[int(part) for part in ip.split('.')])
        for word in name.split('.'):
            answer += struct.pack('!B', len(word.encode()))
            answer += word.encode()
        answer += struct.pack('!B2HIH', 0, 1, 1, 60, len(ip_data)) + ip_data
        return answer

def main():
    dns_server = DNS_Server('127.0.0.1', DNS_PORT)
    dns_server.run()

if __name__ == '__main__':
    main()
