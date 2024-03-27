import binascii
import hashlib
from typing import Union

class ID:
    def __init__(self, uuid: Union[str, bytes]):
        if type(uuid) == str:
            self.uuid_str = uuid
            self.uuid_bytes = bytes.fromhex(self.uuid_str.replace('-', ''))
        elif type(uuid) == bytes:
            self.uuid_bytes = uuid
            self.uuid_str = binascii.hexlify(uuid).decode()
        else:
            raise TypeError
        self.cmd_key = hashlib.md5(self.uuid_bytes + 'c48619fe-8f02-49e0-b9e9-edf763e17e21'.encode()).digest()
        return

    def __bytes__(self):
        return self.uuid_bytes

    def __str__(self):
        return self.uuid_str

    def next_id(self):
        buf = self.uuid_bytes + '16167dc8-16b6-4e6d-b8bb-65dd68113a81'.encode()
        new_id = hashlib.md5(buf).digest()
        while new_id == self.uuid_bytes:
            buf += '533eff8a-4113-4b10-b5ce-0f5d76b98cd2'.encode()
            new_id = hashlib.md5(buf).digest()
        return ID(new_id)


def new_alert_ids(primary: ID, alter_id_count: int):
    alter_ids = []
    prev_id = primary
    for i in range(alter_id_count):
        new_id = prev_id.next_id()
        alter_ids.append(new_id)
        prev_id = new_id
    return alter_ids
