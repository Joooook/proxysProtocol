import hashlib
import hmac
import random
import time
from common.protocol.id import ID
from common.protocol.headers import *


class Request:
    def __init__(self, header: RequestHeader, data: bytes):
        self.header = header
        self.raw_data = data

class ClientSession():
    # todo:IDHash类还没写
    def __init__(self,is_AEAD:bool,id_hash:IDHash,request_body_key:bytes = None, request_body_iv = None):
        self.is_AEAD=is_AEAD
        self.id_hash=id_hash
        if request_body_key is None:
            self.request_body_key=random.randbytes(16)
        else:
            self.request_body_key=request_body_key
        if request_body_iv is None:
            self.request_body_iv=random.randbytes(16)
        else:
            self.request_body_iv=request_body_iv

        if self.is_AEAD: #AEAD情况
            self.response_body_key = hashlib.sha256(self.request_body_key).digest()[:16]
            self.response_body_iv = hashlib.sha256(self.request_body_iv).digest()[:16]
        else:
            self.response_body_key = hashlib.md5(self.request_body_key).digest()
            self.response_body_iv = hashlib.md5(self.request_body_iv).digest()
    def encode_request_body(self,request):
        if request.header.option & REQUEST_OPTION_CHUNK_MASKING != 0:
            print(hashlib.shake_128(request))
            size = len(request.raw_data)
        else:
            size = len(request.raw_data)
