from enum import Enum

REQUEST_OPTION_CHUNK_STREAM = 0X01  # vmess：是否为标准格式
REQUEST_OPTION_CONNECTION_REUSE = 0X02  # 连接复用
REQUEST_OPTION_CHUNK_MASKING = 0X04  # 元数据混淆
REQUEST_OPTION_GLOBAL_PADDING = 0X08  # 全局填充
REQUEST_OPTION_AUTHENTICATED_LENGTH = 0X10  # 启用认证的数据包长度实验


class Security(Enum):  # 从headers.pb.go导入
    UNKNOWN = 0x00
    LEGACY = 0x01
    AUTO = 0x02
    AES128_GCM = 0x03
    CHACHA20_POLY1305 = 0x04
    NONE = 0x05
    ZERO = 0x06


class Command(Enum):
    NONE = 0x00


class ResponseCommand(Command):
    DYNAMIC = 0x01


class RequestCommand(Command):  # 从headers.go导入
    TCP = 0x01
    UDP = 0x02
    MUX = 0x03


class Header:
    def __init__(self, command: Command, option: int):
        self.command = command
        self.option = option


class RequestHeader(Header):
    def __init__(self, version: int, command: RequestCommand, option: int, security: Security, port: int, address: str):
        super().__init__(command, option)
        self.version = version
        self.security = security
        self.port = port
        self.address = address


class ResponseHeader(Header):
    def __init__(self, command: ResponseCommand, option: int):
        super().__init__(command, option)


if __name__ == '__main__':
    header = RequestHeader()
