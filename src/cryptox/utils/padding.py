class PKCS7:
    @staticmethod
    def pad(data: bytes, block_size: int = 16) -> bytes:
        if block_size < 2 or block_size > 255:
            raise ValueError("Block size must be between 2 and 255")
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def unpad(data: bytes, block_size: int = 16) -> bytes:
        if len(data) == 0:
            raise ValueError("Cannot unpad empty data")
        if len(data) % block_size != 0:
            raise ValueError("Data length must be a multiple of block size")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > block_size:
            raise ValueError("Invalid padding")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Invalid padding bytes")
        return data[:-pad_len]

    @staticmethod
    def is_padded(data: bytes, block_size: int = 16) -> bool:
        try:
            PKCS7.unpad(data, block_size)
            return True
        except ValueError:
            return False


def pad(data: bytes, block_size: int = 16) -> bytes:
    return PKCS7.pad(data, block_size)


def unpad(data: bytes, block_size: int = 16) -> bytes:
    return PKCS7.unpad(data, block_size)
