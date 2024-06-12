class IDecrypter:
    def decrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        raise NotImplementedError("decrypt() must be implemented in subclass")