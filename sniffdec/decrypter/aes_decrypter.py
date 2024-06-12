from Crypto.Cipher import AES
from sniffdec.decrypter.base import IDecrypter

class AesDecrypter(IDecrypter):
    def decrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        return self._aes_decrypt(data, key, iv)

    def _aes_decrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(data)