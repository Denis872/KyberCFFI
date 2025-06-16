#!/usr/bin/env python3
"""
Python обвязка для Kyber KEM (Key Encapsulation Mechanism)
Поддерживает все три варианта безопасности: Kyber512, Kyber768, Kyber1024
"""

import os
import secrets
from typing import Tuple, Optional
from cffi import FFI

class KyberError(Exception):
    """Базовый класс исключений для Kyber"""
    pass

class KyberKeyError(KyberError):
    """Ошибки связанные с ключами"""
    pass

class KyberEncryptionError(KyberError):
    """Ошибки шифрования"""
    pass

class KyberDecryptionError(KyberError):
    """Ошибки расшифрования"""
    pass

class KyberBase:
    """Базовый класс для всех вариантов Kyber"""
    
    def __init__(self, variant: str):
        """
        Инициализация базового класса Kyber
        
        Args:
            variant: Вариант Kyber ('kyber512', 'kyber768', 'kyber1024')
        """
        self.variant = variant
        self._ffi = None
        self._lib = None
        self._load_library()
    
    def _load_library(self):
        """Загружает скомпилированную библиотеку для конкретного варианта"""
        try:
            if self.variant == "kyber512":
                import _kyber_kyber512
                self._lib = _kyber_kyber512.lib
                self._ffi = _kyber_kyber512.ffi
                self.SECRETKEY_BYTES = 1632
                self.PUBLICKEY_BYTES = 800
                self.CIPHERTEXT_BYTES = 768
                self.SHARED_SECRET_BYTES = 32
                self._keypair_func = self._lib.pqcrystals_kyber512_ref_keypair
                self._enc_func = self._lib.pqcrystals_kyber512_ref_enc
                self._dec_func = self._lib.pqcrystals_kyber512_ref_dec
                
            elif self.variant == "kyber768":
                import _kyber_kyber768
                self._lib = _kyber_kyber768.lib
                self._ffi = _kyber_kyber768.ffi
                self.SECRETKEY_BYTES = 2400
                self.PUBLICKEY_BYTES = 1184
                self.CIPHERTEXT_BYTES = 1088
                self.SHARED_SECRET_BYTES = 32
                self._keypair_func = self._lib.pqcrystals_kyber768_ref_keypair
                self._enc_func = self._lib.pqcrystals_kyber768_ref_enc
                self._dec_func = self._lib.pqcrystals_kyber768_ref_dec
                
            elif self.variant == "kyber1024":
                import _kyber_kyber1024
                self._lib = _kyber_kyber1024.lib
                self._ffi = _kyber_kyber1024.ffi
                self.SECRETKEY_BYTES = 3168
                self.PUBLICKEY_BYTES = 1568
                self.CIPHERTEXT_BYTES = 1568
                self.SHARED_SECRET_BYTES = 32
                self._keypair_func = self._lib.pqcrystals_kyber1024_ref_keypair
                self._enc_func = self._lib.pqcrystals_kyber1024_ref_enc
                self._dec_func = self._lib.pqcrystals_kyber1024_ref_dec
            else:
                raise KyberError(f"Неподдерживаемый вариант Kyber: {variant}")
                
        except ImportError as e:
            raise KyberError(f"Не удалось загрузить библиотеку для {self.variant}. "
                           f"Убедитесь, что выполнили kyber-build.py: {e}")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Генерирует пару ключей (открытый, секретный)
        
        Returns:
            Tuple[bytes, bytes]: (публичный_ключ, секретный_ключ)
        """
        # Выделяем память для ключей
        pk = self._ffi.new(f"uint8_t[{self.PUBLICKEY_BYTES}]")
        sk = self._ffi.new(f"uint8_t[{self.SECRETKEY_BYTES}]")
        
        # Генерируем ключи
        result = self._keypair_func(pk, sk)
        if result != 0:
            raise KyberKeyError(f"Ошибка генерации ключей: код {result}")
        
        # Конвертируем в bytes
        public_key = bytes(self._ffi.buffer(pk, self.PUBLICKEY_BYTES))
        secret_key = bytes(self._ffi.buffer(sk, self.SECRETKEY_BYTES))
        
        return public_key, secret_key
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Инкапсулирует общий секрет с использованием открытого ключа
        
        Args:
            public_key: Открытый ключ (bytes)
            
        Returns:
            Tuple[bytes, bytes]: (зашифрованный_текст, общий_секрет)
        """
        if len(public_key) != self.PUBLICKEY_BYTES:
            raise KyberEncryptionError(
                f"Неверный размер открытого ключа: ожидается {self.PUBLICKEY_BYTES}, "
                f"получено {len(public_key)}"
            )
        
        # Выделяем память
        ct = self._ffi.new(f"uint8_t[{self.CIPHERTEXT_BYTES}]")
        ss = self._ffi.new(f"uint8_t[{self.SHARED_SECRET_BYTES}]")
        pk = self._ffi.new(f"uint8_t[{self.PUBLICKEY_BYTES}]")
        
        # Копируем открытый ключ
        self._ffi.memmove(pk, public_key, self.PUBLICKEY_BYTES)
        
        # Выполняем инкапсуляцию
        result = self._enc_func(ct, ss, pk)
        if result != 0:
            raise KyberEncryptionError(f"Ошибка инкапсуляции: код {result}")
        
        # Конвертируем в bytes
        ciphertext = bytes(self._ffi.buffer(ct, self.CIPHERTEXT_BYTES))
        shared_secret = bytes(self._ffi.buffer(ss, self.SHARED_SECRET_BYTES))
        
        return ciphertext, shared_secret
    
    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Декапсулирует общий секрет с использованием секретного ключа
        
        Args:
            ciphertext: Зашифрованный текст (bytes)
            secret_key: Секретный ключ (bytes)
            
        Returns:
            bytes: Общий секрет
        """
        if len(ciphertext) != self.CIPHERTEXT_BYTES:
            raise KyberDecryptionError(
                f"Неверный размер зашифрованного текста: ожидается {self.CIPHERTEXT_BYTES}, "
                f"получено {len(ciphertext)}"
            )
        
        if len(secret_key) != self.SECRETKEY_BYTES:
            raise KyberDecryptionError(
                f"Неверный размер секретного ключа: ожидается {self.SECRETKEY_BYTES}, "
                f"получено {len(secret_key)}"
            )
        
        # Выделяем память
        ss = self._ffi.new(f"uint8_t[{self.SHARED_SECRET_BYTES}]")
        ct = self._ffi.new(f"uint8_t[{self.CIPHERTEXT_BYTES}]")
        sk = self._ffi.new(f"uint8_t[{self.SECRETKEY_BYTES}]")
        
        # Копируем данные
        self._ffi.memmove(ct, ciphertext, self.CIPHERTEXT_BYTES)
        self._ffi.memmove(sk, secret_key, self.SECRETKEY_BYTES)
        
        # Выполняем декапсуляцию
        result = self._dec_func(ss, ct, sk)
        if result != 0:
            raise KyberDecryptionError(f"Ошибка декапсуляции: код {result}")
        
        # Конвертируем в bytes
        shared_secret = bytes(self._ffi.buffer(ss, self.SHARED_SECRET_BYTES))
        
        return shared_secret

class Kyber512(KyberBase):
    """Kyber512 - уровень безопасности 1 (эквивалент AES-128)"""
    
    def __init__(self):
        super().__init__("kyber512")

class Kyber768(KyberBase):
    """Kyber768 - уровень безопасности 3 (эквивалент AES-192)"""
    
    def __init__(self):
        super().__init__("kyber768")

class Kyber1024(KyberBase):
    """Kyber1024 - уровень безопасности 5 (эквивалент AES-256)"""
    
    def __init__(self):
        super().__init__("kyber1024")

class KyberKEM:
    """Удобный интерфейс для работы с Kyber KEM"""
    
    @staticmethod
    def create(security_level: int = 3) -> KyberBase:
        """
        Создает экземпляр Kyber с указанным уровнем безопасности
        
        Args:
            security_level: Уровень безопасности (1, 3, или 5)
            
        Returns:
            KyberBase: Экземпляр соответствующего класса Kyber
        """
        if security_level == 1:
            return Kyber512()
        elif security_level == 3:
            return Kyber768()
        elif security_level == 5:
            return Kyber1024()
        else:
            raise KyberError(f"Неподдерживаемый уровень безопасности: {security_level}. "
                           f"Поддерживаются: 1 (Kyber512), 3 (Kyber768), 5 (Kyber1024)")
    
    @staticmethod
    def get_variant_info():
        """Возвращает информацию о всех вариантах Kyber"""
        return {
            "kyber512": {
                "security_level": 1,
                "equivalent": "AES-128",
                "public_key_bytes": 800,
                "secret_key_bytes": 1632,
                "ciphertext_bytes": 768,
                "shared_secret_bytes": 32
            },
            "kyber768": {
                "security_level": 3,
                "equivalent": "AES-192", 
                "public_key_bytes": 1184,
                "secret_key_bytes": 2400,
                "ciphertext_bytes": 1088,
                "shared_secret_bytes": 32
            },
            "kyber1024": {
                "security_level": 5,
                "equivalent": "AES-256",
                "public_key_bytes": 1568,
                "secret_key_bytes": 3168,
                "ciphertext_bytes": 1568,
                "shared_secret_bytes": 32
            }
        }

# Удобные функции для быстрого использования
def generate_keypair(security_level: int = 3) -> Tuple[bytes, bytes]:
    """Генерирует пару ключей с указанным уровнем безопасности"""
    kyber = KyberKEM.create(security_level)
    return kyber.generate_keypair()

def encapsulate(public_key: bytes, security_level: int = 3) -> Tuple[bytes, bytes]:
    """Инкапсулирует общий секрет"""
    kyber = KyberKEM.create(security_level)
    return kyber.encapsulate(public_key)

def decapsulate(ciphertext: bytes, secret_key: bytes, security_level: int = 3) -> bytes:
    """Декапсулирует общий секрет"""
    kyber = KyberKEM.create(security_level)
    return kyber.decapsulate(ciphertext, secret_key) 