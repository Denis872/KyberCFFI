"""
kybercffi - Python CFFI bindings for Kyber post-quantum cryptography

Эта библиотека предоставляет Python обвязку для эталонной реализации
криптографического алгоритма Kyber - победителя конкурса NIST по
пост-квантовой криптографии.

Поддерживаемые варианты:
- Kyber512 (уровень безопасности 1, эквивалент AES-128)
- Kyber768 (уровень безопасности 3, эквивалент AES-192)  
- Kyber1024 (уровень безопасности 5, эквивалент AES-256)

Основные возможности:
- Генерация пар ключей
- Инкапсуляция ключей (шифрование)
- Декапсуляция ключей (расшифрование)
- Кроссплатформенная поддержка (Windows, Linux, macOS)

Примеры использования:
    
    Базовое использование:
    >>> import kybercffi
    >>> kyber = kybercffi.Kyber768()
    >>> pk, sk = kyber.generate_keypair()
    >>> ct, ss = kyber.encapsulate(pk)
    >>> ss2 = kyber.decapsulate(ct, sk)
    >>> assert ss == ss2
    
    Удобные функции:
    >>> from kybercffi import generate_keypair, encapsulate, decapsulate
    >>> pk, sk = generate_keypair(security_level=3)
    >>> ct, ss = encapsulate(pk, security_level=3)
    >>> ss2 = decapsulate(ct, sk, security_level=3)
    
    Фабричный метод:
    >>> kyber = kybercffi.KyberKEM.create(security_level=5)  # Kyber1024

Требования:
- Python >= 3.8
- CFFI >= 1.15.0
- C компилятор (автоматически используется при установке)

Автор: Denis Magnitov <pm13.magnitov@gmail.com>
Лицензия: MIT
Репозиторий: https://github.com/Denis872/KyberCFFI
"""

__version__ = "0.1.0"
__author__ = "Denis Magnitov"
__email__ = "pm13.magnitov@gmail.com"
__license__ = "MIT"
__repository__ = "https://github.com/Denis872/KyberCFFI"

# Импортируем основные классы и функции из kyber.py
try:
    from .kyber import (
        # Основные классы для каждого варианта Kyber
        Kyber512,
        Kyber768, 
        Kyber1024,
        
        # Базовый класс
        KyberBase,
        
        # Фабричный класс для создания экземпляров
        KyberKEM,
        
        # Исключения
        KyberError,
        KyberKeyError,
        KyberEncryptionError,
        KyberDecryptionError,
        
        # Удобные функции для быстрого использования
        generate_keypair,
        encapsulate,
        decapsulate
    )
except ImportError as e:
    # Если импорт не удался, вероятно библиотека не собрана
    import warnings
    warnings.warn(
        f"Не удалось импортировать основные компонены kybercffi: {e}\n"
        f"Возможные причины:\n"
        f"1. Пакет не установлен корректно\n"
        f"2. Отсутствует CFFI: pip install cffi\n"
        f"3. Проблемы с компилятором C\n"
        f"Попробуйте переустановить: pip install --force-reinstall kybercffi",
        RuntimeWarning
    )
    
    # Определяем заглушки для основных классов
    class KyberError(Exception):
        """Базовое исключение Kyber"""
        pass
    
    class KyberKeyError(KyberError):
        """Ошибки ключей"""
        pass
    
    class KyberEncryptionError(KyberError):
        """Ошибки шифрования"""
        pass
    
    class KyberDecryptionError(KyberError):
        """Ошибки расшифрования"""
        pass
    
    # Заглушки для основных классов
    Kyber512 = None
    Kyber768 = None
    Kyber1024 = None
    KyberBase = None
    KyberKEM = None
    generate_keypair = None
    encapsulate = None
    decapsulate = None

# Определяем публичный API - что будет доступно при import *
__all__ = [
    # Основные классы
    "Kyber512",
    "Kyber768", 
    "Kyber1024",
    "KyberBase",
    "KyberKEM",
    
    # Исключения
    "KyberError",
    "KyberKeyError", 
    "KyberEncryptionError",
    "KyberDecryptionError",
    
    # Удобные функции
    "generate_keypair",
    "encapsulate", 
    "decapsulate",
    
    # Метаинформация
    "__version__",
    "__author__",
    "__license__",
    
    # Дополнительные функции
    "get_version_info",
    "get_kyber_info"
]

def get_version_info():
    """
    Возвращает детальную информацию о версии пакета
    
    Returns:
        dict: Словарь с информацией о версии, авторе и зависимостях
    """
    return {
        "version": __version__,
        "author": __author__,
        "email": __email__,
        "license": __license__,
        "repository": __repository__,
        "supported_variants": ["kyber512", "kyber768", "kyber1024"],
        "security_levels": [1, 3, 5],
        "cffi_required": ">=1.15.0",
        "python_required": ">=3.8"
    }

def get_kyber_info():
    """
    Возвращает информацию о всех вариантах Kyber
    
    Returns:
        dict: Подробная информация о каждом варианте Kyber
    """
    if KyberKEM is not None:
        return KyberKEM.get_variant_info()
    else:
        # Возвращаем статическую информацию если модуль не загружен
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

def check_installation():
    """
    Проверяет корректность установки пакета
    
    Returns:
        bool: True если пакет установлен корректно, False иначе
    """
    try:
        # Пытаемся создать экземпляр Kyber768
        if Kyber768 is not None:
            kyber = Kyber768()
            # Пытаемся сгенерировать ключи
            pk, sk = kyber.generate_keypair()
            # Проверяем инкапсуляцию/декапсуляцию
            ct, ss1 = kyber.encapsulate(pk)
            ss2 = kyber.decapsulate(ct, sk)
            return ss1 == ss2
        return False
    except Exception:
        return False

# Информация для отладки
_debug_info = {
    "module_loaded": Kyber768 is not None,
    "version": __version__,
    "cffi_available": False
}

try:
    import cffi
    _debug_info["cffi_available"] = True
    _debug_info["cffi_version"] = cffi.__version__
except ImportError:
    pass 