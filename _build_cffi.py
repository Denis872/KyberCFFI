#!/usr/bin/env python3
"""
CFFI builder for kybercffi - automatically called during package installation

This module creates CFFI bindings for all Kyber variants (512, 768, 1024)
when installing the package via pip install. Supports cross-platform compilation.

Author: Denis Magnitov <pm13.magnitov@gmail.com>
"""

import os
import platform
from cffi import FFI

# Define project root directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KYBER_REF_DIR = os.path.join(PROJECT_ROOT, "kybercffi/kyber", "ref")


def get_platform_settings():
    """
    Determines compilation parameters depending on the platform

    Returns:
        tuple: (extra_compile_args, libraries, extra_link_args, define_macros)
    """
    system = platform.system()

    if system == "Windows":
        # Parameters for Windows/MSVC
        extra_compile_args = ["/O2"]  # Removed /Wall - too many warnings
        libraries = ["advapi32"]  # For CryptAcquireContext
        extra_link_args = []
        define_macros = [("_WIN32", None)]

    elif system == "Linux":
        # Parameters for Linux/GCC
        extra_compile_args = [
            "-O3",
            "-fomit-frame-pointer",
            "-Wall",
            "-Wextra",
            "-fPIC"  # Important for creating shared libraries
        ]
        libraries = []
        extra_link_args = ["-z", "noexecstack"]  # Security
        define_macros = [("__linux__", None), ("_GNU_SOURCE", None)]

    elif system == "Darwin":  # macOS
        # Parameters for macOS/Clang
        extra_compile_args = [
            "-O3",
            "-fomit-frame-pointer",
            "-Wall",
            "-Wextra",
            "-fPIC"
        ]
        libraries = []
        extra_link_args = []
        define_macros = []

    else:
        # Parameters for other Unix systems
        extra_compile_args = [
            "-O3",
            "-fomit-frame-pointer",
            "-Wall",
            "-fPIC"
        ]
        libraries = []
        extra_link_args = []
        define_macros = []

    return extra_compile_args, libraries, extra_link_args, define_macros


def get_source_files():
    """
    Returns list of source files for compilation (relative paths for setuptools)

    Returns:
        list: List of relative paths to C files
    """
    base_files = [
        "kem.c",
        "indcpa.c",
        "polyvec.c",
        "poly.c",
        "ntt.c",
        "cbd.c",
        "reduce.c",
        "verify.c",
        "fips202.c",
        "symmetric-shake.c",
        "randombytes.c"
    ]

    # Return relative paths for setuptools
    return [os.path.join("kyber", "ref", filename) for filename in base_files]


def get_source_files_absolute():
    """
    Returns list of source files with absolute paths (for existence checking)

    Returns:
        list: List of absolute paths to C files
    """
    base_files = [
        "kem.c",
        "indcpa.c",
        "polyvec.c",
        "poly.c",
        "ntt.c",
        "cbd.c",
        "reduce.c",
        "verify.c",
        "fips202.c",
        "symmetric-shake.c",
        "randombytes.c"
    ]

    # Return absolute paths for checking
    return [os.path.join(KYBER_REF_DIR, filename) for filename in base_files]


def create_kyber_ffibuilder(variant_name, k_value):
    """
    Creates FFI builder for specific Kyber variant

    Args:
        variant_name (str): Variant name ('kyber512', 'kyber768', 'kyber1024')
        k_value (int): K parameter value (2, 3, 4)

    Returns:
        FFI: Configured FFI builder
    """
    ffibuilder = FFI()

    # Define C interface
    ffibuilder.cdef(f"""
        // Functions for {variant_name}
        int pqcrystals_{variant_name}_ref_keypair(uint8_t *pk, uint8_t *sk);
        int pqcrystals_{variant_name}_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
        int pqcrystals_{variant_name}_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
    """)

    # Create C code for wrapper (use relative paths in #include)
    c_source = f"""
    #define KYBER_K {k_value}

    #include "api.h"
    #include "kem.h"
    #include "params.h"
    """

    # Get platform settings
    extra_compile_args, libraries, extra_link_args, define_macros = get_platform_settings()

    # Prepare macros for compilation
    compile_macros = define_macros + [("KYBER_K", k_value)]

    # Get source files (relative paths for setuptools/pip installation)
    source_files = get_source_files()

    # Set source code with correct macros
    ffibuilder.set_source(
        f"_kyber_{variant_name}",  # Module in same directory as builder
        c_source,
        sources=source_files,  # Relative paths from kybercffi package root
        include_dirs=["kyber/ref"],  # Relative path from kybercffi package root
        define_macros=compile_macros,
        extra_compile_args=extra_compile_args,
        libraries=libraries,
        extra_link_args=extra_link_args
    )

    return ffibuilder


# Create FFI builders for all Kyber variants
# These objects will be used by setuptools for automatic building

# Kyber512 (security level 1)
ffibuilder_kyber512 = create_kyber_ffibuilder("kyber512", 2)

# Kyber768 (security level 3)
ffibuilder_kyber768 = create_kyber_ffibuilder("kyber768", 3)

# Kyber1024 (security level 5)
ffibuilder_kyber1024 = create_kyber_ffibuilder("kyber1024", 4)

# List of all builders for automatic building
ffi_builders = [
    ffibuilder_kyber512,
    ffibuilder_kyber768,
    ffibuilder_kyber1024
]


def verify_source_files():
    """
    Checks existence of all source files

    Returns:
        bool: True if all files exist, False otherwise
    """
    source_files = get_source_files_absolute()
    missing_files = []

    print(f"Checking source files in: {KYBER_REF_DIR}")

    for src in source_files:
        if not os.path.exists(src):
            missing_files.append(src)
        else:
            print(f"   Found: {os.path.basename(src)}")

    if missing_files:
        print("Missing source files:")
        for f in missing_files:
            print(f"   {f}")
        return False

    # Check header files
    required_headers = ["api.h", "kem.h", "params.h"]
    for header in required_headers:
        header_path = os.path.join(KYBER_REF_DIR, header)
        if not os.path.exists(header_path):
            print(f"Missing header: {header_path}")
            return False
        else:
            print(f"   Found: {header}")

    return True


def build_all_variants():
    """
    Builds all Kyber variants (for manual execution)

    Returns:
        bool: True if build is successful, False otherwise
    """
    print(f"Project root: {PROJECT_ROOT}")
    print(f"Kyber folder: {KYBER_REF_DIR}")

    if not verify_source_files():
        return False

    system = platform.system()
    print(f"Building kybercffi for {system}...")

    variants = [
        ("kyber512", ffibuilder_kyber512),
        ("kyber768", ffibuilder_kyber768),
        ("kyber1024", ffibuilder_kyber1024)
    ]

    for variant_name, ffibuilder in variants:
        print(f"   Building {variant_name}...")
        try:
            ffibuilder.compile(verbose=False)  # Enable verbose for debugging
            print(f"   Success: {variant_name} built successfully")
        except Exception as e:
            print(f"   Error building {variant_name}: {e}")
            return False

    print(f"All Kyber variants successfully built for {system}!")
    return True


# For compatibility with direct execution
if __name__ == "__main__":
    print("CFFI builder for kybercffi")
    print("=" * 50)

    success = build_all_variants()
    if not success:
        import sys

        sys.exit(1)

    print("Build completed successfully!")
    print("\nTo use:")
    print("  import kybercffi")
    print("  kyber = kybercffi.Kyber768()") 