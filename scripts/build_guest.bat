@echo off
REM Mosoo Deterministic Guest Build Script for Windows
echo ==================================================
echo  Building Mosoo RISC0 zkVM Guest Binary
echo  Target: riscv32im-risc0-zkvm-elf
echo ==================================================

where docker >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [+] Using Docker container build for 100%% byte-for-byte reproducibility...
    docker build -t mosoo-guest-builder -f docker/Dockerfile.guest .
    docker run --rm mosoo-guest-builder
    goto done
)

where cargo-risczero >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [+] Building locally with cargo-risczero...
    cargo risczero build --manifest-path methods/guest/Cargo.toml --release
    goto done
)

echo [-] Error: Neither Docker nor cargo-risczero was found.
echo     Please install Docker or rzup (https://risczero.com/install)
exit /b 1

:done
echo ==================================================
echo  Deterministic Guest Build Completed Successfully
echo ==================================================
