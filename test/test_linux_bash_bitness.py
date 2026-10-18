"""linux.bash must parse each process at its own pointer width, not the kernel's."""

from types import SimpleNamespace

import pytest

from volatility3.framework import contexts
from volatility3.framework.layers import physical
from volatility3.plugins.linux import bash

ELF32 = b"\x7fELF\x01"
ELF64 = b"\x7fELF\x02"

EXE_FILE = 0x1111
LIB_FILE = 0x2222


def _vma(start, end, vm_file):
    return SimpleNamespace(vm_start=start, vm_end=end, vm_file=vm_file)


def _layer(headers):
    """A process layer with the given 5-byte headers at the given offsets."""
    buffer = bytearray(0x4000)
    for offset, header in headers.items():
        buffer[offset : offset + len(header)] = header
    context = contexts.Context()
    context.layers.add_layer(
        physical.BufferDataLayer(context, "memory", "memory", bytes(buffer))
    )
    return context.layers["memory"]


def _task(vmas, start_code=0x1900, readable=True):
    mm = SimpleNamespace(
        start_code=start_code,
        is_readable=lambda: readable,
        get_vma_iter=lambda: iter(vmas),
    )
    return SimpleNamespace(mm=mm)


def _process_is_32bit(layer, task, default):
    # The helper does not use plugin state, so no configured plugin instance is needed.
    return bash.Bash._process_is_32bit(None, layer, task, default)


# The executable's ELF header is at its lowest mapping (0x1000), not at the VMA holding
# start_code (0x1800). A library with the other ELF class is mapped too, and VMAs are listed
# out of address order, so the helper must pick the executable and its lowest mapping.
@pytest.mark.parametrize("kernel_32bit", [False, True], ids=["kernel64", "kernel32"])
@pytest.mark.parametrize(
    "exe_header, lib_header, expected",
    [(ELF32, ELF64, True), (ELF64, ELF32, False)],
    ids=["exe32", "exe64"],
)
def test_width_follows_executable(kernel_32bit, exe_header, lib_header, expected):
    layer = _layer({0x1000: exe_header, 0x3000: lib_header})
    vmas = [
        _vma(0x3000, 0x4000, LIB_FILE),
        _vma(0x1800, 0x2000, EXE_FILE),
        _vma(0x2000, 0x3000, None),
        _vma(0x1000, 0x1800, EXE_FILE),
    ]
    assert _process_is_32bit(layer, _task(vmas), kernel_32bit) is expected


@pytest.mark.parametrize("default", [False, True], ids=["kernel64", "kernel32"])
@pytest.mark.parametrize(
    "task",
    [
        SimpleNamespace(mm=None),
        _task([_vma(0x1000, 0x2000, EXE_FILE)], readable=False),
        _task([_vma(0x1000, 0x2000, EXE_FILE)], start_code=0),
        _task([_vma(0x1000, 0x2000, None)]),
        _task([_vma(0x3000, 0x4000, EXE_FILE)]),
    ],
    ids=[
        "no-mm",
        "mm-unreadable",
        "no-start-code",
        "anonymous-code",
        "start-code-unmapped",
    ],
)
def test_falls_back_to_kernel_width(task, default):
    layer = _layer({0x1000: ELF32, 0x3000: ELF64})
    assert _process_is_32bit(layer, task, default) is default


@pytest.mark.parametrize("default", [False, True], ids=["kernel64", "kernel32"])
def test_falls_back_when_no_elf_header(default):
    layer = _layer({})
    vmas = [_vma(0x1000, 0x2000, EXE_FILE)]
    assert _process_is_32bit(layer, _task(vmas), default) is default
