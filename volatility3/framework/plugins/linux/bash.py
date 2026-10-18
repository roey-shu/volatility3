# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a plugin that recovers bash command history
from bash process memory."""

import datetime
import struct
from typing import List

from volatility3.framework import constants, renderers, symbols, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux import bash
from volatility3.plugins import timeliner
from volatility3.plugins.linux import pslist


class Bash(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Recovers bash command history from memory."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 3)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="multi_string_scanner",
                component=scanners.MultiStringScanner,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="bytes_scanner",
                component=scanners.BytesScanner,
                version=(1, 0, 0),
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
        ]

    def _process_is_32bit(self, proc_layer, task, default):
        """Whether a userspace process uses 32-bit pointers, taken from its main executable's
        ELF class. A 64-bit kernel can run 32-bit (compat) processes, whose bash history uses
        32-bit pointers, so the width must follow the process rather than the kernel.

        The main executable is the file backing the VMA that contains ``mm->start_code``; its
        ELF header sits at that file's lowest mapping. Returns ``default`` (the kernel's width)
        if the executable cannot be identified or read."""
        try:
            mm = task.mm
            if not mm or not mm.is_readable():
                return default
            vmas = list(mm.get_vma_iter())

            # identify the executable by the file backing the VMA that holds start_code
            exe_file = None
            try:
                start_code = int(mm.start_code)
            except (AttributeError, exceptions.InvalidAddressException):
                start_code = None
            if start_code:
                for vma in vmas:
                    if vma.vm_file and vma.vm_start <= start_code < vma.vm_end:
                        exe_file = int(vma.vm_file)
                        break
            if exe_file is None:
                return default

            # read e_ident from the executable's lowest mapping (where its ELF header lives)
            exe_vmas = sorted(
                (v for v in vmas if v.vm_file and int(v.vm_file) == exe_file),
                key=lambda v: v.vm_start,
            )
            for vma in exe_vmas:
                header = proc_layer.read(vma.vm_start, 5, pad=True)
                if header[:4] == b"\x7fELF":
                    return header[4] == 1  # e_ident[EI_CLASS]: 1 = ELFCLASS32
        except (exceptions.InvalidAddressException, AttributeError):
            pass
        return default

    def _generator(self, tasks):
        vmlinux = self.context.modules[self.config["kernel"]]
        kernel_32bit = not symbols.symbol_table_is_64bit(
            context=self.context, symbol_table_name=vmlinux.symbol_table_name
        )

        # A 64-bit kernel can host 32-bit (compat) processes, and bash's hist_entry pointer width
        # follows the process, not the kernel; using the kernel's width parses a 32-bit bash wrongly
        # and silently yields no entries. Build each width's symbol table lazily and pick per task
        # from the process's own pointer width (see _process_is_32bit).
        bash_tables = {}

        def bash_table_for(is_32bit):
            if is_32bit not in bash_tables:
                bash_json_file = "bash32" if is_32bit else "bash64"
                table_name = bash.BashIntermedSymbols.create(
                    self.context, self.config_path, "linux", bash_json_file
                )
                ts = self.context.symbol_space.get_type(
                    table_name + constants.BANG + "hist_entry"
                ).relative_child_offset("timestamp")
                bash_tables[is_32bit] = ("I" if is_32bit else "Q", table_name, ts)
            return bash_tables[is_32bit]

        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ["bash", "sh", "dash"]:
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            pack_format, bash_table_name, ts_offset = bash_table_for(
                self._process_is_32bit(proc_layer, task, kernel_32bit)
            )

            bang_addrs = []

            # get task memory sections to be used by scanners
            task_memory_sections = [
                section for section in task.get_process_memory_sections(heap_only=True)
            ]

            # find '#' values on the heap
            for address in proc_layer.scan(
                self.context,
                scanners.BytesScanner(b"#"),
                sections=task_memory_sections,
            ):
                bang_addrs.append(struct.pack(pack_format, address))

            history_entries = []

            if bang_addrs:
                for address, _ in proc_layer.scan(
                    self.context,
                    scanners.MultiStringScanner(bang_addrs),
                    sections=task_memory_sections,
                ):
                    hist = self.context.object(
                        bash_table_name + constants.BANG + "hist_entry",
                        offset=address - ts_offset,
                        layer_name=proc_layer_name,
                    )

                    if hist.is_valid():
                        history_entries.append(hist)

            for hist in sorted(history_entries, key=lambda x: x.get_time_as_integer()):
                yield (
                    0,
                    (task.pid, task_name, hist.get_time_object(), hist.get_command()),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("CommandTime", datetime.datetime),
                ("Command", str),
            ],
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"], filter_func=filter_func
                )
            ),
        )

    def generate_timeline(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        for row in self._generator(
            pslist.PsList.list_tasks(
                self.context, self.config["kernel"], filter_func=filter_func
            )
        ):
            _depth, row_data = row
            description = f'{row_data[0]} ({row_data[1]}): "{row_data[3]}"'
            yield (description, timeliner.TimeLinerType.CREATED, row_data[2])
