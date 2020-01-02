#!/usr/bin/python3
# Helpers for glibc system call list processing.
# Copyright (C) 2018-2020 Free Software Foundation, Inc.
# This file is part of the GNU C Library.
#
# The GNU C Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# The GNU C Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with the GNU C Library; if not, see
# <http://www.gnu.org/licenses/>.

import re

import glibcextract

def extract_system_call_name(macro):
    """Convert the macro name (with __NR_) to a system call name."""
    prefix = '__NR_'
    if macro.startswith(prefix):
        return macro[len(prefix):]
    else:
        raise ValueError('invalid system call name: {!r}'.format(macro))

# Matches macros for systme call names.
RE_SYSCALL = re.compile('__NR_.*')

# Some __NR_ constants are not real
RE_PSEUDO_SYSCALL = re.compile(r"""__NR_(
    # Reserved system call.
    (unused|reserved)[0-9]+

    # Pseudo-system call which describes a range.
    |(syscalls|arch_specific_syscall|(OABI_)?SYSCALL_BASE)
    |(|64_|[NO]32_)Linux(_syscalls)?
   )""", re.X)

def kernel_constants(cc):
    """Return a dictionary with the kernel-defined system call numbers.

    This comes from <asm/unistd.h>.

    """
    return {extract_system_call_name(name) : int(value)
            for name, value in glibcextract.compute_macro_consts(
                    '#include <asm/unistd.h>\n'
                    # Regularlize the kernel definitions if necessary.
                    '#include <fixup-asm-unistd.h>',
                    cc, macro_re=RE_SYSCALL, exclude_re=RE_PSEUDO_SYSCALL)
            .items()}

class SyscallNamesList:
    """The list of known system call names.

    glibc keeps a list of system call names.  The <sys/syscall.h>
    header needs to provide a SYS_ name for each __NR_ macro,
    and the generated <bits/syscall.h> header uses an
    architecture-independent list, so that there is a chance that
    system calls arriving late on certain architectures will automatically
    get the expected SYS_ macro.

    syscalls: list of strings with system call names
    kernel_version: tuple of integers; the kernel version given in the file

    """
    def __init__(self, lines):
        self.syscalls = []
        old_name = None
        self.kernel_version = None
        self.__lines = tuple(lines)
        for line in self.__lines:
            line = line.strip()
            if (not line) or line[0] == '#':
                continue
            comps = line.split()
            if len(comps) == 1:
                self.syscalls.append(comps[0])
                if old_name is not None:
                    if comps[0] < old_name:
                        raise ValueError(
                            'name list is not sorted: {!r} < {!r}'.format(
                                comps[0], old_name))
                old_name = comps[0]
                continue
            if len(comps) == 2 and comps[0] == "kernel":
                if self.kernel_version is not None:
                    raise ValueError(
                        "multiple kernel versions: {!r} and !{r}".format(
                            kernel_version, comps[1]))
                self.kernel_version = tuple(map(int, comps[1].split(".")))
                continue
            raise ValueError("invalid line: !r".format(line))
        if self.kernel_version is None:
            raise ValueError("missing kernel version")

    def merge(self, names):
        """Merge sequence NAMES and return the lines of the new file."""
        names = list(set(names) - set(self.syscalls))
        names.sort()
        names.reverse()
        result = []
        def emit_name():
            result.append(names[-1] + "\n")
            del names[-1]

        for line in self.__lines:
            comps = line.strip().split()
            if len(comps) == 1 and not comps[0].startswith("#"):
                # File has a system call at this position.  Insert all
                # the names that come before the name in the file
                # lexicographically.
                while names and names[-1] < comps[0]:
                    emit_name()
            result.append(line)
        while names:
            emit_name()

        return result

def load_arch_syscall_header(path):
    """"Load the system call header form the file PATH.

    The file must consist of lines of this form:

    #define __NR_exit 1

    The file is parsed verbatim, without running it through a C
    preprocessor or parser.  The intent is that the file can be
    readily processed by tools.

    """
    with open(path) as inp:
        result = {}
        old_name = None
        for line in inp:
            line = line.strip()

            # Ignore the initial comment line.
            if line.startswith("/*") and line.endswith("*/"):
                continue

            define, name, number = line.split(' ', 2)
            if define != '#define':
                raise ValueError("invalid syscall header line: {!r}".format(
                    line))
            result[extract_system_call_name(name)] = int(number)

            # Check list order.
            if old_name is not None:
                if name < old_name:
                    raise ValueError(
                        'system call list is not sorted: {!r} < {!r}'.format(
                            name, old_name))
            old_name = name
        return result

def linux_kernel_version(cc):
    """Return the (major, minor) version of the Linux kernel headers."""
    sym_data = ['#include <linux/version.h>', 'START',
                ('LINUX_VERSION_CODE', 'LINUX_VERSION_CODE')]
    val = glibcextract.compute_c_consts(sym_data, cc)['LINUX_VERSION_CODE']
    val = int(val)
    return ((val & 0xff0000) >> 16, (val & 0xff00) >> 8)
