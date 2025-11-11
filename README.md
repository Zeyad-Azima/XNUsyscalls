# XNUSyscalls

<center><img width="562" height="730" alt="image" src="https://github.com/user-attachments/assets/5680543b-8486-4c9a-9a07-34f0af5d6a93" /></center>

A comprehensive command-line tool for analyzing and looking up XNU kernel system calls across all syscall classes for shellcode development.


## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Syscall Classes](#syscall-classes)
- [Command Options](#command-options)
- [Examples](#examples)
- [Null-Byte Avoidance](#null-byte-avoidance)
- [Function Arguments](#function-arguments)
- [Search Functionality](#search-functionality)
- [Assembly Output](#assembly-output)

## Overview

The XNU Syscall Lookup Tool (`XNUsyscalls.py`) is designed for security researchers, reverse engineers, and kernel developers working with Apple's XNU kernel. It provides comprehensive analysis of all 6 syscall classes in XNU, with special features for shellcode development including null-byte avoidance techniques.

### Syscall Statistics
Based on comprehensive source code analysis:
- **Class 0 (NONE)**: 0 syscalls (invalid)
- **Class 1 (MACH)**: 50 Mach traps (IPC, VM, ports, scheduling)
- **Class 2 (UNIX)**: 669 BSD syscalls (~454 active, ~215 deprecated)
- **Class 3 (MDEP)**: 4-6 machine-dependent calls (x86 only)
- **Class 4 (DIAG)**: 26 diagnostic calls (x86 only)
- **Class 5 (IPC)**: 0 syscalls (reserved but unused)

**Total**: ~530-535 active user-callable syscalls across all classes

## Features

- ✅ **Complete syscall coverage** across all 6 XNU syscall classes
- ✅ **Individual syscall lookup** by number for each class
- ✅ **String-based search** functionality for finding syscalls by name
- ✅ **Function arguments parsing** directly from syscall definitions
- ✅ **Assembly code generation** with beautiful ASCII art boxes
- ✅ **Null-byte avoidance** using `bts` instruction for shellcode development
- ✅ **Colorized output** for better readability
- ✅ **Class listing** functionality to browse all syscalls in a class
- ✅ **Comprehensive argument tables** with position, type, and name information

## Installation

### Prerequisites
- Python 3.6 or later
- XNU source code

### Optional Dependencies
```bash
pip install tabulate  # For enhanced table formatting
```

### Setup
1. Download your XNU version from https://opensource.apple.com/releases/
2. Place `XNUsyscalls.py` in the XNU source root directory
3. Make the script executable:
```bash
chmod +x XNUsyscalls.py
```

## Usage

```bash
python3 XNUsyscalls.py [OPTIONS]
```

The script must be run from the XNU source root directory where `bsd/kern/syscalls.master` exists.

## Syscall Classes

XNU organizes system calls into 6 classes, each with a specific purpose:

| Class | Name | Description | Syscall Value Format |
|-------|------|-------------|---------------------|
| 0 | NONE | Invalid/unused | N/A |
| 1 | MACH | Mach kernel services (IPC, VM, etc.) | `0x1XXXXXX` |
| 2 | UNIX | POSIX/BSD system calls | `0x2XXXXXX` |
| 3 | MDEP | Machine-dependent calls | `0x3XXXXXX` |
| 4 | DIAG | Diagnostic/debugging calls | `0x4XXXXXX` |
| 5 | IPC | Reserved (unused in current XNU) | `0x5XXXXXX` |

### Syscall Value Calculation
Syscall values are calculated using: `(class << 24) | syscall_number`

## Command Options

### Individual Lookup Options
- `-b, --bsd NUM` - Lookup BSD/Unix syscall by number (class 2)
- `-m, --mach NUM` - Lookup Mach syscall by number (class 1)
- `-md, --machdep NUM` - Lookup machine-dependent call by number (class 3)
- `-d, --diag NUM` - Lookup diagnostic call by number (class 4)
- `-i, --ipc NUM` - Lookup IPC syscall by number (class 5)

### Search Options
- `-sb, --search-bsd STRING` - Search BSD syscalls by function name
- `-sm, --search-mach STRING` - Search Mach syscalls by function name
- `-smd, --search-machdep STRING` - Search machine-dependent calls by function name
- `-sd, --search-diag STRING` - Search diagnostic calls by function name
- `-si, --search-ipc STRING` - Search IPC syscalls by function name

### Class Listing Options
- `--syscalls CLASS, -sc CLASS` - List all syscalls in a class (0-5)

### Modifier Options
- `--args` - Show function arguments table
- `-nb, --no-nulls` - Generate null-byte-free assembly using bts instruction

## Examples

### Basic Syscall Lookup

```bash
# Look up BSD syscall 59 (execve)
python3 XNUsyscalls.py -b 59
```
Output:
```
syscall class: UNIX
syscall name: execve()
syscall value: 0x200003B

┌────────────────────┐
│ mov rax, 0x200003B │
│      syscall       │
└────────────────────┘
```

### Syscall with Arguments

```bash
# Look up execve with argument table
python3 XNUsyscalls.py -b 59 --args
```
Output:
```
syscall class: UNIX
syscall name: execve()
syscall value: 0x200003B

Function Arguments:
Pos  Type                           Name
──── ────────────────────────────── ───────────────
1    char *                         fname
2    char **                        argp
3    char **                        envp

┌────────────────────┐
│ mov rax, 0x200003B │
│      syscall       │
└────────────────────┘
```

### Mach Syscall Lookup

```bash
# Look up Mach message trap
python3 XNUsyscalls.py -m 31 --args
```
Output:
```
syscall class: MACH
syscall name: mach_msg_trap()
syscall value: 0x100001F

Function Arguments:
Pos  Type                           Name
──── ────────────────────────────── ───────────────
1    mach_msg_header_t *            msg
2    mach_msg_option_t              option
3    mach_msg_size_t                send_size
4    mach_msg_size_t                rcv_size
5    mach_port_name_t               rcv_name
6    mach_msg_timeout_t             timeout
7    mach_port_name_t               notify

┌────────────────────┐
│ mov rax, 0x100001F │
│      syscall       │
└────────────────────┘
```

### Search Functionality

```bash
# Search for BSD syscalls containing "exec"
python3 XNUsyscalls.py -sb exec
```
Output:
```
Found 3 UNIX syscall(s) matching 'exec':
============================================================
Number: 59
Name: execve()
Value: 0x200003B

┌────────────────────┐
│ mov rax, 0x200003B │
│      syscall       │
└────────────────────┘

Number: 152
Name: setprivexec()
Value: 0x2000098

┌────────────────────┐
│ mov rax, 0x2000098 │
│      syscall       │
└────────────────────┘

Number: 380
Name: __mac_execve()
Value: 0x200017C

┌────────────────────┐
│ mov rax, 0x200017C │
│      syscall       │
└────────────────────┘
```

### Class Listing

```bash
# List all Mach syscalls
python3 XNUsyscalls.py --syscalls 1
```

```bash
# List all BSD syscalls
python3 XNUsyscalls.py -sc 2
```

## Null-Byte Avoidance

One of the most powerful features for shellcode development is the null-byte avoidance technique using the `bts` (bit test and set) instruction.

### The Problem
Many syscall values contain null bytes when represented as immediate values:
- `execve` (BSD syscall 59) = `0x200003B` contains null bytes
- `mach_msg_trap` (Mach syscall 31) = `0x100001F` contains null bytes

### The Solution
The tool implements a technique that avoids null bytes by:
1. Using `push` to place the syscall number (small value) on the stack
2. Using `pop rax` to load it into RAX
3. Using `bts` to set the appropriate class bits
4. Calling `syscall`

### Usage

```bash
# Generate null-byte-free assembly for execve
python3 XNUsyscalls.py -b 59 -nb
```
Output:
```
syscall class: UNIX
syscall name: execve()
syscall value: 0x200003B

┌──────────────────┐
│     push 59      │
│     pop rax      │
│   bts rax, 25    │
│     syscall      │
└──────────────────┘
```

### Technical Details

The `bts` instruction sets specific bits to transform the syscall number into the full syscall value:

- **BSD syscalls (class 2)**: `bts rax, 25` sets bit 25 (2 << 24)
- **Mach syscalls (class 1)**: `bts rax, 24` sets bit 24 (1 << 24)
- **Machine-dependent (class 3)**: `bts rax, 24` and `bts rax, 25` (3 << 24)

### Binary Representation Example

For BSD syscall 59 (execve):
```
Original value (59):     0000000000000000000000000000000000000000000000000000000000111011
Target value (0x200003B): 0000000000000000000000000000000000000010000000000000000000111011
                                                       ^
                                                   bit 25 set
```

## Function Arguments

The tool parses function arguments directly from syscall definitions in the XNU source code.

### Argument Information
For each argument, the tool displays:
- **Position**: Argument order (1, 2, 3, ...)
- **Type**: C data type (int, char *, mach_port_name_t, etc.)
- **Name**: Parameter name from the function signature

### Supported Argument Types
- Basic C types: `int`, `long`, `void *`
- XNU-specific types: `user_addr_t`, `user_size_t`, `mach_port_name_t`
- Pointer types: `char *`, `char **`, `struct stat *`
- Complex types: `mach_msg_header_t *`, `union ldt_entry *`

### Examples

```bash
# Show arguments for read() syscall
python3 XNUsyscalls.py -b 3 --args
```
```
Function Arguments:
Pos  Type                           Name
──── ────────────────────────────── ───────────────
1    int                            fd
2    user_addr_t                    cbuf
3    user_size_t                    nbyte
```

## Search Functionality

The search feature allows finding syscalls by partial name matching.

### Search Features
- **Case-insensitive**: Searches work regardless of case
- **Substring matching**: Finds any syscall containing the search term
- **Excludes deprecated**: Automatically filters out `enosys`, `nosys`, and old syscalls
- **All classes supported**: Search across any syscall class

### Search Examples

```bash
# Find all syscalls related to files
python3 XNUsyscalls.py -sb file

# Find all Mach syscalls related to ports
python3 XNUsyscalls.py -sm port

# Find all syscalls containing "msg" with null-byte-free assembly
python3 XNUsyscalls.py -sm msg -nb

# Case-insensitive search
python3 XNUsyscalls.py -sb EXIT  # finds exit()
```

## Assembly Output

Every syscall lookup displays a beautiful ASCII art box containing the assembly code needed to invoke the syscall.

### Standard Assembly
```
┌────────────────────┐
│ mov rax, 0x200003B │
│      syscall       │
└────────────────────┘
```

### Null-Byte-Free Assembly
```
┌──────────────────┐
│     push 59      │
│     pop rax      │
│   bts rax, 25    │
│     syscall      │
└──────────────────┘
```

### Box Features
- **Unicode box drawing**: Clean, professional appearance
- **Dynamic sizing**: Box adjusts to content width
- **Color coding**: Cyan boxes, green assembly code
- **Centered content**: Assembly instructions are centered within the box

## Advanced Usage

### Combining Options

```bash
# Search with arguments and null-byte avoidance
python3 XNUsyscalls.py -sb exec --args -nb

# Look up machine-dependent call with arguments
python3 XNUsyscalls.py -md 3 --args

# Search diagnostics calls
python3 XNUsyscalls.py -sd perf
```

### Shellcode Development Workflow

1. **Find target syscalls**: Use search to identify relevant syscalls
   ```bash
   python3 XNUsyscalls.py -sb exec
   ```

2. **Analyze arguments**: Check what parameters are needed
   ```bash
   python3 XNUsyscalls.py -b 59 --args
   ```

3. **Generate assembly**: Get null-byte-free assembly for shellcode
   ```bash
   python3 XNUsyscalls.py -b 59 -nb
   ```

4. **Verify values**: Check the syscall values and assembly code

### Real-World Examples

#### Example 1: Finding File Operations
```bash
# Search for file-related syscalls
python3 XNUsyscalls.py -sb open
python3 XNUsyscalls.py -sb read
python3 XNUsyscalls.py -sb write
```

#### Example 2: Process Management
```bash
# Find process-related syscalls
python3 XNUsyscalls.py -sb fork
python3 XNUsyscalls.py -sb exec
python3 XNUsyscalls.py -sb exit
```

#### Example 3: IPC and Communication
```bash
# Find Mach IPC syscalls
python3 XNUsyscalls.py -sm msg
python3 XNUsyscalls.py -sm port
python3 XNUsyscalls.py -sm task
```

#### Example 4: Shellcode Development
```bash
# Generate null-byte-free shellcode for execve("/bin/sh", NULL, NULL)
python3 XNUsyscalls.py -b 59 -nb --args

# Output shows:
# - execve takes 3 arguments: filename, argv, envp
# - Assembly: push 59, pop rax, bts rax, 25, syscall
# - No null bytes in the assembly sequence
```

### Troubleshooting

#### Common Errors

**File not found error:**
```
Error: syscalls.master not found at /path/to/bsd/kern/syscalls.master
Make sure you're running this script from the XNU source root directory
```
**Solution**: Run the script from the XNU source root directory.

**Syscall not found:**
```
Error: UNIX syscall 999 not found
```
**Solution**: Verify the syscall number exists using `--syscalls` option.

**IPC class warning:**
```
IPC syscall class 5 is defined but appears to be unused in current XNU.
Try using -sm to search Mach syscalls (class 1) for IPC functionality instead.
```
**Solution**: Use Mach syscalls for IPC functionality.

#### Validation Commands

```bash
# Verify syscall exists
python3 XNUsyscalls.py --syscalls 2 | grep -i execve

# Check all available syscalls in a class
python3 XNUsyscalls.py --syscalls 1  # List all Mach syscalls
python3 XNUsyscalls.py --syscalls 2  # List all BSD syscalls

# Search for similar syscalls
python3 XNUsyscalls.py -sb similar_name
```


## Related Resources

- [XNU Source Code](https://github.com/apple/darwin-xnu)
- [Apple Developer Documentation](https://developer.apple.com/documentation/)
- [Mach IPC Documentation](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/)
- [BSD System Calls](https://www.freebsd.org/cgi/man.cgi?query=syscalls&sektion=2)
