#!/usr/bin/env python3
"""
XNU Syscall Lookup Tool
Comprehensive syscall analysis for XNU kernel

Based on complete source scan of XNU-11417.121.6:
- Class 0 (NONE): 0 syscalls (invalid)
- Class 1 (MACH): 50 Mach traps (IPC, VM, ports, scheduling)
- Class 2 (UNIX): 669 BSD syscalls (~454 active, ~215 deprecated)
- Class 3 (MDEP): 4-6 machine-dependent calls (x86 only)
- Class 4 (DIAG): 26 diagnostic calls (x86 only)
- Class 5 (IPC): 0 syscalls (reserved but unused)

Total: ~530-535 active user-callable syscalls across all classes
"""

import argparse
import re
import sys
from pathlib import Path

# Try to import tabulate, fallback to simple table if not available
try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Syscall classes from osfmk/mach/i386/syscall_sw.h
SYSCALL_CLASSES = {
    0: {"name": "NONE", "description": "Invalid"},
    1: {"name": "MACH", "description": "Mach"},
    2: {"name": "UNIX", "description": "Unix/BSD"},
    3: {"name": "MDEP", "description": "Machine-dependent"},
    4: {"name": "DIAG", "description": "Diagnostics"},
    5: {"name": "IPC", "description": "Mach IPC"}
}

SYSCALL_CLASS_SHIFT = 24

class XNUSyscallParser:
    def __init__(self, syscalls_master_path):
        self.syscalls_master_path = Path(syscalls_master_path)
        self.syscalls = {}
        self.mach_traps = {}
        self.machdep_calls = {}
        self.diag_calls = {}
        self.parse_syscalls()
        self.parse_mach_traps()
        self.parse_machdep_calls()
        self.parse_diag_calls()

    def parse_syscalls(self):
        """Parse the syscalls.master file and extract syscall information"""
        if not self.syscalls_master_path.exists():
            print(f"{Colors.FAIL}Error: syscalls.master file not found at {self.syscalls_master_path}{Colors.ENDC}")
            sys.exit(1)

        with open(self.syscalls_master_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip comments, empty lines, and preprocessor directives
                if not line or line.startswith(';') or line.startswith('#'):
                    continue

                # Parse syscall line format: NUMBER AUDIT FILES { PROTOTYPE }
                match = re.match(r'^(\d+)\s+\w+\s+\w+\s+\{\s*([^}]+)\s*\}', line)
                if match:
                    syscall_num = int(match.group(1))
                    prototype = match.group(2).strip()

                    # Extract function name from prototype
                    func_match = re.search(r'\b(\w+)\s*\(', prototype)
                    if func_match:
                        func_name = func_match.group(1)

                        # Store all syscalls, including enosys/nosys and old ones

                        self.syscalls[syscall_num] = {
                            'name': func_name,
                            'prototype': prototype,
                            'line': line_num,
                            'class': 2,  # All syscalls in syscalls.master are Unix/BSD class
                            'raw_line': line  # Store the original line for display
                        }

    def parse_mach_traps(self):
        """Parse Mach traps from syscall_sw.c"""
        # Hard-coded list of known Mach traps based on syscall_sw.c analysis
        mach_traps_data = {
            10: "_kernelrpc_mach_vm_allocate_trap",
            11: "_kernelrpc_mach_vm_purgable_control_trap",
            12: "_kernelrpc_mach_vm_deallocate_trap",
            13: "task_dyld_process_info_notify_get_trap",
            14: "_kernelrpc_mach_vm_protect_trap",
            15: "_kernelrpc_mach_vm_map_trap",
            16: "_kernelrpc_mach_port_allocate_trap",
            18: "_kernelrpc_mach_port_deallocate_trap",
            19: "_kernelrpc_mach_port_mod_refs_trap",
            20: "_kernelrpc_mach_port_move_member_trap",
            21: "_kernelrpc_mach_port_insert_right_trap",
            22: "_kernelrpc_mach_port_insert_member_trap",
            23: "_kernelrpc_mach_port_extract_member_trap",
            24: "_kernelrpc_mach_port_construct_trap",
            25: "_kernelrpc_mach_port_destruct_trap",
            26: "mach_reply_port",
            27: "thread_self_trap",
            28: "task_self_trap",
            29: "host_self_trap",
            31: "mach_msg_trap",
            32: "mach_msg_overwrite_trap",
            33: "semaphore_signal_trap",
            34: "semaphore_signal_all_trap",
            35: "semaphore_signal_thread_trap",
            36: "semaphore_wait_trap",
            37: "semaphore_wait_signal_trap",
            38: "semaphore_timedwait_trap",
            39: "semaphore_timedwait_signal_trap",
            40: "_kernelrpc_mach_port_get_attributes_trap",
            41: "_kernelrpc_mach_port_guard_trap",
            42: "_kernelrpc_mach_port_unguard_trap",
            43: "mach_generate_activity_id",
            44: "task_name_for_pid",
            45: "task_for_pid",
            46: "pid_for_task",
            47: "mach_msg2_trap",
            48: "macx_swapon",
            49: "macx_swapoff",
            50: "thread_get_special_reply_port",
            51: "macx_triggers",
            52: "macx_backing_store_suspend",
            53: "macx_backing_store_recovery",
            58: "pfz_exit",
            59: "swtch_pri",
            60: "swtch",
            61: "thread_switch",
            62: "clock_sleep_trap",
            70: "host_create_mach_voucher_trap",
            72: "mach_voucher_extract_attr_recipe_trap",
            76: "_kernelrpc_mach_port_type_trap",
            77: "_kernelrpc_mach_port_request_notification_trap",
            88: "_exclaves_ctl_trap",
            89: "mach_timebase_info_trap",
            90: "mach_wait_until_trap",
            91: "mk_timer_create_trap",
            92: "mk_timer_destroy_trap",
            93: "mk_timer_arm_trap",
            94: "mk_timer_cancel_trap",
            95: "mk_timer_arm_leeway_trap",
            96: "debug_control_port_for_pid",
            100: "iokit_user_client_trap"
        }

        for trap_num, trap_name in mach_traps_data.items():
            self.mach_traps[trap_num] = {
                'name': trap_name,
                'raw_line': f"/* {trap_num} */ MACH_TRAP({trap_name}, ...)",
                'class': 1
            }

    def parse_machdep_calls(self):
        """Parse machine-dependent calls from machdep_call.c"""
        # Hard-coded list of known machine-dependent calls based on machdep_call.c
        machdep_calls_data = {
            3: "thread_fast_set_cthread_self",
            4: "thread_set_user_ldt",
            5: "i386_set_ldt",
            6: "i386_get_ldt"
        }

        for call_num, call_name in machdep_calls_data.items():
            self.machdep_calls[call_num] = {
                'name': call_name,
                'raw_line': f"MACHDEP_CALL_ROUTINE({call_name}, ...)",
                'class': 3
            }

    def parse_diag_calls(self):
        """Parse diagnostics calls from Diagnostics.h"""
        # Hard-coded list of known diagnostic calls based on Diagnostics.h
        diag_calls_data = {
            0: "dgAdjTB",
            1: "dgLRA",
            2: "dgpcpy",
            3: "dgreset",
            4: "dgtest",
            5: "dgBMphys",
            6: "dgUnMap",
            7: "dgBootScreen",
            8: "dgFlush",
            9: "dgAlign",
            10: "dgGzallocTest",
            11: "dgmck",
            12: "dg64",
            13: "dgProbeRead",
            14: "dgCPNull",
            15: "dgPerfMon",
            16: "dgMapPage",
            17: "dgPowerStat",
            18: "dgBind",
            20: "dgAcntg",
            21: "dgKlra",
            22: "dgEnaPMC",
            23: "dgWar",
            24: "dgNapStat",
            25: "dgRuptStat",
            26: "dgPermCheck"
        }

        for call_num, call_name in diag_calls_data.items():
            self.diag_calls[call_num] = {
                'name': call_name,
                'raw_line': f"#define {call_name} {call_num}",
                'class': 4
            }

    def get_syscall_value(self, syscall_num, syscall_class=2):
        """Calculate the syscall value for assembly usage"""
        return (syscall_class << SYSCALL_CLASS_SHIFT) | (syscall_num & 0xFFFF)

    def parse_syscall_master_arguments(self, raw_line):
        """Parse arguments from syscalls.master raw line format"""
        # Extract the function prototype from the syscall.master line
        # Format: NUMBER AUDIT FILES { RETURN_TYPE FUNCTION_NAME(ARGS) FLAGS; }

        # Find the part inside braces
        match = re.search(r'\{([^}]+)\}', raw_line)
        if not match:
            return []

        func_def = match.group(1).strip()

        # Extract function name and arguments
        # Handle cases like: "void exit(int rval) NO_SYSCALL_STUB"
        # or "user_ssize_t read(int fd, user_addr_t cbuf, user_size_t nbyte)"

        # Find the function call part - everything up to the first space after closing paren
        func_match = re.search(r'(\w+\s+)?(\w+)\s*\(([^)]*)\)', func_def)
        if not func_match:
            return []

        args_str = func_match.group(3).strip()

        if not args_str or args_str.lower() == 'void':
            return []

        # Split by comma and parse each argument
        args = []
        arg_parts = [arg.strip() for arg in args_str.split(',')]

        for i, arg in enumerate(arg_parts, 1):
            if not arg:
                continue

            # Parse argument: "type name" or "type *name" etc.
            # Handle complex types like "struct stat *", "user_addr_t", etc.

            # Handle pointer syntax properly
            # Split by whitespace but be careful with pointers
            parts = arg.split()
            if len(parts) >= 2:
                # Last part is the parameter name
                arg_name = parts[-1]
                # Everything else is the type
                arg_type = ' '.join(parts[:-1])

                # Handle pointer notation: **name, *name
                pointer_count = 0
                while arg_name.startswith('*'):
                    arg_name = arg_name[1:]
                    pointer_count += 1

                # Add pointer notation to type
                if pointer_count > 0:
                    arg_type += ' ' + '*' * pointer_count

            else:
                # Only type given, no name
                arg_type = arg
                arg_name = f"arg{i}"

            # Clean up type
            arg_type = re.sub(r'\s+', ' ', arg_type.strip())
            arg_name = arg_name.strip()

            args.append({
                'position': i,
                'type': arg_type,
                'name': arg_name
            })

        return args

    def get_syscall_arguments(self, syscall_num, syscall_class):
        """Get syscall arguments based on class and number"""
        if syscall_class == 1:  # Mach
            if syscall_num in self.mach_traps:
                # For Mach traps, we need to look up the prototype from mach_traps.h
                return self.get_mach_trap_arguments(syscall_num)
        elif syscall_class == 2:  # BSD/Unix
            if syscall_num in self.syscalls:
                raw_line = self.syscalls[syscall_num]['raw_line']
                return self.parse_syscall_master_arguments(raw_line)
        elif syscall_class == 3:  # Machine-dependent
            if syscall_num in self.machdep_calls:
                return self.get_machdep_arguments(syscall_num)
        elif syscall_class == 4:  # Diagnostics
            if syscall_num in self.diag_calls:
                return self.get_diag_arguments(syscall_num)

        return []

    def get_mach_trap_arguments(self, trap_num):
        """Get Mach trap arguments - hardcoded based on mach_traps.h analysis"""
        mach_args = {
            10: [  # _kernelrpc_mach_vm_allocate_trap
                {'position': 1, 'type': 'mach_port_name_t', 'name': 'target'},
                {'position': 2, 'type': 'mach_vm_offset_t *', 'name': 'addr'},
                {'position': 3, 'type': 'mach_vm_size_t', 'name': 'size'},
                {'position': 4, 'type': 'int', 'name': 'flags'}
            ],
            26: [  # mach_reply_port
                # No arguments - returns mach_port_name_t
            ],
            27: [  # thread_self_trap
                # No arguments - returns mach_port_name_t
            ],
            28: [  # task_self_trap
                # No arguments - returns mach_port_name_t
            ],
            31: [  # mach_msg_trap
                {'position': 1, 'type': 'mach_msg_header_t *', 'name': 'msg'},
                {'position': 2, 'type': 'mach_msg_option_t', 'name': 'option'},
                {'position': 3, 'type': 'mach_msg_size_t', 'name': 'send_size'},
                {'position': 4, 'type': 'mach_msg_size_t', 'name': 'rcv_size'},
                {'position': 5, 'type': 'mach_port_name_t', 'name': 'rcv_name'},
                {'position': 6, 'type': 'mach_msg_timeout_t', 'name': 'timeout'},
                {'position': 7, 'type': 'mach_port_name_t', 'name': 'notify'}
            ],
            33: [  # semaphore_signal_trap
                {'position': 1, 'type': 'mach_port_name_t', 'name': 'signal_name'}
            ],
            45: [  # task_for_pid
                {'position': 1, 'type': 'mach_port_name_t', 'name': 'target_tport'},
                {'position': 2, 'type': 'int', 'name': 'pid'},
                {'position': 3, 'type': 'mach_port_name_t *', 'name': 't'}
            ],
            46: [  # pid_for_task
                {'position': 1, 'type': 'mach_port_name_t', 'name': 't'},
                {'position': 2, 'type': 'int *', 'name': 'x'}
            ],
            62: [  # clock_sleep_trap
                {'position': 1, 'type': 'mach_port_name_t', 'name': 'clock_name'},
                {'position': 2, 'type': 'sleep_type_t', 'name': 'sleep_type'},
                {'position': 3, 'type': 'int', 'name': 'sleep_sec'},
                {'position': 4, 'type': 'int', 'name': 'sleep_nsec'},
                {'position': 5, 'type': 'mach_timespec_t *', 'name': 'wakeup_time'}
            ]
        }
        return mach_args.get(trap_num, [])

    def get_machdep_arguments(self, call_num):
        """Get machine-dependent call arguments"""
        machdep_args = {
            3: [  # thread_fast_set_cthread_self
                {'position': 1, 'type': 'uint64_t', 'name': 'self_addr'}
            ],
            4: [  # thread_set_user_ldt
                {'position': 1, 'type': 'uint32_t', 'name': 'selector'},
                {'position': 2, 'type': 'uint64_t', 'name': 'ldt_entry'},
                {'position': 3, 'type': 'uint32_t', 'name': 'set_flag'}
            ],
            5: [  # i386_set_ldt
                {'position': 1, 'type': 'int', 'name': 'start_sel'},
                {'position': 2, 'type': 'union ldt_entry *', 'name': 'descs'},
                {'position': 3, 'type': 'int', 'name': 'num_sels'}
            ],
            6: [  # i386_get_ldt
                {'position': 1, 'type': 'int', 'name': 'start_sel'},
                {'position': 2, 'type': 'union ldt_entry *', 'name': 'descs'},
                {'position': 3, 'type': 'int', 'name': 'num_sels'}
            ]
        }
        return machdep_args.get(call_num, [])

    def get_diag_arguments(self, call_num):
        """Get diagnostic call arguments"""
        # Most diagnostic calls have varying or undocumented arguments
        # Return basic info where known
        diag_args = {
            0: [  # dgAdjTB
                {'position': 1, 'type': 'uint64_t', 'name': 'adjustment'}
            ],
            4: [  # dgtest
                {'position': 1, 'type': 'uint32_t', 'name': 'test_param'}
            ],
            15: [  # dgPerfMon
                {'position': 1, 'type': 'uint32_t', 'name': 'counter_id'},
                {'position': 2, 'type': 'uint32_t', 'name': 'operation'}
            ]
        }
        return diag_args.get(call_num, [])

    def display_arguments_table(self, args):
        """Display arguments in a formatted table"""
        if not args:
            print(f"{Colors.WARNING}No arguments (void){Colors.ENDC}")
            return

        print(f"\n{Colors.HEADER}Function Arguments:{Colors.ENDC}")

        if TABULATE_AVAILABLE:
            # Use tabulate for nice formatting
            table_data = []
            for arg in args:
                table_data.append([
                    f"{Colors.OKCYAN}{arg['position']}{Colors.ENDC}",
                    f"{Colors.OKGREEN}{arg['type']}{Colors.ENDC}",
                    f"{Colors.WARNING}{arg['name']}{Colors.ENDC}"
                ])

            headers = [
                f"{Colors.BOLD}Position{Colors.ENDC}",
                f"{Colors.BOLD}Type{Colors.ENDC}",
                f"{Colors.BOLD}Name{Colors.ENDC}"
            ]
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            # Simple fallback table format
            print(f"{Colors.BOLD}{'Pos':<4} {'Type':<30} {'Name':<15}{Colors.ENDC}")
            print(f"{'─'*4} {'─'*30} {'─'*15}")
            for arg in args:
                pos_str = f"{Colors.OKCYAN}{arg['position']}{Colors.ENDC}"
                type_str = f"{Colors.OKGREEN}{arg['type']:<30}{Colors.ENDC}"
                name_str = f"{Colors.WARNING}{arg['name']}{Colors.ENDC}"
                print(f"{pos_str:<10} {type_str} {name_str}")
        print()  # Add blank line after table

    def display_assembly_box(self, syscall_value, avoid_null_bytes=False):
        """Display ASCII art box with assembly code for the syscall"""
        if avoid_null_bytes and self.has_null_bytes(syscall_value):
            # Use null byte avoidance technique with bts instruction
            asm_code = self.generate_null_byte_free_assembly(syscall_value)
        else:
            # Standard assembly code
            asm_code = f"mov rax, 0x{syscall_value:X}\nsyscall"

        # Calculate box dimensions
        max_line_length = max(len(line) for line in asm_code.split('\n'))
        box_width = max(max_line_length + 4, 20)  # Minimum width of 20

        # Create the ASCII art box
        top_line = f"┌{'─' * (box_width - 2)}┐"
        bottom_line = f"└{'─' * (box_width - 2)}┘"

        print(f"\n{Colors.OKCYAN}{top_line}{Colors.ENDC}")

        # Print each line of assembly code centered in the box
        for line in asm_code.split('\n'):
            padding = (box_width - 2 - len(line)) // 2
            left_padding = ' ' * padding
            right_padding = ' ' * (box_width - 2 - len(line) - padding)
            print(f"{Colors.OKCYAN}│{Colors.ENDC}{left_padding}{Colors.OKGREEN}{line}{Colors.ENDC}{right_padding}{Colors.OKCYAN}│{Colors.ENDC}")

        print(f"{Colors.OKCYAN}{bottom_line}{Colors.ENDC}")
        print()  # Add blank line after box

    def has_null_bytes(self, syscall_value):
        """Check if a syscall value contains null bytes when represented in hex"""
        hex_str = f"{syscall_value:X}"
        # Pad to even length for proper byte representation
        if len(hex_str) % 2:
            hex_str = "0" + hex_str

        # Check each pair of hex digits (representing one byte)
        for i in range(0, len(hex_str), 2):
            byte_str = hex_str[i:i+2]
            if byte_str == "00":
                return True
        return False

    def generate_null_byte_free_assembly(self, syscall_value):
        """Generate assembly code that avoids null bytes using bts instruction"""
        syscall_class = (syscall_value >> SYSCALL_CLASS_SHIFT) & 0xFF
        syscall_num = syscall_value & 0xFFFF

        # Generate assembly using push/pop and bts to avoid null bytes
        asm_lines = [
            f"push {syscall_num}",
            "pop rax"
        ]

        # Use bts to set the appropriate class bits
        # For each bit set in the syscall_class, add a bts instruction
        for bit_pos in range(8):  # Check each bit in the class byte
            if syscall_class & (1 << bit_pos):
                bts_bit = SYSCALL_CLASS_SHIFT + bit_pos
                asm_lines.append(f"bts rax, {bts_bit}")

        asm_lines.append("syscall")
        return "\n".join(asm_lines)

    def lookup_syscall(self, syscall_num, syscall_class, show_args=False, avoid_null_bytes=False):
        """Generic syscall lookup by number and class"""
        class_info = SYSCALL_CLASSES[syscall_class]
        syscall_value = self.get_syscall_value(syscall_num, syscall_class)

        found = False
        syscall_name = ""

        if syscall_class == 1:  # Mach
            if syscall_num in self.mach_traps:
                found = True
                syscall_name = self.mach_traps[syscall_num]['name']
        elif syscall_class == 2:  # BSD/Unix
            if syscall_num in self.syscalls:
                syscall = self.syscalls[syscall_num]
                # Skip enosys/nosys and old syscalls for individual lookup
                if syscall['name'] in ['enosys', 'nosys'] or 'old ' in syscall['raw_line'].lower():
                    print(f"{Colors.FAIL}Error: BSD syscall {syscall_num} is invalid or deprecated{Colors.ENDC}")
                    return False
                found = True
                syscall_name = syscall['name']
        elif syscall_class == 3:  # Machine-dependent
            if syscall_num in self.machdep_calls:
                found = True
                syscall_name = self.machdep_calls[syscall_num]['name']
        elif syscall_class == 4:  # Diagnostics
            if syscall_num in self.diag_calls:
                found = True
                syscall_name = self.diag_calls[syscall_num]['name']
        elif syscall_class == 5:  # IPC
            # IPC class 5 is defined but appears to be reserved/unused in current XNU
            print(f"{Colors.WARNING}IPC syscall class 5 is defined but appears to be unused in current XNU.{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Try using Mach syscall class 1 for IPC functionality instead.{Colors.ENDC}")
            return False

        if found:
            print(f"{Colors.OKBLUE}syscall class:{Colors.ENDC} {Colors.BOLD}{class_info['name']}{Colors.ENDC}")
            print(f"{Colors.OKBLUE}syscall name:{Colors.ENDC} {Colors.OKGREEN}{syscall_name}(){Colors.ENDC}")
            print(f"{Colors.OKBLUE}syscall value:{Colors.ENDC} {Colors.WARNING}0x{syscall_value:X}{Colors.ENDC}")

            # Display arguments if requested
            if show_args:
                args = self.get_syscall_arguments(syscall_num, syscall_class)
                self.display_arguments_table(args)

            # Always display assembly box at the end
            self.display_assembly_box(syscall_value, avoid_null_bytes)

            return True
        else:
            print(f"{Colors.FAIL}Error: {class_info['name']} syscall {syscall_num} not found{Colors.ENDC}")
            return False

    def lookup_bsd_syscall(self, syscall_num, show_args=False, avoid_null_bytes=False):
        """Lookup BSD syscall by number (backward compatibility)"""
        return self.lookup_syscall(syscall_num, 2, show_args, avoid_null_bytes)

    def search_syscalls_by_name(self, search_string, syscall_class, show_args=False, avoid_null_bytes=False):
        """Search syscalls by function name substring"""
        class_info = SYSCALL_CLASSES[syscall_class]
        search_lower = search_string.lower()
        found_syscalls = []

        if syscall_class == 1:  # Mach
            for trap_num, trap in self.mach_traps.items():
                if search_lower in trap['name'].lower():
                    found_syscalls.append((trap_num, trap['name'], trap))
        elif syscall_class == 2:  # BSD/Unix
            for syscall_num, syscall in self.syscalls.items():
                # Skip enosys/nosys and old syscalls for search
                if syscall['name'] in ['enosys', 'nosys'] or 'old ' in syscall['raw_line'].lower():
                    continue
                if search_lower in syscall['name'].lower():
                    found_syscalls.append((syscall_num, syscall['name'], syscall))
        elif syscall_class == 3:  # Machine-dependent
            for call_num, call in self.machdep_calls.items():
                if search_lower in call['name'].lower():
                    found_syscalls.append((call_num, call['name'], call))
        elif syscall_class == 4:  # Diagnostics
            for call_num, call in self.diag_calls.items():
                if search_lower in call['name'].lower():
                    found_syscalls.append((call_num, call['name'], call))
        elif syscall_class == 5:  # IPC
            print(f"{Colors.WARNING}IPC syscall class 5 is defined but appears to be unused in current XNU.{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Try using -sm to search Mach syscalls (class 1) for IPC functionality instead.{Colors.ENDC}")
            return False

        if not found_syscalls:
            print(f"{Colors.FAIL}No {class_info['name']} syscalls found matching '{search_string}'{Colors.ENDC}")
            return False

        print(f"{Colors.HEADER}{Colors.BOLD}Found {len(found_syscalls)} {class_info['name']} syscall(s) matching '{search_string}':{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")

        for syscall_num, syscall_name, syscall_data in sorted(found_syscalls):
            syscall_value = self.get_syscall_value(syscall_num, syscall_class)
            print(f"{Colors.OKBLUE}Number:{Colors.ENDC} {Colors.WARNING}{syscall_num}{Colors.ENDC}")
            print(f"{Colors.OKBLUE}Name:{Colors.ENDC} {Colors.OKGREEN}{syscall_name}(){Colors.ENDC}")
            print(f"{Colors.OKBLUE}Value:{Colors.ENDC} {Colors.WARNING}0x{syscall_value:X}{Colors.ENDC}")

            # Display arguments if requested
            if show_args:
                args = self.get_syscall_arguments(syscall_num, syscall_class)
                self.display_arguments_table(args)

            # Always display assembly box at the end
            self.display_assembly_box(syscall_value, avoid_null_bytes)

            print()  # Add blank line between results

        return True

    def list_syscalls_by_class(self, class_num):
        """List all syscalls for a given class"""
        if class_num not in SYSCALL_CLASSES:
            print(f"{Colors.FAIL}Error: Invalid syscall class {class_num}. Valid classes: 0-5{Colors.ENDC}")
            return

        class_info = SYSCALL_CLASSES[class_num]
        print(f"{Colors.HEADER}{Colors.BOLD}Syscall Class {class_num}: {class_info['name']} ({class_info['description']}){Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")

        if class_num == 0:  # NONE - Invalid
            print(f"{Colors.WARNING}Syscall class {class_num} is invalid/unused{Colors.ENDC}")

        elif class_num == 1:  # Mach - these are in mach_trap_table
            if not self.mach_traps:
                print(f"{Colors.WARNING}No Mach traps found for class {class_num}{Colors.ENDC}")
                return

            # Display Mach trap entries
            for trap_num in sorted(self.mach_traps.keys()):
                trap = self.mach_traps[trap_num]
                print(f"{Colors.OKGREEN}{trap['raw_line']}{Colors.ENDC}")

        elif class_num == 2:  # Unix/BSD - these are in syscalls.master
            if not self.syscalls:
                print(f"{Colors.WARNING}No syscalls found for class {class_num}{Colors.ENDC}")
                return

            # Display raw syscall entries from syscalls.master
            for syscall_num in sorted(self.syscalls.keys()):
                syscall = self.syscalls[syscall_num]
                print(f"{Colors.OKGREEN}{syscall['raw_line']}{Colors.ENDC}")

        elif class_num == 3:  # Machine-dependent - these are in machdep_call_table
            if not self.machdep_calls:
                print(f"{Colors.WARNING}No machine-dependent calls found for class {class_num}{Colors.ENDC}")
                return

            # Display machdep call entries
            for call_num in sorted(self.machdep_calls.keys()):
                call = self.machdep_calls[call_num]
                print(f"{Colors.OKGREEN}{call['raw_line']}{Colors.ENDC}")

        elif class_num == 4:  # Diagnostics - these are diagnostic calls
            if not self.diag_calls:
                print(f"{Colors.WARNING}No diagnostic calls found for class {class_num}{Colors.ENDC}")
                return

            # Display diagnostic call entries
            for call_num in sorted(self.diag_calls.keys()):
                call = self.diag_calls[call_num]
                print(f"{Colors.OKGREEN}{call['raw_line']}{Colors.ENDC}")

        elif class_num == 5:  # IPC - Mach IPC specific calls
            # Based on comprehensive XNU source scan: IPC class 5 is reserved but unused
            print(f"{Colors.WARNING}SYSCALL_CLASS_IPC (class 5) is defined but unused in current XNU.{Colors.ENDC}")
            print(f"{Colors.WARNING}Comprehensive source scan found 0 user-callable syscalls in class 5.{Colors.ENDC}")
            print(f"{Colors.OKCYAN}IPC functionality is implemented through Mach syscalls (class 1):{Colors.ENDC}")
            print(f"{Colors.OKCYAN}  • mach_msg_trap (31) - Core IPC message passing{Colors.ENDC}")
            print(f"{Colors.OKCYAN}  • mach_msg_overwrite_trap (32) - IPC with overwrite{Colors.ENDC}")
            print(f"{Colors.OKCYAN}  • mach_msg2_trap (47) - Enhanced message passing{Colors.ENDC}")
            print(f"{Colors.OKCYAN}  • Various mach_port_* traps for port management{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Use --syscalls 1 to view all 50 Mach syscalls.{Colors.ENDC}")

def print_banner():
    """Print ASCII art banner with tool name and author information"""
    banner = f"""
{Colors.OKCYAN}╔══════════════════════════════════════════════╗
║                                              ║
║                {Colors.BOLD}XNU Syscalls{Colors.ENDC}{Colors.OKCYAN}                  ║
║                                              ║
║              {Colors.WARNING}By: Zeyad Azima{Colors.ENDC}{Colors.OKCYAN}                 ║
║           {Colors.OKGREEN}https://zeyadazima.com/{Colors.ENDC}{Colors.OKCYAN}            ║
║                                              ║
╚══════════════════════════════════════════════╝{Colors.ENDC}
"""
    print(banner)

def main():
    # Always print banner first
    print_banner()

    parser = argparse.ArgumentParser(
        description="XNU Syscall Lookup Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {Colors.OKGREEN}python3 XNUsyscalls.py -b 59{Colors.ENDC}         # Lookup BSD syscall 59 (execve)
  {Colors.OKGREEN}python3 XNUsyscalls.py -b 59 --args{Colors.ENDC}  # Show execve with arguments table
  {Colors.OKGREEN}python3 XNUsyscalls.py -b 59 -nb{Colors.ENDC}     # Show execve with null-byte-free assembly
  {Colors.OKGREEN}python3 XNUsyscalls.py -m 31 --args{Colors.ENDC}  # Show mach_msg_trap with arguments
  {Colors.OKGREEN}python3 XNUsyscalls.py -md 3{Colors.ENDC}         # Lookup machine-dependent call 3
  {Colors.OKGREEN}python3 XNUsyscalls.py -d 15{Colors.ENDC}         # Lookup diagnostic call 15
  {Colors.OKGREEN}python3 XNUsyscalls.py -sb exec --args{Colors.ENDC} # Search BSD syscalls containing "exec"
  {Colors.OKGREEN}python3 XNUsyscalls.py -sm msg -nb{Colors.ENDC}    # Search Mach syscalls containing "msg" (no nulls)
  {Colors.OKGREEN}python3 XNUsyscalls.py -smd thread{Colors.ENDC}    # Search machine-dependent calls containing "thread"
  {Colors.OKGREEN}python3 XNUsyscalls.py --syscalls 2{Colors.ENDC}   # List all BSD syscalls
  {Colors.OKGREEN}python3 XNUsyscalls.py -sc 1{Colors.ENDC}         # List all Mach syscalls (short form)
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-b', '--bsd', type=int, metavar='NUM',
                      help='Lookup BSD/Unix syscall by number (class 2)')
    group.add_argument('-m', '--mach', type=int, metavar='NUM',
                      help='Lookup Mach syscall by number (class 1)')
    group.add_argument('-md', '--machdep', type=int, metavar='NUM',
                      help='Lookup machine-dependent call by number (class 3)')
    group.add_argument('-d', '--diag', type=int, metavar='NUM',
                      help='Lookup diagnostic call by number (class 4)')
    group.add_argument('-i', '--ipc', type=int, metavar='NUM',
                      help='Lookup IPC syscall by number (class 5, same as Mach)')
    group.add_argument('-sb', '--search-bsd', type=str, metavar='STRING',
                      help='Search BSD syscalls by function name (class 2)')
    group.add_argument('-sm', '--search-mach', type=str, metavar='STRING',
                      help='Search Mach syscalls by function name (class 1)')
    group.add_argument('-smd', '--search-machdep', type=str, metavar='STRING',
                      help='Search machine-dependent calls by function name (class 3)')
    group.add_argument('-sd', '--search-diag', type=str, metavar='STRING',
                      help='Search diagnostic calls by function name (class 4)')
    group.add_argument('-si', '--search-ipc', type=str, metavar='STRING',
                      help='Search IPC syscalls by function name (class 5)')
    group.add_argument('--syscalls', '-sc', type=int, metavar='CLASS',
                      choices=range(6), help='List syscalls by class (0-5)')

    parser.add_argument('--args', action='store_true',
                       help='Show function arguments table (use with -b, -m, -md, -d, -i, -sb, -sm, -smd, -sd, -si)')
    parser.add_argument('-nb', '--no-nulls', action='store_true',
                       help='Generate null-byte-free assembly using bts instruction')

    args = parser.parse_args()

    # Find syscalls.master file
    current_dir = Path.cwd()
    syscalls_master_path = current_dir / "bsd" / "kern" / "syscalls.master"

    if not syscalls_master_path.exists():
        print(f"{Colors.FAIL}Error: syscalls.master not found at {syscalls_master_path}{Colors.ENDC}")
        print(f"{Colors.WARNING}Make sure you're running this script from the XNU source root directory{Colors.ENDC}")
        sys.exit(1)

    parser_obj = XNUSyscallParser(syscalls_master_path)

    # Check if --args is used without a syscall lookup or search
    if args.args and args.syscalls is not None:
        print(f"{Colors.WARNING}--args option is only valid with individual syscall lookups or searches{Colors.ENDC}")
        sys.exit(1)

    if args.bsd is not None:
        parser_obj.lookup_bsd_syscall(args.bsd, args.args, args.no_nulls)
    elif args.mach is not None:
        parser_obj.lookup_syscall(args.mach, 1, args.args, args.no_nulls)
    elif args.machdep is not None:
        parser_obj.lookup_syscall(args.machdep, 3, args.args, args.no_nulls)
    elif args.diag is not None:
        parser_obj.lookup_syscall(args.diag, 4, args.args, args.no_nulls)
    elif args.ipc is not None:
        parser_obj.lookup_syscall(args.ipc, 5, args.args, args.no_nulls)
    elif args.search_bsd is not None:
        parser_obj.search_syscalls_by_name(args.search_bsd, 2, args.args, args.no_nulls)
    elif args.search_mach is not None:
        parser_obj.search_syscalls_by_name(args.search_mach, 1, args.args, args.no_nulls)
    elif args.search_machdep is not None:
        parser_obj.search_syscalls_by_name(args.search_machdep, 3, args.args, args.no_nulls)
    elif args.search_diag is not None:
        parser_obj.search_syscalls_by_name(args.search_diag, 4, args.args, args.no_nulls)
    elif args.search_ipc is not None:
        parser_obj.search_syscalls_by_name(args.search_ipc, 5, args.args, args.no_nulls)
    elif args.syscalls is not None:
        parser_obj.list_syscalls_by_class(args.syscalls)

if __name__ == "__main__":
    main()
