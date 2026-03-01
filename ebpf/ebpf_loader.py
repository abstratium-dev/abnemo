#!/usr/bin/env python3
"""
eBPF Loader - Loads and manages the eBPF network monitor
"""

import os
import struct
import socket
from bcc import BPF


class EBPFLoader:
    def __init__(self):
        self.bpf = None
        self.event_callback = None
        
    def load(self, event_callback):
        """
        Load and attach the eBPF program to kernel hooks
        
        How it works:
        1. BCC compiles C code to eBPF bytecode
        2. Kernel verifies bytecode (safety checks)
        3. Bytecode loaded into kernel
        4. Kprobes attached to kernel functions (tcp_sendmsg, etc.)
        5. Perf buffer created for kernel->userspace communication
        
        Persistence:
        - Hooks remain active until explicitly detached
        - Automatically cleaned up when Python process exits
        - Can be manually cleaned up with cleanup()
        
        Security:
        - Kernel verifier ensures eBPF program is safe
        - Cannot crash kernel or access arbitrary memory
        - Sandboxed execution environment
        """
        self.event_callback = event_callback
        
        # Get path to C program
        ebpf_dir = os.path.dirname(os.path.abspath(__file__))
        c_file = os.path.join(ebpf_dir, "network_monitor.c")
        
        if not os.path.exists(c_file):
            raise FileNotFoundError(f"eBPF C program not found: {c_file}")
        
        # Read C program
        with open(c_file, 'r') as f:
            bpf_text = f.read()
        
        print("[*] Compiling eBPF program...")
        try:
            # BCC compiles C -> eBPF bytecode -> loads into kernel
            self.bpf = BPF(text=bpf_text)
        except Exception as e:
            print(f"[!] Failed to compile eBPF program: {e}")
            raise
        
        print("[*] Attaching eBPF probes...")
        
        # Attach kprobes to kernel functions
        # These intercept calls to tcp_sendmsg/udp_sendmsg
        try:
            self.bpf.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
            self.bpf.attach_kprobe(event="tcp_connect", fn_name="trace_tcp_connect")
            print("[+] Attached to TCP hooks")
        except Exception as e:
            print(f"[!] Warning: Could not attach to TCP hooks: {e}")
        
        try:
            self.bpf.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")
            print("[+] Attached to UDP hooks")
        except Exception as e:
            print(f"[!] Warning: Could not attach to UDP hooks: {e}")
        
        # Open perf buffer for receiving events from kernel
        # This creates a ring buffer for kernel->userspace communication
        self.bpf["events"].open_perf_buffer(self._handle_event)
        print("[+] eBPF program loaded successfully")
        
    def _handle_event(self, cpu, data, size):
        """Handle events from eBPF"""
        # Parse event structure
        # struct connection_event_t {
        #     u32 pid;           // 0-3
        #     char comm[16];     // 4-19
        #     u32 saddr;         // 20-23
        #     u32 daddr;         // 24-27
        #     u16 sport;         // 28-29
        #     u16 dport;         // 30-31
        #     u8 protocol;       // 32
        #     u64 cgroup_id;     // 33-40
        #     u32 saddr_v6[4];   // 41-56
        #     u32 daddr_v6[4];   // 57-72
        #     u8 ip_version;     // 73
        # }
        
        event = self.bpf["events"].event(data)
        
        # Extract fields
        pid = event.pid
        comm = event.comm.decode('utf-8', 'replace').rstrip('\x00')
        protocol = 'tcp' if event.protocol == 6 else 'udp'
        cgroup_id = event.cgroup_id
        ip_version = event.ip_version
        
        # Format IP addresses
        if ip_version == 4:
            # IPv4
            saddr = socket.inet_ntoa(struct.pack('I', event.saddr))
            daddr = socket.inet_ntoa(struct.pack('I', event.daddr))
        else:
            # IPv6
            saddr = self._format_ipv6(event.saddr_v6)
            daddr = self._format_ipv6(event.daddr_v6)
        
        sport = event.sport
        dport = event.dport
        
        # Create event dict
        event_data = {
            'pid': pid,
            'comm': comm,
            'saddr': saddr,
            'daddr': daddr,
            'sport': sport,
            'dport': dport,
            'protocol': protocol,
            'cgroup_id': cgroup_id,
            'ip_version': ip_version
        }
        
        # Call user callback
        if self.event_callback:
            self.event_callback(event_data)
    
    def _format_ipv6(self, addr_array):
        """Format IPv6 address from u32[4] array"""
        # Convert array of u32 to bytes
        addr_bytes = b''
        for i in range(4):
            addr_bytes += struct.pack('I', addr_array[i])
        
        # Convert to IPv6 string
        return socket.inet_ntop(socket.AF_INET6, addr_bytes)
    
    def poll(self, timeout=None):
        """Poll for events"""
        if self.bpf:
            if timeout is None:
                self.bpf.perf_buffer_poll()
            else:
                self.bpf.perf_buffer_poll(timeout=int(timeout * 1000))  # Convert to ms
    
    def cleanup(self):
        """
        Cleanup eBPF resources and detach kernel hooks
        
        What happens:
        1. Detaches all kprobes from kernel functions
        2. Closes perf buffer
        3. Unloads eBPF program from kernel
        4. Frees kernel memory
        
        When called:
        - Explicitly via this method
        - Automatically when Python process exits (via __del__)
        - Automatically on Ctrl+C (via ebpf_monitor.py)
        
        After cleanup:
        - Kernel functions return to normal (no interception)
        - No more events generated
        - Hash maps freed from kernel memory
        """
        if self.bpf:
            print("[*] Cleaning up eBPF...")
            # BCC's cleanup() does:
            # - Detach all kprobes
            # - Close perf buffers
            # - Unload eBPF program from kernel
            # - Free all resources
            self.bpf.cleanup()
            self.bpf = None
