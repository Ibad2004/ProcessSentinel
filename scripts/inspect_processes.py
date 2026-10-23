
"""Print a small sample of running process information."""

from pc_security.scanner.process_scanner import scan_processes


def main():
    processes = scan_processes()

    print(f"\nTotal processes found: {len(processes)}")
    print("-" * 80)

    for process in processes[:10]:
        print(f"PID:        {process['pid']}")
        print(f"Name:       {process['name']}")
        print(f"Path:       {process['exe_path']}")
        print(f"CPU:        {process['cpu_percent']}%")
        print(f"Memory:     {process['memory_mb']} MiB")
        print(f"Parent PID: {process['parent_pid']}")
        print("-" * 80)


if __name__ == "__main__":
    main()
