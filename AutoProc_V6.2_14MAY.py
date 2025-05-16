import subprocess
import os
import time
import csv
import sys
import winreg
import json
import psutil
import fnmatch
from deepdiff import DeepDiff
import threading

def Get_Script_Path() -> str:
    return os.path.dirname(os.path.abspath(__file__))

Script_path = Get_Script_Path()
TARGET_PROC = None

# === DIRECTORIES ===
tools_dir = os.path.join(Script_path, "Tools")
working_dir = os.path.join(Script_path, "Working")
results_dir = os.path.join(Script_path, "Results")

# Ensure required folders exist
os.makedirs(tools_dir, exist_ok=True)
os.makedirs(working_dir, exist_ok=True)
os.makedirs(results_dir, exist_ok=True)

# === PATHS ===
Proc_Path = os.path.join(tools_dir, "procmon.exe")
Filter_Path = os.path.join(tools_dir, "BasicFilter1.PMC")
Handle_Path = os.path.join(tools_dir, "handle.exe")

PML_Path = os.path.join(working_dir, "RawOutput.pml")
CSV_Path = os.path.join(working_dir, "RawOutput.csv")
task_before_path = os.path.join(working_dir, "tasks_before.csv")
task_after_path = os.path.join(working_dir, "tasks_after.csv")
reg_before_path = os.path.join(working_dir, "reg_before.json")
reg_after_path = os.path.join(working_dir, "reg_after.json")

Output_Path = os.path.join(results_dir, "ProcFilteredOutput.txt")
Handle_Output = os.path.join(results_dir, "handles_output.txt")
task_dif_path = os.path.join(results_dir, "New_tasks.txt")
reg_dif_path = os.path.join(results_dir, "reg_dif.txt")

network_log_path = os.path.join(results_dir, "network_activity.txt")


wait = 5
TOOL_RESULTS = {
    "Procmon Hits": 0,
    "New Tasks Found": 0,
    "Registry Modifications": 0,
    "Handle Entries": 0,
    "Child/Orphan Processes": 0,
    "Network Connections": 0,
}


# === PROCMON ===
def Run_PM():
    if not os.path.exists(Proc_Path):
        print("[!] Cannot find Procmon.")
        sys.exit(0)
    print("-> Launching Procmon")
    subprocess.Popen([
        Proc_Path, "/AcceptEula", "/Quiet", "/Minimized",
        "/LoadConfig", Filter_Path, "/Backingfile", PML_Path
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(wait)

def Terminate():
    if not any(proc.info['name'].lower() == "procmon.exe" for proc in psutil.process_iter(['name'])):
        print("[!] Procmon is not running. Skipping termination.")
        return
    subprocess.run([Proc_Path, "/Terminate"], check=True, capture_output=True, text=True)

def Convert_Output():
    subprocess.run([Proc_Path, "/openlog", PML_Path, "/Saveas", CSV_Path], check=True, capture_output=True, text=True)

def get_unique_operations(csv_path: str) -> list:
    unique_ops = set()
    proc_filter = TARGET_PROC.lower()

    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [field.strip().strip('"') for field in reader.fieldnames]
        for row in reader:
            proc_name = row.get("Process Name", "").strip().lower()
            if fnmatch.fnmatch(proc_name, proc_filter):  # match against user input
                op = row.get("Operation", "").strip()
                if op:
                    unique_ops.add(op)
    return sorted(unique_ops)


def prompt_for_process_name() -> str:
    return TARGET_PROC

def prompt_for_operations(operations: list) -> set:
    print("\nSelect operations to output:")
    for i, op in enumerate(operations, start=1):
        print(f"[{i}] {op}")
    choices = input("\nEnter options separated by commas (i.e. 1,2,5): ")
    selected = set()
    try:
        indices = [int(i.strip()) for i in choices.split(",") if i.strip()]
        for i in indices:
            if 1 <= i <= len(operations):
                selected.add(operations[i - 1])
    except ValueError:
        print("[!] Invalid input.")
    return selected

def filter_output(csv_path: str, output_path: str):
    if not os.path.exists(csv_path):
        print(f"[!] CSV file not found: {csv_path}")
        return
    selected_proc = prompt_for_process_name()
    operations = get_unique_operations(csv_path)
    selected_ops = prompt_for_operations(operations)
    if not selected_ops:
        print("[!] No operations selected.")
        return
    with open(csv_path, "r", encoding="utf-8-sig") as infile, open(output_path, "w", encoding="utf-8") as outfile:
        reader = csv.DictReader(infile)
        reader.fieldnames = [field.strip().strip('"') for field in reader.fieldnames]
        matches = 0
        rows = []
        for row in reader:
            op = row["Operation"].strip()
            proc = row["Process Name"].strip()
            if op in selected_ops and (not selected_proc or fnmatch.fnmatch(proc.lower(), selected_proc)):
                matches += 1
                rows.append(row)
        header_format = "| {:^20} | {:^25} | {:^25} | {:^8} | {:^15} | {}\n"
        row_format = "| {:<20} | {:<25} | {:<25} | {:<8} | {:<15} | {}\n" + "-"*198 + "\n"
        header_line = header_format.format("Time", "Process", "Operation", "PID", "Result", "Path")
        header_line = header_line.rstrip() + " "*25 + f"[*] Total Hits: {matches}\n"
        outfile.write(header_line)
        outfile.write("|" + "-" * 198 + "|\n")

        TOOL_RESULTS["Procmon Hits"] = matches
        for row in rows:
            outfile.write(row_format.format(
                row["Time of Day"], row["Process Name"], row["Operation"],
                row["PID"], row["Result"], row["Path"],
            ))
        if matches:
            print(f"-> {matches} matching operations written to: {output_path}.")
            os.startfile(output_path)
        else:
            print("[!] No matching operations found.")

# === SCHTASKS ===
def tasks_snapshot(path: str):
    result = subprocess.run(["schtasks", "/Query", "/FO", "CSV", "/V"], capture_output=True, text=True, check=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(result.stdout)

def filter_MS_tasks(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [row for row in reader if "Microsoft" not in row["TaskName"]]

def dif_tasks(before: list[dict], after: list[dict]) -> list[dict]:
    before_names = {t["TaskName"] for t in before}
    return [t for t in after if t["TaskName"] not in before_names]

def write_dif(diff: list[dict], path: str):
    with open(path, "w", encoding="utf-8") as f:
        if not diff:
            return
        f.write("| {:<40} | {:<10} | {:<20} | {:<40} |\n".format("TaskName", "Status", "Next Run Time", "Task Run"))
        f.write("|" + "-" * 130 + "|\n")
        for task in diff:
            f.write("| {:<40} | {:<10} | {:<20} | {:<40} |\n".format(
                task['TaskName'], task['Status'], task.get('Next Run Time', ''), task.get('Task Run', '')
            ))
        
def out_tasks(task_dif_path: str):
    if os.path.getsize(task_dif_path) == 0:
        print("No new tasks detected. Removing task text file.")
        os.remove(task_dif_path)
    else:
        os.startfile(task_dif_path)

# === REGISTRY ===
def snapshot_registry(hive, hive_name=""):
    snapshot = {}

    def walk(key, path=""):
        # Recurse into subkeys
        i = 0
        while True:
            try:
                subkey = winreg.EnumKey(key, i)
                with winreg.OpenKey(key, subkey) as child:
                    walk(child, f"{path}\\{subkey}")
                i += 1
            except (OSError, PermissionError):
                break

        # Capture values at this key
        j = 0
        values = {}
        while True:
            try:
                name, val, _ = winreg.EnumValue(key, j)
                # Convert bytes to hex string for JSON safety
                if isinstance(val, bytes):
                    val = val.hex()
                values[name] = val

                values[name] = val
                j += 1
            except (OSError, PermissionError):
                break

        if values:
            snapshot[path] = values
       #     print(f"[+] Captured {len(values)} value(s) at: {path}")

    with winreg.ConnectRegistry(None, hive) as reg:
        # Try known large base paths
        for base in ["SOFTWARE", "SYSTEM"]:
            try:
                with winreg.OpenKey(reg, base) as root:
                    walk(root, f"{hive_name}\\{base}")
            except FileNotFoundError:
                print(f"[!] {base} not found in {hive_name}")
            except PermissionError:
                print(f"[!] Permission denied to {base} in {hive_name}")

    return snapshot



def save_registry_snapshot(path: str):
    full_snapshot = {}
    hives = [
        (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
        (winreg.HKEY_CURRENT_USER, "HKCU")
    ]

    for hive, name in hives:
        print(f"-> Scanning {name}...")
        snapshot = snapshot_registry(hive, name)
        total_keys = len(snapshot)
        total_values = sum(len(v) for v in snapshot.values())
        print(f"   -> {total_keys} registry paths, {total_values} values captured from {name}")
        full_snapshot[name] = snapshot

    with open(path, "w", encoding="utf-8") as f:
        json.dump(full_snapshot, f, indent=2)


def diff_registry_snapshots(before: str, after: str, output: str):
    import re
    with open(before, "r", encoding="utf-8") as f1:
        reg_before = json.load(f1)
    with open(after, "r", encoding="utf-8") as f2:
        reg_after = json.load(f2)

    diff = DeepDiff(reg_before, reg_after, view='tree')
    if not diff:
        if os.path.exists(output):
            os.remove(output)
        return

    # Categories for human-readable types
    changes = {
        "Key Created": [],
        "Key Deleted": [],
        "Value Created": [],
        "Value Modified": [],
        "Value Deleted": [],
    }

    # Helper to extract clean registry path and value name
    def parse_path(path_obj):
        path = path_obj.path(output_format='list')
        if len(path) >= 3:
            hive = path[0]
            key_path = path[1]
            value_name = path[2]
            return hive, key_path, value_name
        elif len(path) == 2:
            hive = path[0]
            key_path = path[1]
            return hive, key_path, None
        return (None, None, None)

    # Filter function for noisy values
    def is_volatile_value(val_name):
        return re.fullmatch(r"(LastWriteTime|SequenceNumber|Timestamp|ActiveTime|ActiveMillis|CreationTime)", val_name, re.IGNORECASE)

    # Parse diff changes
    for change in diff.get("values_changed", []):
        hive, key_path, val = parse_path(change)
        if hive and key_path and val and not is_volatile_value(val):
            changes["Value Modified"].append((f"{hive}\\{key_path}", val))

    for change in diff.get("dictionary_item_added", []):
        hive, key_path, val = parse_path(change)
        if hive and key_path:
            if val:  # value added to existing key
                changes["Value Created"].append((f"{hive}\\{key_path}", val))
            else:    # entire key created
                changes["Key Created"].append((f"{hive}\\{key_path}", ""))

    for change in diff.get("dictionary_item_removed", []):
        hive, key_path, val = parse_path(change)
        if hive and key_path:
            if val:
                changes["Value Deleted"].append((f"{hive}\\{key_path}", val))
            else:
                changes["Key Deleted"].append((f"{hive}\\{key_path}", ""))

    # Determine max widths for formatting
    all_entries = sum(changes.values(), [])
    max_type = max((len(k) for k in changes), default=10)
    max_path = max((len(p) for p, _ in all_entries), default=30)
    max_val = max((len(v) for _, v in all_entries), default=10)

    row_fmt = f"| {{:<{max_type}}} | {{:<{max_path}}} | {{:<{max_val}}} |\n"
    sep_line = f"+{'-' * (max_type + 2)}+{'-' * (max_path + 2)}+{'-' * (max_val + 2)}+\n"

    with open(output, "w", encoding="utf-8") as f:
        for section, items in changes.items():
            if not items:
                continue
            f.write(f"\n=== Registry Modifications: {section} ===\n")
            f.write(row_fmt.format("Type", "Registry Path", "Value Name"))
            f.write(sep_line)
            for path, val in items:
                f.write(row_fmt.format(section, path, val))
                f.write(sep_line)

    TOOL_RESULTS["Registry Modifications"] = sum(len(v) for v in changes.values())
    
def out_reg(reg_dif_path: str):
    if not os.path.exists(reg_dif_path):
        print("\nNo registry modifications detected.")
    else:
        os.startfile(reg_dif_path)


#PID check
def wait_for_process(target_proc: str) -> int:
    print(f"-> Waiting for process [*] '{target_proc}' [*] to start...")
    print("_" * 73 + "\n" + "-" * 20 + f"[***] DETONATE MALWARE NOW. [***]" + "-" * 20 + "\n" + "_" * 73)
    pid = None
    while not pid:
        for p in psutil.process_iter(['pid', 'name']):
            if fnmatch.fnmatch(p.info['name'].lower(), target_proc):
                pid = p.info['pid']
                print(f"[+] Found match: {p.info['name']} (PID: {pid})")
                return pid
        time.sleep(1)

# === HANDLE TRACKING ===
def poll_handles_during_lifetime(handle_path: str, pid: int, temp_dir: str, output_path: str, interval: int = 2):
    counter = 0
    handle_temp_dir = os.path.join(temp_dir, "handle_temp")
    os.makedirs(handle_temp_dir, exist_ok=True)

    print(" -> Polling handles...")

    while psutil.pid_exists(pid):
        temp_file = os.path.join(handle_temp_dir, f"handle_{counter}.txt")
        with open(temp_file, "w", encoding="utf-8") as f:
            subprocess.run([
                handle_path, "-p", str(pid), "-a", "-nobanner"
            ], stdout=f, text=True)
        counter += 1
        time.sleep(interval)

    print(f" -> Handle polling complete. {counter} snapshots saved to: {handle_temp_dir}")
    merge_handle_snapshots(handle_temp_dir, output_path)


def merge_handle_snapshots(temp_dir: str, output_path: str):
    seen = set()
    merged_lines = []
    script_path = os.path.abspath(sys.argv[0]).lower()
    for filename in sorted(os.listdir(temp_dir)):
        if not filename.startswith("handle_") or not filename.endswith(".txt"):
            continue
        filepath = os.path.join(temp_dir, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line_clean = line.strip()
                line_lower = line_clean.lower()
                if (
                    line_clean and
                    line_lower not in seen and
                    "no matching handles" not in line_lower and
                    script_path not in line_lower and
                    not fnmatch.fnmatch(line_clean, "*: Event*")
                ):
                    seen.add(line_lower)
                    merged_lines.append(line_clean)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(merged_lines))
    print(f" -> Final handle dump written to: {output_path}")
    TOOL_RESULTS["Handle Entries"] = len(open(output_path, "r", encoding="utf-8").readlines()) if os.path.exists(output_path) else 0

def track_process_handles(handle_path: str, pid: int, temp_dir: str, output_path: str):
    poll_handles_during_lifetime(handle_path, pid, temp_dir, output_path)

def out_handle(merged_output_path: str):
    if not os.path.exists(merged_output_path):
        print("\nNo process handles detected.")
    else:
        os.startfile(merged_output_path)

# === Child Process Tracking ===

def track_spawned_processes(parent_pid: int, log_path: str, interval: int = 2):
    known_pids = set()
    original_ppid = parent_pid

    print(" -> Tracking child/orphaned processes...")

    with open(log_path, "w", encoding="utf-8") as log:
        header = "| {:<8} | {:<30} | {:<8} | {:<10} | {}\n".format("TYPE", "NAME", "PID", "STATUS", "CMDLINE")
        log.write(header)
        log.write("|" + "-" * 100 + "|\n")

        while psutil.pid_exists(parent_pid):
            try:
                parent = psutil.Process(parent_pid)
                children = parent.children(recursive=True)

                for child in children:
                    if child.pid not in known_pids:
                        known_pids.add(child.pid)
                        orphan = child.ppid() != original_ppid
                        proc_type = "ORPHAN" if orphan else "CHILD"
                        TOOL_RESULTS["Child/Orphan Processes"] += 1
                        try:
                            log.write("| {:<8} | {:<30} | {:<8} | {:<10} | {}\n".format(
                                proc_type,
                                child.name(),
                                child.pid,
                                child.status(),
                                " ".join(child.cmdline())
                            ))
                            log.flush()
                            print(f"[+] {proc_type}: {child.name()} (PID: {child.pid})")
                        except (psutil.AccessDenied, psutil.ZombieProcess):
                            continue

                time.sleep(interval)
            except psutil.NoSuchProcess:
                break
def out_children(child_log_path: str):
    if not os.path.exists(child_log_path):
        print("\nNo child/orphaned processes detected.")
    else:
        os.startfile(child_log_path)

# === NETWORK MONITORING ===
def monitor_network_connections(pid, log_path, interval=2):
    import socket

    seen = set()
    print(f" -> Monitoring network connections for PID {pid} and children...")

    with open(log_path, "w", encoding="utf-8") as log:
        log.write("| {:<10} | {:<8} | {:<30} | {:<30} | {:<10} |\n".format(
            "Type", "PID", "Local Addr", "Remote Addr", "Status"
        ))
        log.write("|" + "-" * 98 + "|\n")

        while psutil.pid_exists(pid):
            try:
                all_procs = [psutil.Process(pid)]
                all_procs += all_procs[0].children(recursive=True)
                for proc in all_procs:
                    try:
                        conns = proc.connections(kind='inet')
                        for conn in conns:
                            key = (proc.pid, conn.laddr, conn.raddr, conn.status)
                            if key in seen:
                                continue
                            seen.add(key)
                            TOOL_RESULTS["Network Connections"] += 1
                            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
                            remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
                            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                            log.write("| {:<10} | {:<8} | {:<30} | {:<30} | {:<10} |\n".format(
                                proto, proc.pid, local, remote, conn.status
                            ))
                            log.flush()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
            except psutil.NoSuchProcess:
                break
            time.sleep(interval)


def out_network():
    network_log_path = os.path.join(results_dir, "network_activity.txt")
    if not os.path.exists(network_log_path):
        print("\nNo network activity detected.")
    else:
        os.startfile(network_log_path)

# === CLEANUP ===
def Cleanup():
    print("-> Cleaning up temporary files:")

    # Remove working temp files
    for path in [PML_Path, CSV_Path, task_before_path, task_after_path, reg_before_path, reg_after_path]:
        if os.path.exists(path):
            os.remove(path)
            print(f"    -> Removed: {path}")

    # Remove handle_temp directory (used during handle polling)
    handle_temp_dir = os.path.join(working_dir, "handle_temp")
    if os.path.exists(handle_temp_dir):
        for file in os.listdir(handle_temp_dir):
            file_path = os.path.join(handle_temp_dir, file)
            if os.path.isfile(file_path):
                os.remove(file_path)
        os.rmdir(handle_temp_dir)
        print(f"    -> Removed: {handle_temp_dir}")

def show_results(path: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write("=== Summary of Tool Analysis ===\n\n")
        for tool, count in TOOL_RESULTS.items():
            f.write(f"{tool:<25}: {count}\n")
    print(f" -> Summary written to: {path}")
    os.startfile(path)


# === MAIN ===
def main():
    global TARGET_PROC
    print("\nEnter name of the malicious process you want to monitor,\n(Wildcard (*) allowed)")
    TARGET_PROC = input("Process name: ").strip().lower()

    tasks_snapshot(task_before_path)
    Run_PM()
    save_registry_snapshot(reg_before_path)
    
    child_log_path = os.path.join(results_dir, "child_processes.txt")

    pid = wait_for_process(TARGET_PROC)
 
    handle_thread = threading.Thread(
    target=track_process_handles,
    args=(Handle_Path, pid, working_dir, Handle_Output)
    )

    handle_thread.start()
    time.sleep(1)  # Give some time for the handle thread to start
    
    child_log_path = os.path.join(results_dir, "child_processes.txt")
    child_thread = threading.Thread(target=track_spawned_processes, args=(pid, child_log_path))
    child_thread.start()

    network_thread = threading.Thread(
        target=monitor_network_connections,
        args=(pid, network_log_path)
    )
    network_thread.start()

    network_thread.join()
    handle_thread.join()
    child_thread.join()

    print("\n-> Process completed, closing down.\n")
    
    Terminate()
    Convert_Output()

    save_registry_snapshot(reg_after_path)
    diff_registry_snapshots(reg_before_path, reg_after_path, reg_dif_path)
   
    tasks_snapshot(task_after_path)
    before = filter_MS_tasks(task_before_path)
    after = filter_MS_tasks(task_after_path)
    new_tasks = dif_tasks(before, after)
    TOOL_RESULTS["New Tasks Found"] = len(new_tasks)
    write_dif(new_tasks, task_dif_path)
    
    filter_output(csv_path=CSV_Path, output_path=Output_Path)
    
    out_children(child_log_path)
    out_reg(reg_dif_path)
    out_tasks(task_dif_path)
    out_handle(Handle_Output)
    out_network()

    Cleanup()
    show_results(os.path.join(results_dir, "summary.txt")) 

if __name__ == "__main__":
    main()
