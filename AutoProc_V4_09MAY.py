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

# ============================== SETUP ==============================
def Get_Script_Path() -> str:
    return os.path.dirname(os.path.abspath(__file__))

Script_path = Get_Script_Path()
TARGET_PROC = None  # Global target process name

# Paths
output_dir = os.path.join(Script_path, "0_outputs")

Proc_Path = os.path.join(Script_path, "1_processmonitor", "procmon.exe")
Filter_Path = os.path.join(Script_path, "1_processmonitor", "BasicFilter1.PMC")
PML_Path = os.path.join(Script_path, "1_processmonitor", "RawOutput.pml")
CSV_Path = os.path.join(Script_path, "1_processmonitor", "RawOutput.csv")
Output_Path = os.path.join(output_dir, "ProcFilteredOutput.txt")

Handle_Path = os.path.join(Script_path, "4_misc_tools", "handle.exe")
Handle_Output = os.path.join(output_dir, "handles_output.txt")

task_before_path = os.path.join(Script_path, "2_Schtasks", "tasks_before.csv")
task_after_path = os.path.join(Script_path, "2_Schtasks", "tasks_after.csv")
task_dif_path = os.path.join(output_dir, "New_tasks.txt")

reg_path = os.path.join(Script_path, "Reg")
reg_before_path = os.path.join(reg_path, "3_reg_before.json")
reg_after_path = os.path.join(reg_path, "3_reg_after.json")
reg_dif_path = os.path.join(reg_path, "3_reg_dif.txt")

wait = 5

# ============================== PROCMON ==============================
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
    # Check if Procmon is running
    procmon_running = any(
        proc.info['name'].lower() == "procmon.exe"
        for proc in psutil.process_iter(['name'])
    )
    if not procmon_running:
        print("[!] Procmon is not running. Skipping termination.")
        return

    # Terminate Procmon
    subprocess.run([Proc_Path, "/Terminate"], check=True, capture_output=True, text=True)

def Convert_Output():
    subprocess.run([Proc_Path, "/openlog", PML_Path, "/Saveas", CSV_Path], check=True, capture_output=True, text=True)

def get_unique_operations(csv_path: str) -> list:
    unique_ops = set()
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [field.strip().strip('"') for field in reader.fieldnames]
        for row in reader:
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
        row_format = "| {:<20} | {:<25} | {:<25} | {:<8} | {:<15} | {}\n"
        outfile.write(header_format.format("Time", "Process", "Operation", "PID", "Result", "Path"))
        outfile.write("|" + "-" * 198 + "|\n")
        for row in rows:
            outfile.write(row_format.format(
                row["Time of Day"],
                row["Process Name"],
                row["Operation"],
                row["PID"],
                row["Result"],
                row["Path"]
            ))
        if matches == 0:
            print("[!] No matching operations found.")
        else:
            print(f"-> {matches} matching operations written to: {output_path}.")
            os.startfile(output_path)

# ============================== SCHTASKS ==============================
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
                task['TaskName'],
                task['Status'],
                task.get('Next Run Time', ''),
                task.get('Task Run', '')
            ))

def out_tasks(task_dif_path: str):
    if os.path.getsize(task_dif_path) == 0:
        print("No new tasks detected. Removing task text file.")
        os.remove(task_dif_path)
    else:
        os.startfile(task_dif_path)

# ============================== REGISTRY ==============================
def snapshot_registry(hive, hive_name=""):
    snapshot = {}
    def walk(key, path=""):
        try:
            i = 0
            while True:
                subkey = winreg.EnumKey(key, i)
                with winreg.OpenKey(key, subkey) as child:
                    walk(child, f"{path}\\{subkey}")
                i += 1
        except OSError:
            pass
        try:
            j = 0
            values = {}
            while True:
                name, val, _ = winreg.EnumValue(key, j)
                values[name] = val
                j += 1
            if values:
                snapshot[path] = values
        except OSError:
            pass
    with winreg.ConnectRegistry(None, hive) as reg:
        with winreg.OpenKey(reg, "") as root:
            walk(root, hive_name)
    return snapshot

def save_registry_snapshot(path: str):
    full_snapshot = {}
    hives = [(winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")]
    for hive, name in hives:
        print(f"-> Scanning {name}...")
        full_snapshot[name] = snapshot_registry(hive, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(full_snapshot, f, indent=2)

def diff_registry_snapshots(before: str, after: str, output: str):
    with open(before, "r", encoding="utf-8") as f1:
        reg_before = json.load(f1)
    with open(after, "r", encoding="utf-8") as f2:
        reg_after = json.load(f2)
    diff = DeepDiff(reg_before, reg_after, view='tree')
    if not diff:
        if os.path.exists(output):
            os.remove(output)
        return
    with open(output, "w", encoding="utf-8") as f:
        f.write("| {:<20} | {:<80} |\n".format("ChangeType", "Path"))
        f.write("|" + "-" * 105 + "|\n")
        for change_type, changes in diff.items():
            for change in changes:
                f.write("| {:<20} | {:<80} |\n".format(change_type, change.path()))

def out_reg(reg_dif_path: str):
    if not os.path.exists(reg_dif_path):
        print("\nNo registry modifications detected.")
    else:
        os.startfile(reg_dif_path)

# ============================== HANDLE TRACKING ==============================
def poll_handles_during_lifetime(handle_path: str, pid: int, temp_dir: str, interval: int = 2):
    counter = 0
    handle_temp_dir = os.path.join(Script_path, "4_misc_tools", "handle_temp")
    os.makedirs(handle_temp_dir, exist_ok=True)

    print("[*] Polling handles...")
    while psutil.pid_exists(pid):
        temp_file = os.path.join(handle_temp_dir, f"handle_{counter}.txt")
        with open(temp_file, "w", encoding="utf-8") as f:
            subprocess.run([
                handle_path,
                "-p", str(pid),
                "-a",
                "-nobanner"
            ], stdout=f, text=True)
        counter += 1
        time.sleep(interval)

    print(f"[+] Handle polling complete. {counter} snapshots saved to: {handle_temp_dir}")
    merge_handle_snapshots(handle_temp_dir, os.path.join(temp_dir, "handles_output.txt"))
    
    # Clean up temporary files
    for file in os.listdir(handle_temp_dir):
        os.remove(os.path.join(handle_temp_dir, file))
    os.rmdir(handle_temp_dir)

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

    print(f"[+] Deduplicated handle dump written to: {output_path}")

def track_process_handles(handle_path: str, merged_output_path: str, temp_dir: str):
    print(f"-> Waiting for process [*] '{TARGET_PROC}' [*] to start...")
    print(f"[*] DETONATE MALWARE NOW. [*]")

    pid = None
    while True:
        for p in psutil.process_iter(['pid', 'name']):
            if fnmatch.fnmatch(p.info['name'].lower(), TARGET_PROC):
                pid = p.info['pid']
                print(f"[+] Found match: {p.info['name']} (PID: {pid})")
                break
        if pid:
            break
        time.sleep(1)

    poll_handles_during_lifetime(handle_path, pid, temp_dir)


def out_handle(merged_output_path: str):
    if not os.path.exists(merged_output_path):
        print("\nNo process handles detected.")
    else:
        os.startfile(merged_output_path)
# ============================ Clean Up ============================

def Cleanup():
    print("-> Cleaning up: ")
    if os.path.exists(PML_Path):
        os.remove(PML_Path)
        os.remove(CSV_Path)
        print("    -> Proc files removed.")        
    if os.path.exists(task_before_path):
        os.remove(task_before_path)
        os.remove(task_after_path)
        print("    -> Schtasks files removed.")
    if os.path.exists(reg_before_path):
        os.remove(reg_before_path)
        os.remove(reg_after_path)
        print("    -> Reg files removed.")

# ============================== MAIN ==============================
def main():
    global TARGET_PROC
    print("Enter name of the malicious process you want to monitor,\n(wildcard allowed, e.g. calc*)")
    TARGET_PROC = input("Process name: ").strip().lower()

    tasks_snapshot(task_before_path)
    Run_PM()
    save_registry_snapshot(reg_before_path)
    track_process_handles(Handle_Path, Handle_Output, output_dir)

    Terminate()
    Convert_Output()

    save_registry_snapshot(reg_after_path)
    diff_registry_snapshots(reg_before_path, reg_after_path, reg_dif_path)
    out_reg(reg_dif_path)

    tasks_snapshot(task_after_path)
    before = filter_MS_tasks(task_before_path)
    after = filter_MS_tasks(task_after_path)
    new_tasks = dif_tasks(before, after)
    write_dif(new_tasks, task_dif_path)
    out_tasks(task_dif_path)

    filter_output(csv_path=CSV_Path, output_path=Output_Path)
    out_handle(Handle_Output)
    Cleanup()

if __name__ == "__main__":
    main()


