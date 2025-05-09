import subprocess
import os
import time
import csv
import sys
import winreg 
import json
from deepdiff import DeepDiff

def Get_Script_Path() -> str:  # Find script path
    return os.path.dirname(os.path.abspath(__file__))

Script_path = Get_Script_Path()


#PROCMON
# Find PROCMON paths
Proc_Path = os.path.join(Script_path, "processmonitor", "procmon.exe")
Filter_Path = os.path.join(Script_path, "processmonitor", "BasicFilter1.PMC")
PML_Path = os.path.join(Script_path, "processmonitor", "RawOutput.pml")
CSV_Path = os.path.join(Script_path, "processmonitor", "RawOutput.csv")
Output_Path = os.path.join(Script_path, "processmonitor", "FilteredOutput.txt")

wait = 5

##############################################################
# Run Procmon
def Run_PM():
    if not os.path.exists(Proc_Path):
        print("[!] Cannot find Procmon. Please ensure the \"ProcessMonitor\" folder is located in the same directory as the script.")
        sys.exit(0)
    else:
        print("-> Launching Procmon with general filtering.")
        subprocess.Popen(
            [
                Proc_Path,
                "/AcceptEula",
                "/Quiet",
                "/Minimized",
                "/LoadConfig", Filter_Path,
                "/Backingfile", PML_Path
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(wait)

# Terminate Procmon
def Terminate():
    subprocess.run(
        [
            Proc_Path,
            "/Terminate"
        ],
        check=True,
        capture_output=True,
        text=True
    )

# Convert .pml to .csv
def Convert_Output():
    subprocess.run(
        [
            Proc_Path,
            "/openlog", PML_Path,
            "/Saveas", CSV_Path
        ],
        check=True,
        capture_output=True,
        text=True
    )

# Remove .pml file
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
    

# Get unique operation names from CSV
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

# Prompt user for operations to include
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

# Prompt user for process name filter
def prompt_for_process_name() -> str:
    proc_name = input("\n Press Enter to see full output \n         - OR - \n Enter name of malicious process: ").strip()
    return proc_name.lower() if proc_name else ""

# Filter by selected operations and optional process name
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

    with open(csv_path, "r", encoding="utf-8-sig") as infile, \
         open(output_path, "w", encoding="utf-8") as outfile:

        reader = csv.DictReader(infile)
        reader.fieldnames = [field.strip().strip('"') for field in reader.fieldnames]
        matches = 0
        rows = []

        for row in reader:
            op = row["Operation"].strip()
            proc = row["Process Name"].strip()
            
            if op in selected_ops and (not selected_proc or proc.lower() == selected_proc):
                matches += 1
                rows.append(row)
            
        header_format = "| {:^20} | {:^25} | {:^25} | {:^8} | {:^15} | {}"
        row_format = "| {:^20} | {:^25} | {:^25} | {:^8} | {:^15} | {}\n"
        outfile.write(header_format.format("Time", "Process", "Operation", "PID", "Result", "Path"))
        outfile.write(f"{'[*] Total Hits: ':>25} {matches}\n")
        outfile.write("_" * 200 + "\n")


        for row in rows:
                outfile.write(row_format.format(
                    row["Time of Day"],
                    row["Process Name"],
                    row["Operation"],
                    row["PID"],
                    row["Result"],
                    row["Path"]
                ))
                outfile.write("-" * 200 + "\n")

        if matches == 0:
            print("[!] No matching operations found.")
        else:
            print(f"-> {matches} matching operations written to: {output_path}.")
            os.startfile(output_path)

##############################################################
#SCHTASKS
task_before_path = os.path.join(Script_path, "Schtasks", "tasks_before.csv")
task_after_path = os.path.join(Script_path, "Schtasks", "tasks_after.csv")
task_dif_path = os.path.join(Script_path, "Schtasks", "New_tasks.txt")

def tasks_snapshot(path: str):
    result = subprocess.run(
        ["schtasks", "/Query", "/FO", "CSV", "/V"],
        capture_output=True,
        text=True,
        check=True
    )
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
        for task in diff:
            f.write(f"{task['TaskName']} | {task['Status']} | {task.get('Next Run Time', '')} | {task.get('Task Run', '')}\n")
def out_tasks(task_dif_path: str):
    if os.path.getsize(task_dif_path) == 0:
        print("No new tasks detected. Removing task text file.")
        os.remove(task_dif_path)
    else: 
        os.startfile(task_dif_path)
             
##############################################################
#REG
reg_path = os.path.join(Script_path, "Reg")

reg_before_path = os.path.join(reg_path, "reg_before.json")
reg_after_path = os.path.join(reg_path, "reg_after.json")
reg_dif_path = os.path.join(reg_path, "reg_dif.txt")

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
    hives = [
        (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
        (winreg.HKEY_CURRENT_USER, "HKCU")
    ]
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
        if os.path.exists(reg_dif_path):
            os.remove(reg_dif_path)
        return 

    with open(output, "w", encoding="utf-8") as f:
        f.write("Registry modifications:\n\n")
        for change_type, changes in diff.items():
            f.write(f"[{change_type}]\n")
            for change in changes:
                f.write(f"- {change.path()}\n")
            f.write("\n")
def out_reg(reg_dif_path: str):
    if not os.path.exists(reg_dif_path):
        print("\nNo registry modifications detected. Removing reg text file.")
        
    else: 
        os.startfile(reg_dif_path)






# Main execution
def main():
    tasks_snapshot(task_before_path)
    Run_PM()
    save_registry_snapshot(reg_before_path)

    print("_" * 50 + "\n")
    print("     [*] Detonate malware now. [*] \n Press enter when malware has finished. \n")
    input("_" * 50 + "\n")

    Terminate() #Procmon
    Convert_Output() #Procmon

    save_registry_snapshot(reg_after_path) #reg
    diff_registry_snapshots(reg_before_path, reg_after_path, reg_dif_path) #reg
    out_reg(reg_dif_path) #reg

    tasks_snapshot(task_after_path) #schtasks
    before = filter_MS_tasks(task_before_path) #schtasks
    after = filter_MS_tasks(task_after_path) #schtasks
    new_tasks = dif_tasks(before, after) #schtasks
    write_dif(new_tasks, task_dif_path) #schtasks
    out_tasks(task_dif_path) #schtasks

    filter_output(csv_path=CSV_Path, output_path=Output_Path) #Procmon
    
    Cleanup()
    

if __name__ == "__main__":
    main()
