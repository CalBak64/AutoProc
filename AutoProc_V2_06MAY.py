import subprocess
import os
import time
import csv
import sys

def Get_Script_Path() -> str:  # Find script path
    return os.path.dirname(os.path.abspath(__file__))

Script_path = Get_Script_Path()

# Find PROCMON paths
Proc_Path = os.path.join(Script_path, "processmonitor", "procmon.exe")
Filter_Path = os.path.join(Script_path, "processmonitor", "BasicFilter1.PMC")
PML_Path = os.path.join(Script_path, "processmonitor", "RawOutput.pml")
CSV_Path = os.path.join(Script_path, "processmonitor", "RawOutput.csv")
Output_Path = os.path.join(Script_path, "processmonitor", "FilteredOutput.txt")

wait = 5

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
    #print("-> Cleaning up.")
    if os.path.exists(PML_Path):
        os.remove(PML_Path)
        print("-> PML Removed.")

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

# Main execution
def main():
    Run_PM()
    print(" ______________________________________ \n")
    input("     [*] Detonate malware now. [*] \n Press enter when malware has finished. \n ______________________________________ \n")

    Terminate()
    Convert_Output()
    Cleanup()
    filter_output(csv_path=CSV_Path, output_path=Output_Path)

if __name__ == "__main__":
    main()
