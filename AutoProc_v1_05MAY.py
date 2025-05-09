import subprocess
import os
import time
import csv

def Get_Script_Path() -> str: #Find script path
    return os.path.dirname(os.path.abspath(__file__))

Script_path = Get_Script_Path()
#Find PROCMON paths
Proc_Path = os.path.join(Script_path, "processmonitor", "procmon.exe")
Filter_Path = os.path.join(Script_path, "processmonitor", "BasicFilter1.PMC")
PML_Path = os.path.join(Script_path, "processmonitor", "RawOutput.pml")
CSV_Path = os.path.join(Script_path, "processmonitor", "RawOutput.csv")
Output_Path = os.path.join(Script_path, "processmonitor", "FilteredOutput.txt")

wait = 5

#Run Procmon
## Need to add output line || Adjust input filter for generalized purpose
def Run_PM():
    print("[*] Launching Procmon with general filtering. [*]")
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

def Terminate():
    subprocess.run(
        [Proc_Path,
         "/Terminate"
        ],
        check=True,
        capture_output=True,
        text=True
    )
def Convert_Output():
    subprocess.run(
        [Proc_Path,
        "/openlog", PML_Path,
        "/Saveas", CSV_Path
        ],
        check=True,
        capture_output=True,
        text=True
    )
def Cleanup():
    print("[*] Cleaning Up [*]")
    if os.path.exists(PML_Path):
        os.remove(PML_Path)
        print("Files Cleaned.")

#User Input process name
def prompt_for_process_name() -> str:
    proc_name = input("\nEnter name of malicious process: ").strip()
    return proc_name.lower() if proc_name else ""


# Enumerating Operations
def get_unique_operations(csv_path: str) -> list:
                        # Extract unique operations from the CSV.
    unique_ops = set()
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        # Patch: Handle BOM in fieldnames
        if reader.fieldnames and reader.fieldnames[0].startswith('\ufeff'):
            reader.fieldnames[0] = reader.fieldnames[0].replace('\ufeff', '')
        for row in reader:
            op = row.get("Operation", "").strip()
            if op:
                unique_ops.add(op)
    return sorted(unique_ops)
def prompt_for_operations(operations: list) -> set:
                    # Prompt user with a numbered list to choose operations.
    print("\nSelect operations to output:")
    for i, op in enumerate(operations, start=1):
        print(f"[{i}] {op}")

    choices = input("\nEnter operation numbers (e.g., 1,3,5): ")
    selected = set()
    try:
        indices = [int(i.strip()) for i in choices.split(",") if i.strip()]
        for i in indices:
            if 1 <= i <= len(operations):
                selected.add(operations[i - 1])
    except ValueError:
        print("[!] Invalid input.")
    return selected

#Output Filter Master
def filter_output(csv_path: str, output_path: str):
                    # Filter CSV by selected operations and export to TXT.
    if not os.path.exists(csv_path):
        print(f"[!] CSV file not found: {csv_path}")
        return

    selected_proc = prompt_for_process_name()
    operations = get_unique_operations(csv_path)
    selected_ops = prompt_for_operations(operations)
    
    if not selected_ops:
        print("[!] No operations selected.")
        return

    with open(csv_path, "r", encoding="utf-8", errors="ignore") as infile, \
         open(output_path, "w", encoding="utf-8") as outfile:

        reader = csv.DictReader(infile)
        # Patch: Handle BOM in fieldnames
        if reader.fieldnames and reader.fieldnames[0].startswith('\ufeff'):
            reader.fieldnames[0] = reader.fieldnames[0].replace('\ufeff', '')
        reader.fieldnames = [field.strip().strip('"') for field in reader.fieldnames]
        matches = 0

        for row in reader:
            proc = row["Process Name"].strip()
            op = row["Operation"].strip()

            if op in selected_ops and (not selected_proc or proc.lower() == selected_proc):
                matches += 1
                outfile.write(f"{row['Time of Day']} | {row['Process Name']} | {row['Operation']} | {row['PID']} | {row['Result']} | {row['Path']}\n")

        if matches == 0:
            print("[!] No matching operations or processes found.")
        else:
            print(f"[*] {matches} matching operations written to: {output_path}")
            os.startfile(output_path)  # Only works on Windows



def main():
    Run_PM()
    print("[*] Detonate malware now. [*]") ###### DETONATION ########
    time.sleep(wait)
    input("Press ENTER when malware has finished.")
    Terminate()
    Convert_Output()
    Cleanup()
    filter_output(csv_path=CSV_Path, output_path=Output_Path)



if __name__ == "__main__":
    main()


## TO DO
    #Procmon output to CSV(?)
    #Procmon output filtering
    #Regshot inc.
    #Schtasks inc. (include system tasks)
    #
    #