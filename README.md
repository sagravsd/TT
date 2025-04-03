README 
==============================
Sysmon, Tasklist, Taskkill Emulator in C++
TT.exe (T for Tasklist and T for Taskkill)
==============================
Silvia Vargas
March 27, 2025
------------------------------
Description
------------------------------
This tool is a C++ application that mimics the functionality of the following Windows utilities:
- tasklist: Lists all currently running processes on the system. Switches used: /V and /SVC
- taskkill: Terminates a process by its PID. Switches used: /PID, /IM and /T
Scope: The script is tailored for local process management and does not handle remote systems 
    (i.e. Switches /S and /U) 
This tool is also used in conjunction with Sysmon-style logging.
------------------------------
Compilation Instructions
------------------------------
To compile this program from Visual Studio 2022:
1. Open the code project
2. Build it using CTRL+SHIFT+B. This will create an .exe file and it will save it at the location of your 
   choice when you created the project (i.e. C:\Dev)
------------------------------
Sysmon Config
------------------------------
This is the sysmon config file to

<Sysmon schemaversion="4.90">
  <EventFiltering>

    <!-- Track process creation for TT.exe -->
    <RuleGroup name="Process Creation" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="contains">TT.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Track process termination for TT.exe -->
    <RuleGroup name="Process Termination" groupRelation="or">
      <ProcessTerminate onmatch="include">
        <Image condition="contains">TT.exe</Image>
      </ProcessTerminate>
    </RuleGroup>

  </EventFiltering>
</Sysmon>

------------------------------
Apply Sysmon Config
------------------------------
Save the above as sysmon-config.xml
Apply it to Sysmon as follows:

sysmon -c "C:\Sysmon\sysmon-config.xml" -accepteula
sysmon -c "C:\Sysmon\sysmon-config.xml"

Other useful commands to troubleshoot:
cd C:\Sysmon
sysmon -h
sc query sysmon64
sysmon -c

------------------------------
Running the Tool
------------------------------
To run the tool:
1. Open the .exe file. This is the file referenced in the Compilation Instructions section.
------------------------------
Tool Features:
------------------------------
This tool features:
1. List all running processes (like tasklist)
2. Kill a process by PID (like taskkill)
3. Monitor a folder for file changes (like Sysmon)
------------------------------
Available Options (Menu):
------------------------------
When the tool starts, it displays a preset menu where you will be asked to choose an option:
1. List tasks (verbose: tasklist /V)
2. List services running within each task (/SVC)
3. Kill task by PID (taskkill /PID)
4. Kill task by name (taskkill /IM)
5. Kill process tree (/T)
6. Exit
------------------------------
Examples Using the Tool
------------------------------
This tool was used primarily testing Notepad. Below are some examples:
  Open Notepad > Select Option 1: Notepad will show a process running
  Select Option 3 and enter the Process ID for Notepad
  Open Notepad > Select Option 1: Notepad will show a process running
  Select Option 4 and enter Notepad.exe

After running the tool, check the Event Viewer to the Events recorded as per the sysmon config file.
Defensive Strategy for System Monitoring
------------------------------
The defensive strategy combines the C++ script  and the Sysmon configuration file to monitor, detect, and respond to suspicious system activities effectively as follows:

1. C++ Script:
   - Lists running processes and services for oversight.
   - Can terminates malicious processes and their child processes (`KillProcessTree`).
   - Ensures actions are performed with elevated privileges for maximum control.

2. Sysmon Configuration:
   - Logs process creation (Event ID 1) and termination (Event ID 5) specifically for `TT.exe`.
   - Provides detailed insights into process activity through Windows Event Viewer.

3. Integration:
   - Use Sysmon logs to track anomalous behavior, such as unexpected creation/termination of `TT.exe`.
   - Cross-verify Sysmon logs with real-time data from the script for inconsistencies.

4. Response Plan:
   - Automate process termination for flagged activities.
   - Collect forensic data before killing processes to ensure evidence for analysis.
------------------------------
5. Notes
------------------------------
- The following Windows APIs are included in this C++ script:

Privileges and Elevation: AllocateAndInitializeSid, CheckTokenMembership, ShellExecuteEx.
Process Management: CreateToolhelp32Snapshot, Process32First, Process32Next, TerminateProcess.
Service Management: OpenSCManager, EnumServicesStatusEx, CloseServiceHandle.
Memory Management: malloc, free, CloseHandle.
Error Handling: GetLastError.

It also uses native Windows APIs such as: ToolHelp32Snapshot, OpenProcess,
TerminateProcess, and CreateFile.

- Some features may require admin privileges, especially killing system-level processes. This script has this built in.
------------------------------
6. Contact
------------------------------
Q&A: sagravsd@gmail.com
------------------------------

# TT
