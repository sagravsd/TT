#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <shellapi.h>
#include <vector>

// Function to check if the program is running with elevated privileges
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID administratorsGroup;

    // Allocate and initialize a SID for the administrators group
    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &administratorsGroup)) {
        // Check whether the token has the administrator SID
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    return isAdmin;
}

// Function to restart the program with elevated privileges
void RequestAdminPrivileges() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)) == 0) {
        std::cerr << "Failed to retrieve module path. Exiting." << std::endl;
        exit(1);
    }

    SHELLEXECUTEINFO sei = { sizeof(sei) };
    sei.lpVerb = L"runas";  // Verb to request elevation
    sei.lpFile = szPath;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;

    if (!ShellExecuteEx(&sei)) {
        std::cerr << "Failed to elevate process. Exiting." << std::endl;
        exit(1);
    }
}

// Function to list tasks (verbose: tasklist /V)
void ListTasksVerbose() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot" << std::endl;
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::wcout << L"Process Name: " << pe32.szExeFile << std::endl;
            std::wcout << L"Process ID: " << pe32.th32ProcessID << std::endl;
            std::wcout << L"Thread Count: " << pe32.cntThreads << std::endl << std::endl;
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}

// Function to list services hosted by each process (equivalent to /SVC)
void ListServicesByProcess() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL) {
        std::cerr << "Failed to open Service Control Manager. Error code: " << GetLastError() << std::endl;
        return;
    }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    DWORD bufferSize = 4096; // Initial buffer size
    LPBYTE buffer = NULL;

    while (true) {
        buffer = (LPBYTE)malloc(bufferSize);
        if (buffer == NULL) {
            std::cerr << "Failed to allocate memory for services enumeration." << std::endl;
            CloseServiceHandle(hSCManager);
            return;
        }

        // Attempt to enumerate services
        if (EnumServicesStatusEx(
            hSCManager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            buffer,
            bufferSize,
            &bytesNeeded,
            &servicesReturned,
            &resumeHandle,
            NULL
        )) {
            // Enumeration succeeded; process the services
            break;
        }

        // If the error is ERROR_MORE_DATA, resize the buffer
        if (GetLastError() == ERROR_MORE_DATA) {
            free(buffer);
            bufferSize = bytesNeeded; // Update the buffer size to the required amount
        }
        else {
            std::cerr << "Failed to enumerate services. Error code: " << GetLastError() << std::endl;
            free(buffer);
            CloseServiceHandle(hSCManager);
            return;
        }
    }

    // Map services to their process IDs
    LPENUM_SERVICE_STATUS_PROCESS services = (LPENUM_SERVICE_STATUS_PROCESS)buffer;
    for (DWORD i = 0; i < servicesReturned; i++) {
        if (services[i].ServiceStatusProcess.dwProcessId != 0) {  // Only display valid PIDs
            std::wcout << L"Service Name: " << services[i].lpServiceName << std::endl;
            std::wcout << L"Display Name: " << services[i].lpDisplayName << std::endl;
            std::wcout << L"Process ID: " << services[i].ServiceStatusProcess.dwProcessId << std::endl;
            std::wcout << L"----------------------------------" << std::endl;
        }
        else {
            std::wcout << L"Service Name: " << services[i].lpServiceName << std::endl;
            std::wcout << L"Display Name: " << services[i].lpDisplayName << std::endl;
            std::wcout << L"Process ID: 0 (Kernel-mode or no associated process)" << std::endl;
        }
    }

    // Clean up
    free(buffer);
    CloseServiceHandle(hSCManager);
}

// Function to terminate a process and its child processes (equivalent to /T)
void KillProcessTree(DWORD parentPID) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot for process tree termination." << std::endl;
        return;
    }

    std::vector<DWORD> childPIDs;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ParentProcessID == parentPID) {
                childPIDs.push_back(pe32.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    // Terminate all child processes first
    for (DWORD pid : childPIDs) {
        KillProcessTree(pid);
    }

    // Terminate the parent process
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, parentPID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process for termination: " << parentPID << std::endl;
        return;
    }

    if (!TerminateProcess(hProcess, 0)) {
        std::cerr << "Failed to terminate process: " << parentPID << std::endl;
    }
    else {
        std::cout << "Terminated process: " << parentPID << std::endl;
    }

    CloseHandle(hProcess);
}

// Function to kill a task by its name
void KillTaskByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot" << std::endl;
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (processName == pe32.szExeFile) {
                KillProcessTree(pe32.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}

// Main function
int main() {
    // Check for administrative privileges
    if (!IsRunningAsAdmin()) {
        std::cout << "Program is not running with elevated privileges. Requesting admin rights...\n" << std::endl;
        RequestAdminPrivileges();
        return 0;
    }
    else {
        std::cout << "Program is running with elevated privileges.\n" << std::endl;
    }

    int choice;
    std::cout << "Task Manager Script" << std::endl;

    while (true) {
        std::cout << "\nChoose an option:\n";
        std::cout << "1. List tasks (verbose: tasklist /V)\n";
        std::cout << "2. List services running within each task (/SVC)\n";
        std::cout << "3. Kill task by PID (taskkill /PID)\n";
        std::cout << "4. Kill task by name (taskkill /IM)\n";
        std::cout << "5. Kill process tree (/T)\n";
        std::cout << "6. Exit\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice;

        switch (choice) {
        case 1:
            ListTasksVerbose();
            break;
        case 3: {
            DWORD pid;
            std::cout << "Enter PID of the process to kill: ";
            std::cin >> pid;
            KillProcessTree(pid);
            break;
        }
        case 4: {
            std::wstring processName;
            std::wcin.ignore(); // Clear input buffer
            std::wcout << L"Enter name of the process to kill: ";
            std::getline(std::wcin, processName);
            KillTaskByName(processName);
            break;
        }
        case 2:
            ListServicesByProcess();
            break;
        case 5: {
            DWORD pid;
            std::cout << "Enter PID of the process tree to kill: ";
            std::cin >> pid;
            KillProcessTree(pid);
            break;
        }
        case 6:
            std::cout << "Exiting..." << std::endl;
            return 0;
        default:
            std::cerr << "Invalid choice. Try again." << std::endl;
        }
    }

    return 0;
}
