// File Scanner Utility
// Scans files/directories for known malicious hashes, supports quarantine, deletion, and file info
// Cross-platform: Windows and Unix-like OS support

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <conio.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#else
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#endif

#define MALWARE_HASH "e99a18c428cb38d5f260853678922e03" // Example malicious hash
#define HASH_SIZE 16

// Lists all running processes on the system
void listProcesses() {
#ifdef _WIN32
    DWORD processes[1024], count;
    if (!EnumProcesses(processes, sizeof(processes), &count)) return;
    count /= sizeof(DWORD);

    printf("[+] Running processes:\n");
    for (unsigned int i = 0; i < count; i++) {
        if (processes[i]) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
            if (hProcess) {
                char processName[MAX_PATH] = "<unknown>";
                HMODULE module;
                DWORD needed;
                if (EnumProcessModules(hProcess, &module, sizeof(module), &needed)) {
                    GetModuleBaseName(hProcess, module, processName, sizeof(processName) / sizeof(char));
                }
                printf("PID %u: %s\n", processes[i], processName);
                CloseHandle(hProcess);
            }
        }
    }
#else
    DIR *procDir = opendir("/proc");
    if (!procDir) return;
    struct dirent *entry;
    printf("[+] Running processes:\n");
    while ((entry = readdir(procDir)) != NULL) {
        if (isdigit(entry->d_name[0])) {
            char cmdPath[256];
            snprintf(cmdPath, sizeof(cmdPath), "/proc/%s/cmdline", entry->d_name);
            FILE *cmdFile = fopen(cmdPath, "r");
            if (cmdFile) {
                char cmd[256];
                if (fgets(cmd, sizeof(cmd), cmdFile)) {
                    printf("PID %s: %s\n", entry->d_name, cmd);
                }
                fclose(cmdFile);
            }
        }
    }
    closedir(procDir);
#endif
}

// Checks if a file exists
int fileExists(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file) {
        fclose(file);
        return 1;
    }
    return 0;
}

// Computes the MD5 hash of a file
void computeMD5(const char *filename, unsigned char *result) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("[!] Unable to open file: %s\n", filename);
        return;
    }

    unsigned char data[1024];
    size_t bytes;

#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
    while ((bytes = fread(data, 1, sizeof(data), file)) != 0)
        CryptHashData(hHash, data, bytes, 0);
    DWORD hashLen = HASH_SIZE;
    CryptGetHashParam(hHash, HP_HASHVAL, result, &hashLen, 0);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
#else
    MD5_CTX mdContext;
    MD5_Init(&mdContext);
    while ((bytes = fread(data, 1, sizeof(data), file)) != 0)
        MD5_Update(&mdContext, data, bytes);
    MD5_Final(result, &mdContext);
#endif

    fclose(file);
}

// Prints a hash in hexadecimal format
void printHash(const unsigned char *hash) {
    for (int i = 0; i < HASH_SIZE; i++)
        printf("%02x", hash[i]);
    printf("\n");
}

// Scans a single file for a known malicious hash
void scanFile(const char *filename) {
    if (!fileExists(filename)) {
        printf("[!] File not found: %s\n", filename);
        return;
    }

    unsigned char hash[HASH_SIZE];
    char computedHash[HASH_SIZE * 2 + 1] = {0};

    computeMD5(filename, hash);
    printf("MD5 Hash: ");
    printHash(hash);

    // Convert hash to hex string
    for (int i = 0; i < HASH_SIZE; i++)
        sprintf(&computedHash[i * 2], "%02x", hash[i]);

    // Compare against known malicious hash
    if (strcmp(computedHash, MALWARE_HASH) == 0) {
        printf("[!] Warning: File is flagged as malicious\n");
    } else {
        printf("[+] File appears clean\n");
    }
}

// Moves a file to the quarantine directory
void quarantineFile(const char *filename) {
    if (!fileExists(filename)) {
        printf("[!] File not found: %s\n", filename);
        return;
    }

    char quarantinePath[256];
    snprintf(quarantinePath, sizeof(quarantinePath), "quarantine/%s", filename);

#ifdef _WIN32
    CreateDirectory("quarantine", NULL);
    if (!MoveFile(filename, quarantinePath)) {
        printf("[!] Failed to quarantine file: %s\n", filename);
        return;
    }
#else
    mkdir("quarantine", 0755);
    if (rename(filename, quarantinePath) != 0) {
        printf("[!] Failed to quarantine file: %s\n", filename);
        return;
    }
#endif
    printf("[+] File moved to quarantine: %s\n", quarantinePath);
}

// Deletes a file from the file system
void deleteFile(const char *filename) {
    if (!fileExists(filename)) {
        printf("[!] File not found: %s\n", filename);
        return;
    }

    if (remove(filename) == 0) {
        printf("[+] File deleted: %s\n", filename);
    } else {
        printf("[!] Failed to delete file: %s\n", filename);
    }
}

// Displays info about a file (size, etc.)
void getFileInfo(const char *filename) {
    if (!fileExists(filename)) {
        printf("[!] File not found: %s\n", filename);
        return;
    }

#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (GetFileAttributesEx(filename, GetFileExInfoStandard, &fileInfo)) {
        printf("[+] File information for %s:\n", filename);
        printf("  Size: %llu bytes\n", ((unsigned long long)fileInfo.nFileSizeHigh << 32) + fileInfo.nFileSizeLow);
    } else {
        printf("[!] Unable to retrieve file information.\n");
    }
#else
    struct stat fileStat;
    if (stat(filename, &fileStat) == 0) {
        printf("[+] File information for %s:\n", filename);
        printf("  Size: %ld bytes\n", fileStat.st_size);
    } else {
        printf("[!] Unable to retrieve file information.\n");
    }
#endif
}

// Scans all regular files in a directory for malware
void scanDirectory(const char *directory) {
#ifdef _WIN32
    WIN32_FIND_DATA findFileData;
    char searchPath[256];
    snprintf(searchPath, sizeof(searchPath), "%s\\*", directory);
    HANDLE hFind = FindFirstFile(searchPath, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("[!] Directory not found: %s\n", directory);
        return;
    }
    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char filePath[256];
            snprintf(filePath, sizeof(filePath), "%s\\%s", directory, findFileData.cFileName);
            scanFile(filePath);
        }
    } while (FindNextFile(hFind, &findFileData) != 0);
    FindClose(hFind);
#else
    DIR *dir = opendir(directory);
    if (!dir) {
        printf("[!] Directory not found: %s\n", directory);
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char filePath[256];
            snprintf(filePath, sizeof(filePath), "%s/%s", directory, entry->d_name);
            scanFile(filePath);
        }
    }
    closedir(dir);
#endif
}

// Displays the main menu and handles user input
void showMenu() {
    printf("\n== File Scanning Utilities ==\n");
    printf("1. List running processes\n");
    printf("2. Scan a file for malware\n");
    printf("3. Scan a directory for malware\n");
    printf("4. Quarantine a file\n");
    printf("5. Delete a file\n");
    printf("6. Get file information\n");
    printf("7. Exit\n");
    printf("Enter your choice: ");
}

int main(void) {
    char choice;
    char filename[256];
    char directory[256];

    while (1) {
        showMenu();
        choice = getchar();
        getchar(); // consume newline

        switch (choice) {
            case '1':
                listProcesses();
                break;
            case '2':
                printf("Enter file name to scan: ");
                fgets(filename, sizeof(filename), stdin);
                filename[strcspn(filename, "\n")] = 0;
                scanFile(filename);
                break;
            case '3':
                printf("Enter directory to scan: ");
                fgets(directory, sizeof(directory), stdin);
                directory[strcspn(directory, "\n")] = 0;
                scanDirectory(directory);
                break;
            case '4':
                printf("Enter file name to quarantine: ");
                fgets(filename, sizeof(filename), stdin);
                filename[strcspn(filename, "\n")] = 0;
                quarantineFile(filename);
                break;
            case '5':
                printf("Enter file name to delete: ");
                fgets(filename, sizeof(filename), stdin);
                filename[strcspn(filename, "\n")] = 0;
                deleteFile(filename);
                break;
            case '6':
                printf("Enter file name to get info: ");
                fgets(filename, sizeof(filename), stdin);
                filename[strcspn(filename, "\n")] = 0;
                getFileInfo(filename);
                break;
            case '7':
                printf("Exiting...\n");
                exit(0);
            default:
                printf("[!] Invalid choice. Please try again.\n");
        }
    }
    return 0;
}
