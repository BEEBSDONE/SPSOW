#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

#define MAX_CONNECTIONS 1000

void createIpList(char[8], char[16], char[16], char[16], bool);
void startScan(int, char[8], char[16], char[16], char[16], bool);

void flush_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

bool file_exists_and_not_empty(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size > 0;
    }
    return false;
}

bool create_or_truncate_file(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file != NULL) {
        fclose(file);
        return true;
    }
    return false;
}

int main() {
    int port;
    char ipFirst[8] = "1.0.0.0";
    char ipLast[16] = "239.255.255.255";
    char ipBegin[16];
    char ipFinish[16];
    char askIp;
    bool allIp = false;
    char inputBuffer[100];
    char *endptr;

    while (1) {
        printf("Enter the port that you want to scan (0-65535):\n");
        if (fgets(inputBuffer, sizeof(inputBuffer), stdin) == NULL) {
            printf("Input error.\n");
            continue;
        }

        if (strchr(inputBuffer, '\n') == NULL) {
            printf("Input too long. Please enter a valid number.\n");
            flush_input_buffer();
            continue;
        }

        inputBuffer[strcspn(inputBuffer, "\n")] = '\0';

        errno = 0;
        long portLong = strtol(inputBuffer, &endptr, 10);

        if (endptr == inputBuffer) {
            printf("No digits were found. Please enter a valid integer.\n");
            continue;
        } else if (*endptr != '\0') {
            printf("Invalid characters found after the number. Please enter a valid integer.\n");
            continue;
        } else if ((errno == ERANGE && (portLong == LONG_MAX || portLong == LONG_MIN)) || (portLong > 65535 || portLong < 0)) {
            printf("Port number out of range. Please enter a number between 0 and 65535.\n");
            continue;
        } else {
            port = (int)portLong;
            printf("Port selected: %d\n", port);
            break;
        }
    }

    while (1) {
        printf("Do you want to scan all the world? (y/n)\n");
        if (fgets(inputBuffer, sizeof(inputBuffer), stdin) == NULL) {
            printf("Input error.\n");
            continue;
        }

        if (sscanf(inputBuffer, "%c", &askIp) != 1 || (askIp != 'y' && askIp != 'n')) {
            printf("Invalid input. Please enter 'y' or 'n'.\n");
        } else {
            break;
        }
    }

    if (askIp == 'y') {
        allIp = true;
        if (file_exists_and_not_empty("allIpList.txt")) {
            printf("The file allIpList.txt already exists and is not empty.\n");
            printf("Skipping IP generation and using the existing file for scanning.\n");
        } else {
            printf("You selected all the world!\n");
            printf("Creating IP list...\n");
            printf("This may take 1 hour! Be patient :)\n");
            createIpList(ipFirst, ipLast, ipBegin, ipFinish, allIp);
        }
        startScan(port, ipFirst, ipLast, ipBegin, ipFinish, allIp);
        printf("Scan is finished!\n");
    } else if (askIp == 'n') {
        if (create_or_truncate_file("rangeIpList.txt")) {
            printf("File rangeIpList.txt has been created.\n");
        } else {
            printf("Failed to create rangeIpList.txt. Exiting...\n");
            return 1;
        }

        while (1) {
            printf("Enter the first IP:\n");
            if (fgets(ipBegin, sizeof(ipBegin), stdin) == NULL) {
                printf("Input error.\n");
                continue;
            }

            ipBegin[strcspn(ipBegin, "\n")] = '\0';

            struct sockaddr_in sa;
            if (inet_pton(AF_INET, ipBegin, &(sa.sin_addr)) != 1) {
                printf("Invalid IP address format. Please enter a valid IPv4 address.\n");
            } else {
                break;
            }
        }

        while (1) {
            printf("Enter the last IP:\n");
            if (fgets(ipFinish, sizeof(ipFinish), stdin) == NULL) {
                printf("Input error.\n");
                continue;
            }

            ipFinish[strcspn(ipFinish, "\n")] = '\0';

            struct sockaddr_in sa;
            if (inet_pton(AF_INET, ipFinish, &(sa.sin_addr)) != 1) {
                printf("Invalid IP address format. Please enter a valid IPv4 address.\n");
            } else {
                break;
            }
        }

        printf("Creating IP List between %s and %s...\n", ipBegin, ipFinish);
        createIpList(ipFirst, ipLast, ipBegin, ipFinish, allIp);
        startScan(port, ipFirst, ipLast, ipBegin, ipFinish, allIp);
        printf("Scan is finished!\n");
    }

    return 0;
}

void createIpList(char ipFirst[8], char ipLast[16], char ipBegin[16], char ipFinish[16], bool allIp) {
    char ipStart[16];
    char ipEnd[16];

    if (allIp == true) {
        strcpy(ipStart, ipFirst);
        strcpy(ipEnd, ipLast);
    } else {
        strcpy(ipStart, ipBegin);
        strcpy(ipEnd, ipFinish);
    }

    unsigned char startSegments[4];
    unsigned char endSegments[4];
    char ipAddress[16];

    sscanf(ipStart, "%hhu.%hhu.%hhu.%hhu", &startSegments[0], &startSegments[1], &startSegments[2], &startSegments[3]);
    sscanf(ipEnd, "%hhu.%hhu.%hhu.%hhu", &endSegments[0], &endSegments[1], &endSegments[2], &endSegments[3]);

    FILE *pF;
    if (allIp) {
        pF = fopen("allIpList.txt", "w");
    } else {
        pF = fopen("rangeIpList.txt", "w");
    }

    while (1) {

        // Exclusion List
        // 10.0.0.0–10.255.255.255
        if (startSegments[0] == 10) {
            startSegments[0] = 11;
            startSegments[1] = 0;
            startSegments[2] = 0;
            startSegments[3] = 0;
            continue;
        }

        // 100.64.0.0–100.127.255.255
        if (startSegments[0] == 100 && (startSegments[1] >= 64 && startSegments[1] <= 127)) {
            startSegments[0] = 101;
            startSegments[1] = 0;
            startSegments[2] = 0;
            startSegments[3] = 0;
            continue;
        }

        // 127.0.0.0–127.255.255.255
        if (startSegments[0] == 127) {
            startSegments[0] = 128;
            startSegments[1] = 0;
            startSegments[2] = 0;
            startSegments[3] = 0;
            continue;
        }

        // 169.254.0.0–169.254.255.255
        if (startSegments[0] == 169 && startSegments[1] == 254) {
            startSegments[0] = 169;
            startSegments[1] = 255;
            startSegments[2] = 0;
            startSegments[3] = 0;
            continue;
        }

        // 172.16.0.0–172.31.255.255
        if (startSegments[0] == 172 && (startSegments[1] >= 16 && startSegments[1] <= 31)) {
            startSegments[0] = 172;
            startSegments[1] = 32;
            startSegments[2] = 0;
            startSegments[3] = 0;
            continue;
        }

        // 192.0.0.0–192.0.0.255
        if (startSegments[0] == 192 && startSegments[1] == 0 && startSegments[2] == 0) {
            startSegments[0] = 192;
            startSegments[1] = 0;
            startSegments[2] = 1;
            startSegments[3] = 0;
            continue;
        }

        // 192.0.2.0–192.0.2.255
        if (startSegments[0] == 192 && startSegments[1] == 0 && startSegments[2] == 2) {
            startSegments[0] = 192;
            startSegments[1] = 0;
            startSegments[2] = 3;
            startSegments[3] = 0;
            continue;
        }

        // 192.88.99.0–192.88.99.255
        if (startSegments[0] == 192 && startSegments[1] == 88 && startSegments[2] == 99) {
            startSegments[0] = 192;
            startSegments[1] = 88;
            startSegments[2] = 100;
            startSegments[3] = 0;
            continue;
        }

        // 192.168.0.0–192.168.255.255
        if (startSegments[0] == 192 && startSegments[1] == 168) {
            startSegments[0] = 193;
            startSegments[1] = 0;
            startSegments[2] = 0;
            startSegments[3] = 0;
            continue;
        }

        // 198.18.0.0–198.19.255.255
        if (startSegments[0] == 198 && (startSegments[1] == 18 || startSegments[1] == 19)) {
            startSegments[0] = 198;
            startSegments[1] = 20;
            startSegments[2] = 0;
            startSegments[3] = 0;
            continue;
        }

        // 198.51.100.0–198.51.100.255
        if (startSegments[0] == 198 && startSegments[1] == 51 && startSegments[2] == 100) {
            startSegments[0] = 198;
            startSegments[1] = 51;
            startSegments[2] = 101;
            startSegments[3] = 0;
            continue;
        }

        // 203.0.113.0–203.0.113.255
        if (startSegments[0] == 203 && startSegments[1] == 0 && startSegments[2] == 113) {
            startSegments[0] = 203;
            startSegments[1] = 0;
            startSegments[2] = 114;
            startSegments[3] = 0;
            continue;
        }

        // 224.0.0.0–239.255.255.255
        if (startSegments[0] >= 224 && startSegments[0] <= 239) {
            break; // These IPs are all excluded, so stop processing
        }

        // 233.252.0.0–233.252.0.255
        if (startSegments[0] == 233 && startSegments[1] == 252 && startSegments[2] == 0) {
            startSegments[0] = 233;
            startSegments[1] = 252;
            startSegments[2] = 1;
            startSegments[3] = 0;
            continue;
        }

        sprintf(ipAddress, "%u.%u.%u.%u", startSegments[0], startSegments[1], startSegments[2], startSegments[3]);

        fprintf(pF, "%s\n", ipAddress);

        if (startSegments[0] == endSegments[0] &&
            startSegments[1] == endSegments[1] &&
            startSegments[2] == endSegments[2] &&
            startSegments[3] == endSegments[3]) {
            break;
        }

        startSegments[3]++;
        for (int i = 3; i > 0; i--) {
            if (startSegments[i] == 0) {
                startSegments[i - 1]++;
            } else {
                break;
            }
        }
    }

    fclose(pF);
}

void startScan(int port, char ipFirst[8], char ipLast[16], char ipBegin[16], char ipFinish[16], bool allIp) {
    FILE *ipFile;
    FILE *resultsFile;
    char ipAddress[16];
    struct sockaddr_in target[MAX_CONNECTIONS];
    int sock[MAX_CONNECTIONS];
    fd_set fdset;
    struct timeval tv;
    int activeConnections = 0;
    int max_fd = 0;
    int i;

    if (allIp == true) {
        printf("Scanning all the world for port %d!\n", port);
    } else {
        printf("Scanning between %s and %s for port %d!\n", ipBegin, ipFinish, port);
    }

    if (allIp) {
        ipFile = fopen("allIpList.txt", "r");
    } else {
        ipFile = fopen("rangeIpList.txt", "r");
    }

    if (ipFile == NULL) {
        perror("Failed to open IP list file");
        return;
    }

    resultsFile = fopen("results.txt", "w");
    if (resultsFile == NULL) {
        perror("Failed to open results file");
        fclose(ipFile);
        return;
    }

    for (i = 0; i < MAX_CONNECTIONS; i++) {
        sock[i] = -1;
    }

    while (!feof(ipFile) || activeConnections > 0) {
        FD_ZERO(&fdset);
        max_fd = 0;
        for (i = 0; i < MAX_CONNECTIONS; i++) {
            if (sock[i] != -1) {
                FD_SET(sock[i], &fdset);
                if (sock[i] > max_fd) max_fd = sock[i];
            }
        }

        if (max_fd > 0) {
            tv.tv_sec = 0;
            tv.tv_usec = 200000;

            int result = select(max_fd + 1, NULL, &fdset, NULL, &tv);
            if (result > 0) {
                for (i = 0; i < MAX_CONNECTIONS; i++) {
                    if (sock[i] != -1 && FD_ISSET(sock[i], &fdset)) {
                        socklen_t len = sizeof(int);
                        int sock_err;
                        getsockopt(sock[i], SOL_SOCKET, SO_ERROR, &sock_err, &len);
                        if (sock_err == 0) {
                            fprintf(resultsFile, "%s:%d\n", inet_ntoa(target[i].sin_addr), port);
                        }
                        close(sock[i]);
                        sock[i] = -1;
                        activeConnections--;
                    }
                }
            } else if (result < 0) {
                perror("select() error");
                break;
            } else {
                for (i = 0; i < MAX_CONNECTIONS; i++) {
                    if (sock[i] != -1) {
                        close(sock[i]);
                        sock[i] = -1;
                        activeConnections--;
                    }
                }
            }
        }

        if (activeConnections < MAX_CONNECTIONS && !feof(ipFile) && fgets(ipAddress, sizeof(ipAddress), ipFile) != NULL) {
            ipAddress[strcspn(ipAddress, "\n")] = 0;

            for (i = 0; i < MAX_CONNECTIONS; i++) {
                if (sock[i] == -1) break;
            }

            sock[i] = socket(AF_INET, SOCK_STREAM, 0);
            if (sock[i] < 0) {
                perror("Socket creation failed");
                fclose(ipFile);
                fclose(resultsFile);
                return;
            }

            fcntl(sock[i], F_SETFL, O_NONBLOCK);

            target[i].sin_family = AF_INET;
            target[i].sin_port = htons(port);
            inet_pton(AF_INET, ipAddress, &target[i].sin_addr);

            if (connect(sock[i], (struct sockaddr *)&target[i], sizeof(target[i])) < 0) {
                if (errno != EINPROGRESS) {
                    close(sock[i]);
                    sock[i] = -1;
                } else {
                    activeConnections++;
                }
            }
        }

        if (feof(ipFile) && activeConnections == 0) {
            break;
        }
    }

    fclose(ipFile);
    fclose(resultsFile);

    printf("Scanning complete.\n");
}

