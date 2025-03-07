/* Parallel tsdec - ptsdec
 *
 * Copyright (c) 2025 - Terry Hardie
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Version 0.1a
*/


#include <dvbcsa/dvbcsa.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


pthread_mutex_t muEncryptedPackets;
pthread_cond_t muconEncryptedPacketsAdded;

pthread_mutex_t muDecryptedPackets;
pthread_cond_t muconDecryptedPacketsAdded;

int nPacketsToBeDecrypted = 0;
int nPacketsToBeWritten = 0;
#define FILE_WRITER_SLOTS 1024000
//#define FILE_WRITER_SLOTS 32

struct cryptedPacket {
    unsigned char data[188];
    size_t originalFilePos;
    int offsetToDecrypt;
    struct cryptedPacket *pNext;
};

struct cryptedPacket *packetsToDecryptHead = NULL;
struct cryptedPacket *packetsToDecryptTail = NULL;

struct cryptedPacket *decryptedPacketsHead = NULL;
struct cryptedPacket *decryptedPacketsTail = NULL;

struct cryptedPacket **decryptedPacketsArray;
int *decryptedPacketsArrayVacancy;
size_t *decryptedPacketsArrayExpectedOffset;

struct dvbcsa_key_s *key;

void addPacketToDecryptedQueue(struct cryptedPacket *thisPacket) {
    pthread_mutex_lock(&muDecryptedPackets);
    if (nPacketsToBeWritten > 50000) {
        pthread_mutex_unlock(&muDecryptedPackets);
        usleep(10000);
        pthread_mutex_lock(&muDecryptedPackets);
    }
    thisPacket->pNext = NULL;
    if (decryptedPacketsTail == NULL) {
        decryptedPacketsTail = decryptedPacketsHead = thisPacket;
    } else {
        decryptedPacketsTail->pNext = thisPacket;
        decryptedPacketsTail = thisPacket;
    }
    nPacketsToBeWritten++;
    pthread_cond_signal(&muconDecryptedPacketsAdded);
    pthread_mutex_unlock(&muDecryptedPackets);
}

void addPacketToDecryptedArray(struct cryptedPacket *thisPacket) {
/*
    while (!__atomic_compare_exchange(&decryptedPacketsArray[(thisPacket->originalFilePos / 188) % FILE_WRITER_SLOTS], &pSlot, &thisPacket, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        // Slot is full. We have to wait for the file write to free to slot
        pSlot = NULL;
        usleep(100);
    }
*/
    pthread_mutex_lock(&muDecryptedPackets);
    while(
            decryptedPacketsArrayVacancy[(thisPacket->originalFilePos / 188) % FILE_WRITER_SLOTS] != 1
            ||  decryptedPacketsArrayExpectedOffset[(thisPacket->originalFilePos / 188) % FILE_WRITER_SLOTS] != thisPacket->originalFilePos
            ) {
        pthread_mutex_unlock(&muDecryptedPackets);
        usleep(100);
        pthread_mutex_lock(&muDecryptedPackets);
    }
    decryptedPacketsArray[(thisPacket->originalFilePos / 188) % FILE_WRITER_SLOTS] = thisPacket;
    decryptedPacketsArrayVacancy[(thisPacket->originalFilePos / 188) % FILE_WRITER_SLOTS] = 0;

    thisPacket->pNext = NULL;
    //printf("addPacketToDecryptedArray: Added packet for pos %zu in slot %zu\n", thisPacket->originalFilePos, (thisPacket->originalFilePos / 188) % FILE_WRITER_SLOTS);
    //pthread_mutex_lock(&muDecryptedPackets);
    nPacketsToBeWritten++;
    pthread_mutex_unlock(&muDecryptedPackets);
}

void getPacketFromDecryptedArray(struct cryptedPacket **thisPacket, size_t nFilePos) {
    struct cryptedPacket *pSlot = NULL;
    time_t started = time(NULL);

/*
    while(__atomic_compare_exchange(&decryptedPacketsArray[(nFilePos / 188) % FILE_WRITER_SLOTS], &pSlot, &pItemToPutinArray, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        // If this is true, it means NULL as swapped into NULL, so the slot was empty. Keep trying
        usleep(100);
        time_t now = time(NULL);

        if (now - 5 > started) {
            fprintf(stderr, "Waited more than 5 seconds for packet to arrive... Pos: %zu\n", nFilePos);
            sleep(1);
        }
    }
*/
    pthread_mutex_lock(&muDecryptedPackets);
    while(decryptedPacketsArrayVacancy[(nFilePos / 188) % FILE_WRITER_SLOTS] == 1) {
        pthread_mutex_unlock(&muDecryptedPackets);
        usleep(100);
        time_t now = time(NULL);

        if (now - 5 > started) {
            fprintf(stderr, "Waited more than 5 seconds for packet to arrive... Pos: %zu\n", nFilePos);
            sleep(1);
        }
        pthread_mutex_lock(&muDecryptedPackets);
    }
    pSlot = decryptedPacketsArray[(nFilePos / 188) % FILE_WRITER_SLOTS];
    decryptedPacketsArray[(nFilePos / 188) % FILE_WRITER_SLOTS] = NULL;
    decryptedPacketsArrayVacancy[(nFilePos / 188) % FILE_WRITER_SLOTS] = 1;
    decryptedPacketsArrayExpectedOffset[(nFilePos / 188) % FILE_WRITER_SLOTS] = nFilePos + (188 * FILE_WRITER_SLOTS);

    if (pSlot->originalFilePos != nFilePos) {
        fprintf(stderr, "Got out of order packet for slot %zu. Expected pos %zu, got %zu\n", (nFilePos / 188) % FILE_WRITER_SLOTS, nFilePos, pSlot->originalFilePos);
        *thisPacket = NULL;
        return;
    }
    //printf("getPacketFromDecryptedArray: Got packet from array for pos %zu from slot %zu\n", pSlot->originalFilePos, (nFilePos / 188) % FILE_WRITER_SLOTS);
    pSlot->pNext = NULL;
    *thisPacket = pSlot;


    //pthread_mutex_lock(&muDecryptedPackets);
    nPacketsToBeWritten--;
    pthread_mutex_unlock(&muDecryptedPackets);
}


void addPacketToEncryptedQueue(struct cryptedPacket *thisPacket) {
    pthread_mutex_lock(&muEncryptedPackets);
    thisPacket->pNext = NULL;
    if (packetsToDecryptTail == NULL) {
        packetsToDecryptTail = packetsToDecryptHead = thisPacket;
    } else {
        packetsToDecryptTail->pNext = thisPacket;
        packetsToDecryptTail = thisPacket;
    }
    nPacketsToBeDecrypted++;
    //printf("addPacketToEncryptedQueue: Added packet to EncryptedQueue for pos %zu\n", thisPacket->originalFilePos);
    pthread_cond_signal(&muconEncryptedPacketsAdded);
    pthread_mutex_unlock(&muEncryptedPackets);
}

void *DecryptionThread(void *pszArg) {
    //printf("DecryptionThread alive\n");
    while (1) {
        struct cryptedPacket *thisPacket;
        pthread_mutex_lock(&muEncryptedPackets);
        if (packetsToDecryptHead == NULL) {
            pthread_cond_wait(&muconEncryptedPacketsAdded, &muEncryptedPackets);
        }
        if (packetsToDecryptHead == NULL) {
            pthread_mutex_unlock(&muEncryptedPackets);
            continue;
        }
        thisPacket = packetsToDecryptHead;
        packetsToDecryptHead = thisPacket->pNext;
        if (packetsToDecryptTail == thisPacket) {
            packetsToDecryptTail = NULL;
        }
        thisPacket->pNext = NULL;
        nPacketsToBeDecrypted--;
        pthread_mutex_unlock(&muEncryptedPackets);

        if (thisPacket->offsetToDecrypt >= 188) {
            fprintf(stderr, "DecryptionThread: Offset to decypt out of range!\n");
        }
        dvbcsa_decrypt(key, thisPacket->data + thisPacket->offsetToDecrypt, 188 - thisPacket->offsetToDecrypt);
        thisPacket->data[3] &= 0x3f; // clear top 2 high bits for encryption

        //printf("Decrypted packet for file pos: %d\n", thisPacket->originalFilePos);
        //addPacketToDecryptedQueue(thisPacket);
        addPacketToDecryptedArray(thisPacket);
    }
}

void *FileWriterThread(void *pszArg) {
    //printf("FileWriterThread alive\n");
    char *pszFilename = (char *) pszArg;
    FILE *outFile;
    if ((outFile = fopen(pszArg, "wb")) == NULL) {
        printf("ERROR: File %s cannot be opened. error: %s\n", pszFilename, strerror(errno));
        return NULL;
    }
    struct cryptedPacket *thisPacket;
    size_t filePos = 0;
    while (1) {
        getPacketFromDecryptedArray(&thisPacket, filePos);
        if (thisPacket->originalFilePos != filePos) {

        }
        fwrite(thisPacket->data, 1, 188, outFile);
        //printf("Wrote packet for file pos: %d\n", thisPacket->originalFilePos);
        filePos += 188;
        free(thisPacket);
    }
}


void *FileWriterThreadLL(void *pszArg) {
    printf("FileWriterThread alive\n");
    FILE *outFile;
    if ((outFile = fopen("b.ts", "wb")) == NULL) {
        printf("ERROR: File cannot be opened.\n");
        return NULL;
    }
    struct cryptedPacket *thisPacket;
    size_t filePos = 0;
    while (1) {
        pthread_mutex_lock(&muDecryptedPackets);
        if (decryptedPacketsHead == NULL) {
            //printf("FileWriterThread: Waiting for signal\n");
            pthread_cond_wait(&muconDecryptedPacketsAdded, &muDecryptedPackets);
        }
        struct cryptedPacket *prevPacket = NULL;
        thisPacket = decryptedPacketsHead;
        while (thisPacket != NULL) {
            //printf("FileWriterThread: Need pos %d. Checking decrypted packet pos %d\n", filePos, thisPacket->originalFilePos);
            if (thisPacket->originalFilePos == filePos) {
                if (prevPacket != NULL) {
                    prevPacket->pNext = thisPacket->pNext;
                }
                if (decryptedPacketsTail == thisPacket) {
                    decryptedPacketsTail = prevPacket;
                }
                if (decryptedPacketsHead == thisPacket) {
                    decryptedPacketsHead = thisPacket->pNext;
                }
                nPacketsToBeWritten--;
                break;
            } else {
                prevPacket = thisPacket;
                thisPacket = thisPacket->pNext;
            }
        }
        pthread_mutex_unlock(&muDecryptedPackets);
        if (thisPacket != NULL) {
            thisPacket->pNext = NULL;
            fwrite(thisPacket->data, 1, 188, outFile);
            //printf("Wrote packet for file pos: %d\n", thisPacket->originalFilePos);
            filePos += 188;
            free(thisPacket);
        } else {
            //printf("Didn't find. Looping.\n");
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <source filename> <dest filename> <number of decrypt threads> <16 hex for CW>\n", argv[0]);
        return -1;
    }
    char *pszSourceFile = argv[1];
    char *pszDestFile = argv[2];
    unsigned char szCW[8];

    int nThreads = atoi(argv[3]);

    for (int counter = 0; counter < 8; counter++) {
        int nVal;
        if (sscanf(argv[4]+(counter * 2), "%02x", &nVal) != 1) {
            fprintf(stderr, "Unable to parse CW. Do not include any 0x. Just 16 hex characters: %s", argv[3]);
            return -1;
        }
        szCW[counter] = nVal;
    }
    dvbcsa_cw_t cw;
    memcpy(cw, szCW, sizeof(cw));

    key = dvbcsa_key_alloc();

    decryptedPacketsArray = malloc(sizeof(struct cryptedPacket *) * FILE_WRITER_SLOTS);
    memset(decryptedPacketsArray, 0, sizeof(struct cryptedPacket *) * FILE_WRITER_SLOTS);

    decryptedPacketsArrayVacancy = malloc(sizeof(int) * FILE_WRITER_SLOTS);
    decryptedPacketsArrayExpectedOffset = malloc(sizeof(size_t) * FILE_WRITER_SLOTS);

    int nExpectedFilePos = 0;
    for (int counter = 0; counter < FILE_WRITER_SLOTS; counter ++) {
        decryptedPacketsArrayExpectedOffset[counter] = nExpectedFilePos;
        decryptedPacketsArrayVacancy[counter] = 1;
        nExpectedFilePos += 188;
    }

    dvbcsa_key_set(cw, key);

    FILE* inFile;

    if ((inFile = fopen(pszSourceFile, "rb")) == NULL) {
        printf("ERROR: File %s cannot be opened. error = %s\n", pszSourceFile, strerror(errno));
        return -1;
    }

    if (-1 == pthread_mutex_init(&muEncryptedPackets, NULL)) {
        printf("Failed to initialize mutex for sending data to file. Error %d\n", errno);
        return -1;
    }
    if (-1 == pthread_cond_init(&muconEncryptedPacketsAdded, NULL)) {
        printf("Failed to initialize condition for sending data to file. Error %d\n", errno);
        return -1;
    }
    if (-1 == pthread_mutex_init(&muDecryptedPackets, NULL)) {
        printf("Failed to initialize mutex for sending data to file. Error %d\n", errno);
        return -1;
    }
    if (-1 == pthread_cond_init(&muconDecryptedPacketsAdded, NULL)) {
        printf("Failed to initialize condition for sending data to file. Error %d\n", errno);
        return -1;
    }


    pthread_t hDecryptionThreads[64];
    pthread_t hFileWriterThread;
    pthread_attr_t ThreadAttr;

    pthread_attr_init(&ThreadAttr);
    pthread_attr_setscope(&ThreadAttr, PTHREAD_SCOPE_SYSTEM);
    for (int counter = 0; counter < nThreads; counter++) {
        pthread_create(&hDecryptionThreads[counter], &ThreadAttr, DecryptionThread, NULL);
    }

    pthread_create(&hFileWriterThread, &ThreadAttr, FileWriterThread, pszDestFile);

    size_t nBytesRead;
    size_t filePos = 0;
    unsigned char *buf;
    time_t lastReport = 0;
    while(1) {
        if (nPacketsToBeDecrypted < FILE_WRITER_SLOTS) {
            struct cryptedPacket *thisPacket = malloc(sizeof(struct cryptedPacket));
            buf = thisPacket->data;
            nBytesRead = fread(buf, 1, 188, inFile);
            if (nBytesRead == 0) {
                break;
            }
            if (nBytesRead != 188) {
                fprintf(stderr, "fread() failed: %zu\n", nBytesRead);
                return -1;
            }
            if (buf[0] != 0x47) {
                fprintf(stderr, "ts sync byte incorrect: 0x%x\n", buf[0]);
                return -1;
            }
            unsigned int tsc, adp, tei, pid, adpLength = 0;

            pid = ((buf[1] & 0x1f) << 8) | buf[2];

            if (pid == 0x1fff) {
                // NULL pid
                continue;
            }

            tsc = (buf[3] & 0xc0) >> 6;
            tei = (buf[1] & 0x80) >> 7;
            adp = (buf[3] & 0x30) >> 4;
            if (adp == 3) {
                adpLength = buf[4] + 1;
            } else if (adp == 0) {
                fprintf(stderr, "Adaption field not supported: 0x%x\n", adp);
                continue;
            }
            if (tei) {
                continue;
            }
            thisPacket->originalFilePos = filePos;
            switch (tsc) {
                case 0x2:
                case 0x3:
                    // Scrambled with odd or even key
                    thisPacket->offsetToDecrypt = 4 + adpLength;
                    addPacketToEncryptedQueue(thisPacket);
                    break;
                case 0x1:
                    fprintf(stderr, "TSC not supported: 0x%x\n", tsc);
                    return -1;
                case 0x0:
                    //addPacketToDecryptedQueue(thisPacket);
                    addPacketToDecryptedArray(thisPacket);
            }
            filePos += 188;
        } else {
            usleep(10000);
        }

        time_t now = time(NULL);
        if (lastReport != now) {
            printf("FilePos: %zu\tToDecrypt: %d\tToWrite: %d\n", filePos, nPacketsToBeDecrypted, nPacketsToBeWritten);
            lastReport = now;
        }
    }
    // Wait for queues to drain
    while (nPacketsToBeDecrypted > 0 || nPacketsToBeWritten > 0) {
        time_t now = time(NULL);
        if (lastReport != now) {
            printf("FilePos: %zu\tToDecrypt: %d\tToWrite: %d\n", filePos, nPacketsToBeDecrypted, nPacketsToBeWritten);
            lastReport = now;
        }
        usleep(10000);
    }

    return 0;
}
