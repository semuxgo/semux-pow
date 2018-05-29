#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#include <sys/time.h>
#endif

#include "argon2.h"
#include "thread.h"

#define ADDRESS_LEN   20
#define HASH_LEN      32
#define DIFFICULTY    0x0FFFFFFF
#define NONCE_CHUNK   128

/**
 * Argon2 parameters
 */
uint32_t t_cost = 1;
uint32_t m_cost = (1 << 16);
uint32_t parallelism = 1;

/**
 * Hash salt
 */
uint8_t *salt = (uint8_t *) "semux-pow-argon2";
size_t salt_len = 16;

struct task {
    uint8_t *address; // wallet address
    uint64_t timestamp; // milliseconds
    uint32_t from; // inclusive
    uint32_t to; // exclusive
};

#if defined(_WIN32)
HANDLE mutex = CreateMutex(NULL, false, NULL);
#else
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

void *mine(void *arg) {
    struct task *t = (struct task *) arg;
    uint32_t nonce, diff;

    // hash holder
    uint8_t hash[HASH_LEN];

    // prepare data
    uint8_t data[ADDRESS_LEN + sizeof(uint64_t) + sizeof(uint32_t)];
    memcpy(data, t->address, ADDRESS_LEN);
    data[ADDRESS_LEN] = t->timestamp >> 56;
    data[ADDRESS_LEN + 1] = t->timestamp >> 48;
    data[ADDRESS_LEN + 2] = t->timestamp >> 40;
    data[ADDRESS_LEN + 3] = t->timestamp >> 32;
    data[ADDRESS_LEN + 4] = t->timestamp >> 24;
    data[ADDRESS_LEN + 5] = t->timestamp >> 16;
    data[ADDRESS_LEN + 6] = t->timestamp >> 8;
    data[ADDRESS_LEN + 7] = t->timestamp;

    for (nonce = t->from; nonce < t->to; nonce++) {
        // increase nonce
        data[ADDRESS_LEN + 8] = nonce >> 24;
        data[ADDRESS_LEN + 9] = nonce >> 16;
        data[ADDRESS_LEN + 10] = nonce >> 8;
        data[ADDRESS_LEN + 11] = nonce;

        // compute hash
        argon2i_hash_raw(t_cost, m_cost, parallelism, data, sizeof(data), salt, salt_len, hash, HASH_LEN);

        // check diff
        diff = ((uint32_t) hash[0] << 24) | ((uint32_t) hash[1] << 16) | ((uint32_t) hash[2] << 8) | (uint32_t) hash[3];
        if (diff <= DIFFICULTY) {
            size_t i;

#if defined(_WIN32)
            WaitForSingleObject(mutex, INFINITE);
#else
            pthread_mutex_lock(&mutex);
#endif
            for (i = 0; i < sizeof(data); i++) {
                printf("%02x", data[i]);
            }
            printf(" => ");
            for (i = 0; i < HASH_LEN; i++) {
                printf("%02x", hash[i]);
            }
            printf("\n");
#if defined(_WIN32)
            ReleaseMutex(mutex);
#else
            pthread_mutex_unlock(&mutex);
#endif
        }
    }

    argon2_thread_exit();
    return NULL;
}

uint64_t current_timestamp() {
#if defined(_WIN32)
    SYSTEMTIME tm;
    GetSystemTime(&tm);
    return tm.wSecond * 1000ULL + tm.wMilliseconds;
#else
    struct timeval tm;
    gettimeofday(&tm, NULL);
    return tm.tv_sec * 1000ULL + tm.tv_usec / 1000ULL;
#endif
}

int main(void) {
    // TODO: parse arguments
    uint8_t address[ADDRESS_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };
    size_t num_threads = 4, i;

    while (1) {
        uint64_t timestamp = current_timestamp();

        struct task *tasks = (struct task *) malloc(sizeof(struct task) * num_threads);
        argon2_thread_handle_t *threads = (argon2_thread_handle_t *) malloc(sizeof(argon2_thread_handle_t) * num_threads);

        for (i = 0; i < num_threads; i++) {
            tasks[i].address = address;
            tasks[i].timestamp = timestamp;
            tasks[i].from = NONCE_CHUNK * i;
            tasks[i].to = NONCE_CHUNK * (i + 1);

            if (argon2_thread_create(&threads[i], mine, &tasks[i])) {
                fprintf(stderr, "Error creating thread\n");
                return 1;
            }
        }

        for (i = 0; i < num_threads; i++) {
            if (argon2_thread_join(threads[i])) {
                fprintf(stderr, "Error joining thread\n");
                return 2;
            }
        }

        printf("Hash rate: %llu H/s\n", 1000ULL * NONCE_CHUNK * num_threads / (current_timestamp() - timestamp));
        free(tasks);
        free(threads);
    }

    return 0;
}
