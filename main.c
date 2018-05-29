#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "argon2.h"

#define ADDRESS_LEN   20
#define HASH_LEN      32
#define DIFFICULTY    0x0FFFFFFF
#define NONCE_CHUNK   128

/**
 * Argon2
 */
uint32_t t_cost = 1;
uint32_t m_cost = (1 << 16);
uint32_t parallelism = 1;

uint8_t *salt = (uint8_t *) "semux-pow-argon2";
size_t salt_len = 16;

struct task {
    uint8_t *address; // wallet address
    uint64_t timestamp; // milliseconds
    uint32_t from; // inclusive
    uint32_t to; // exclusive
};

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *mine(void *arg) {
    struct task *t = (struct task *) arg;

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

    for (uint32_t n = t->from; n < t->to; n++) {
        // increase nonce
        data[ADDRESS_LEN + 8] = n >> 24;
        data[ADDRESS_LEN + 9] = n >> 16;
        data[ADDRESS_LEN + 10] = n >> 8;
        data[ADDRESS_LEN + 11] = n;

        // compute hash
        argon2i_hash_raw(t_cost, m_cost, parallelism, data, sizeof(data), salt, salt_len, hash, HASH_LEN);

        // check diff
        uint32_t diff = ((uint32_t) hash[0] << 24) | ((uint32_t) hash[1] << 16) | ((uint32_t) hash[2] << 8)
                | (uint32_t) hash[3];
        if (diff <= DIFFICULTY) {
            pthread_mutex_lock(&mutex);
            for (int i = 0; i < sizeof(data); i++) {
                printf("%02x", data[i]);
            }
            printf(" => ");
            for (int i = 0; i < HASH_LEN; i++) {
                printf("%02x", hash[i]);
            }
            printf("\n");
            pthread_mutex_unlock(&mutex);
        }
    }

    return NULL;
}

uint64_t current_timestamp() {
    struct timeval t;
    gettimeofday(&t, NULL);

    return t.tv_sec * 1000LL + t.tv_usec / 1000LL;
}

int main(void) {
    // TODO: parse arguments
    size_t num_threads = 8;
    uint8_t address[ADDRESS_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

    while (1) {
        uint64_t timestamp = current_timestamp();

        struct task *tasks[num_threads];
        pthread_t threads[num_threads];

        for (size_t i = 0; i < num_threads; i++) {
            tasks[i] = (struct task*) malloc(sizeof(struct task));
            tasks[i]->address = address;
            tasks[i]->timestamp = timestamp;
            tasks[i]->from = NONCE_CHUNK * i;
            tasks[i]->to = NONCE_CHUNK * (i + 1);

            if (pthread_create(&threads[i], NULL, mine, tasks[i])) {
                fprintf(stderr, "Error creating thread\n");
                return 1;
            }
        }

        for (size_t i = 0; i < num_threads; i++) {
            if (pthread_join(threads[i], NULL)) {
                fprintf(stderr, "Error joining thread\n");
                return 2;
            }
            free(tasks[i]);
        }

        printf("Hash rate: %ld H/s\n", NONCE_CHUNK * num_threads * 1000 / (current_timestamp() - timestamp));
    }

    return 0;
}
