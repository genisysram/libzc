/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2017 Marc Ferland
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "ptext_private.h"
#include "list.h"

#define k2(index) w->key2_final[index]
#define k1(index) w->key1_final[index]
#define k0(index) w->key0_final[index]
#define cipher(index) w->ciphertext[index]
#define plaintext(index) w->plaintext[index]

struct worker {
    uint32_t key2_final[13];
    uint32_t key1_final[13];
    uint32_t key0_final[13];
    const uint8_t *plaintext;         /* points to ptext->plaintext */
    const uint8_t *ciphertext;        /* points to ptext->ciphertext */
    const uint8_t (*lsbk0_lookup)[2]; /* points to ptext->lsbk0_lookup */
    const uint32_t *lsbk0_count;      /* points to ptext->lsbk0_count */
    const struct key2r *k2r;          /* points to ptext->k2r */
    struct zc_key inter_rep;
    pthread_t thread_id;
    pthread_mutex_t *mutex;
    uint32_t *next;
    bool found;
    struct zc_crk_ptext *ptext;
    struct list_head workers;
};

static void compute_one_intermediate_int_rep(uint8_t cipher, uint8_t *plaintext, struct zc_key *k)
{
    k->key2 = crc32inv(k->key2, msb(k->key1));
    k->key1 = ((k->key1 - 1) * MULTINV) - lsb(k->key0);
    uint32_t tmp = k->key2 | 3;
    uint32_t key3 = lsb((tmp * (tmp ^ 1)) >> 8);
    *plaintext = cipher ^ key3;
    k->key0 = crc32inv(k->key0, *plaintext);
}

static int compute_intermediate_internal_rep(struct worker *w, struct zc_key *k)
{
    uint32_t i = 4;

    k->key2 = k2(i);
    k->key1 = k1(i);
    /* key0 is already set */

    do {
        uint8_t p;
        compute_one_intermediate_int_rep(cipher(i - 1), &p, k);
        if (p != plaintext(i - 1))
            break;
        --i;
    } while (i > 0);

    if (i == 0) {
        w->inter_rep = *k;
        return 0;
    }
    return -1;
}

static bool verify_key0(const struct worker *w, uint32_t key0,
                        uint32_t start, uint32_t stop)
{
    for (uint32_t i = start; i < stop; ++i) {
        key0 = crc32(key0, plaintext(i));
        if (mask_lsb(key0) != k0(i + 1))
            return false;
    }
    return true;
}

static void key_found(struct worker *w)
{
    w->found = true;
}

static void compute_key0(struct worker *w)
{
    struct zc_key k = { .key0 = 0x0, .key1 = 0x0, .key2 = 0x0 };

    /* calculate key0_6{0..15} */
    k.key0 = (k0(7) ^ crc_32_tab[k0(6) ^ plaintext(6)]) << 8;
    k.key0 = (k.key0 | k0(6)) & 0x0000ffff;

    /* calculate key0_5{0..23} */
    k.key0 = (k.key0 ^ crc_32_tab[k0(5) ^ plaintext(5)]) << 8;
    k.key0 = (k.key0 | k0(5)) & 0x00ffffff;

    /* calculate key0_4{0..31} */
    k.key0 = (k.key0 ^ crc_32_tab[k0(4) ^ plaintext(4)]) << 8;
    k.key0 = (k.key0 | k0(4));

    /* verify against known bytes */
    if (!verify_key0(w, k.key0, 4, 12))
        return;

    if (compute_intermediate_internal_rep(w, &k) == 0)
        key_found(w);
}

static void recurse_key1(struct worker *w, uint32_t current_idx)
{
    if (current_idx == 3) {
        compute_key0(w);
        return;
    }

    uint32_t key1i = k1(current_idx);
    uint32_t rhs_step1 = (key1i - 1) * MULTINV;
    uint32_t rhs_step2 = (rhs_step1 - 1) * MULTINV;
    uint8_t diff = msb(rhs_step2 - (mask_msb(k1(current_idx - 2))));

    for (uint32_t c = 2; c != 0; --c, --diff) {
        for (uint32_t i = 0; i < w->lsbk0_count[diff]; ++i) {
            uint32_t lsbkey0i = w->lsbk0_lookup[diff][i];
            if (mask_msb(rhs_step1 - lsbkey0i) == mask_msb(k1(current_idx - 1))) {
                w->key1_final[current_idx - 1] = rhs_step1 - lsbkey0i;
                w->key0_final[current_idx] = lsbkey0i;
                recurse_key1(w, current_idx - 1);
            }
        }
    }
}

static void compute_key1(struct worker *w)
{
    /* find matching msb, section 3.3 from Biham & Kocher */
    for (uint32_t i = 0; i < pow2(24); ++i) {
        const uint32_t key1_12_tmp = mask_msb(k1(12)) | i;
        const uint32_t key1_11_tmp = (key1_12_tmp - 1) * MULTINV;
        if (mask_msb(key1_11_tmp) == mask_msb(k1(11))) {
            w->key1_final[12] = key1_12_tmp;
            recurse_key1(w, 12);
        }
    }
}

static uint32_t compute_key1_msb(struct worker *w, uint32_t current_idx)
{
    const uint32_t key2i = k2(current_idx);
    const uint32_t key2im1 = k2(current_idx - 1);
    return (key2i << 8) ^ crc_32_invtab[key2i >> 24] ^ key2im1;
}

static int recurse_key2(struct worker *w, struct ka **array, uint32_t current_idx)
{
    uint8_t key3im1;
    uint8_t key3im2;

    if (current_idx == 1) {
        compute_key1(w);
        return 0;
    }

    key3im1 = generate_key3(w, current_idx - 1);
    key3im2 = generate_key3(w, current_idx - 2);

    /* empty array before appending new keys */
    ka_empty(array[current_idx - 1]);

    if (key2r_compute_single(k2(current_idx),
                             array[current_idx - 1],
                             key2r_get_bits_15_2(w->k2r, key3im1),
                             key2r_get_bits_15_2(w->k2r, key3im2),
                             KEY2_MASK_8BITS))
        return -1;

    ka_uniq(array[current_idx - 1]);

    for (uint32_t i = 0; i < array[current_idx - 1]->size; ++i) {
        w->key2_final[current_idx - 1] = ka_at(array[current_idx - 1], i);
        w->key1_final[current_idx] = compute_key1_msb(w, current_idx) << 24;
        if (recurse_key2(w, array, current_idx - 1))
            return -1;
    }

    return 0;
}

static void ptext_final_deinit(struct ka **key2)
{
    for (uint32_t i = 0; i < 12; ++i) {
        if (key2[i]) {
            ka_free(key2[i]);
            key2[i] = NULL;
        }
    }
}

static int ptext_final_init(struct ka **key2)
{
    memset(key2, 0, sizeof(struct ka *));
    for (uint32_t i = 0; i < 12; ++i) {
        /* 64: probably too much but will work everytime */
        if (ka_alloc(&key2[i], 64)) {
            ptext_final_deinit(key2);
            return -1;
        }
    }
    return 0;
}

/* ZC_EXPORT int zc_crk_ptext_attack(struct zc_crk_ptext *ptext, struct zc_key *out_key) */
/* { */
/*     struct ka *array[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; */
/*     struct worker w; */

/*     if (ptext_final_init(array)) */
/*         return -1; */

/*     memset(&w, 0, sizeof(struct worker)); */

/*     w.plaintext = ptext->plaintext; */
/*     w.ciphertext = ptext->ciphertext; */
/*     w.lsbk0_lookup = ptext->lsbk0_lookup; */
/*     w.lsbk0_count = ptext->lsbk0_count; */
/*     w.ptext = ptext; */

/*     ptext->found = false; */
/*     pthread_mutex_init(&ptext->mutex, NULL); */
/*     for (uint32_t i = 0; i < ptext->key2->size; ++i) { */
/*         w.key2_final[12] = ptext->key2->array[i]; */
/*         if (recurse_key2(&w, array, 12)) */
/*             break; */
/*         if (ptext->found) { */
/*             out_key->key0 = w.inter_rep.key0; */
/*             out_key->key1 = w.inter_rep.key1; */
/*             out_key->key2 = w.inter_rep.key2; */
/*             break; */
/*         } */
/*     } */
/*     pthread_mutex_destroy(&ptext->mutex); */

/*     ptext_final_deinit(array); */
/*     return (ptext->found == true ? 0 : -1); */
/* } */

static void *worker(void *p)
{
    struct ka *array[12];
    struct worker *w = (struct worker *)p;
    uint32_t i;

    if (ptext_final_init(array))
        return NULL;

    while (1) {
        pthread_mutex_lock(w->mutex);
        if (w->ptext->found) {
            pthread_mutex_unlock(w->mutex);
            break;
        }
        i = (*w->next)++;
        pthread_mutex_unlock(w->mutex);
        w->key2_final[12] = w->ptext->key2->array[i];
        if (recurse_key2(w, array, 12))
            break;
        if (w->found) {
            pthread_mutex_lock(w->mutex);
            w->ptext->found = true;
            pthread_mutex_unlock(w->mutex);
            break;
        }
    }
    return NULL;
}

static void dealloc_workers(struct list_head *head)
{
    struct worker *w, *tmp;
    list_for_each_entry_safe(w, tmp, head, workers) {
        list_del(&w->workers);
        free(w);
    }
}

static int alloc_workers(const struct zc_crk_ptext *ptext,
                         struct list_head *head,
                         pthread_mutex_t *mutex,
                         uint32_t *next,
                         size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        struct worker *w = calloc(1, sizeof(struct worker));

        if (!w) {
            dealloc_workers(head);
            return -1;
        }

        w->plaintext = ptext->plaintext;
        w->ciphertext = ptext->ciphertext;
        w->lsbk0_lookup = ptext->lsbk0_lookup;
        w->lsbk0_count = ptext->lsbk0_count;
        w->k2r = ptext->k2r;
        w->mutex = mutex;
        w->next = next;

        list_add(&w->workers, head);
    }

    return 0;
}

ZC_EXPORT int zc_crk_ptext_attack(struct zc_crk_ptext *ptext, struct zc_key *out_key, size_t count)
{
    struct list_head head;
    pthread_mutex_t mutex;
    uint32_t next = 0;
    struct worker *w;
    int err;

    pthread_mutex_init(&mutex, NULL);

    INIT_LIST_HEAD(&head);

    err = alloc_workers(ptext, &head, &mutex, &next, count);
    if (err)
        goto end;

    list_for_each_entry(w, &head, workers) {
        if (pthread_create(&w->thread_id, NULL, worker, w)) {
            perror("pthread_create failed");
            goto end;           /* TODO: cancel the other threads */
        }
    }

    err = -1;
    list_for_each_entry(w, &head, workers) {
        pthread_join(w->thread_id, NULL);
        if (w->found) {
            *out_key = w->inter_rep;
            err = 0;
        }
    }

end:
    pthread_mutex_destroy(&mutex);
    return err;
}

ZC_EXPORT int zc_crk_ptext_find_internal_rep(const struct zc_key *start_key,
                                             const uint8_t *ciphertext, size_t size,
                                             struct zc_key *internal_rep)
{
    struct zc_key k;
    uint32_t i;

    /* the cipher text also includes the 12 prepended bytes */
    if (size < 12)
        return -1;

    i = size - 1;
    k = *start_key;
    do {
        uint8_t p;
        compute_one_intermediate_int_rep(ciphertext[i], &p, &k);
    } while (i--);

    *internal_rep = k;
    return 0;
}