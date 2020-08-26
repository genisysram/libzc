/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2018 Marc Ferland
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ptext_private.h"
#include "libzc_private.h"
#include "pool.h"

#define KEY2_ARRAY_LEN (1 << 22)

static void generate_all_key2_bits_31_2(uint32_t *key2, const uint16_t *key2_bits_15_2)
{
	uint32_t i, j;
	for (i = 0; i < pow2(16); ++i)
		for (j = 0; j < 64; ++j)
			key2[i * 64 + j] = (i << 16) | key2_bits_15_2[j];
}

static uint32_t bits_1_0_key2i(uint32_t key2im1, uint32_t key2i)
{
	uint32_t tmp = key2im1 ^ crc_32_invtab[msb(key2i)];
	tmp = (tmp >> 8) & 0x3;      /* keep only bit 9 and 8 */
	return tmp;
}

static size_t generate_all_key2i_with_bits_1_0(uint32_t *key2i,
					       uint32_t key2i_frag,
					       const uint16_t *key2im1_bits_15_2)
{
	const uint32_t key2im1_bits_31_10 = (key2i_frag << 8) ^ crc_32_invtab[key2i_frag >> 24];
	const uint32_t key2im1_bits_15_10_rhs = key2im1_bits_31_10 & 0xfc00;
	size_t total = 0;

	for (int j = 0; j < 64; ++j) {
		const uint32_t key2im1_bits_15_10_lhs = key2im1_bits_15_2[j] & 0xfc00;

		/* the left and right hand side share 6 bits in position
		   [15..10]. See biham & kocher 3.1. */
		if (key2im1_bits_15_10_rhs == key2im1_bits_15_10_lhs) {
			uint32_t key2im1;
			key2im1 = key2im1_bits_31_10 & 0xfffffc00;
			key2im1 |= key2im1_bits_15_2[j];
			key2i[total++] = key2i_frag | bits_1_0_key2i(key2im1, key2i_frag);
		}
	}

	return total;
}

size_t key2r_compute_single(uint32_t key2i_plus_1,
			    uint32_t *key2i,
			    const uint16_t *key2i_bits_15_2,
			    const uint16_t *key2im1_bits_15_2,
			    uint32_t common_bits_mask)
{
	const uint32_t key2i_bits31_8 = (key2i_plus_1 << 8) ^ crc_32_invtab[key2i_plus_1 >> 24];
	const uint32_t key2i_bits15_10_rhs = key2i_bits31_8 & common_bits_mask;
	size_t total = 0;

	for (uint32_t i = 0; i < 64; ++i) {
		const uint32_t key2i_bits15_10_lhs = key2i_bits_15_2[i] & common_bits_mask;

		/* the left and right hand side share the same 6 bits in
		   position [15..10]. See biham & kocher 3.1. */
		if (key2i_bits15_10_rhs == key2i_bits15_10_lhs) {
			uint32_t key2i_frag;

			/* save 22 most significant bits [31..10] */
			key2i_frag = key2i_bits31_8 & 0xfffffc00;

			/* save bits [15..2] with common 6 bits */
			key2i_frag |= key2i_bits_15_2[i];

			/* save bits [1..0] */
			total += generate_all_key2i_with_bits_1_0(&key2i[total],
								  key2i_frag,
								  key2im1_bits_15_2);
		}
	}

	return total;
}

struct reduc_work_unit {
	const uint16_t *key2i_bits_15_2;
	const uint16_t *key2im1_bits_15_2;
	uint32_t common_bits_mask;
	const uint32_t *key2ip1;	/* keys to process */
	size_t key2ip1_size;		/* number of keys to process */
	struct list_head list;
};

struct reduc_data {
	uint32_t *tmp;	              /* temporary key2 buffer */
	struct reduc_input_param *in; /* data shared between threads */
};

struct reduc_input_param {
	uint32_t *key2i;
	size_t key2i_size;
	pthread_mutex_t mutex;
};

static int key2r_compute_next_array(struct threadpool *pool,
				    const uint32_t *key2ip1,
				    size_t key2ip1_size,
				    const uint16_t *key2i_bits_15_2,
				    const uint16_t *key2im1_bits_15_2,
				    uint32_t common_bits_mask)
{
	struct reduc_work_unit *u;
	size_t nbthreads = threadpool_get_nbthreads(pool);
	size_t nbunits = key2ip1_size < nbthreads ? key2ip1_size : nbthreads;
	size_t nbkeys_per_thread = key2ip1_size / nbunits;
	size_t rem = key2ip1_size % nbunits;

	u = calloc(nbunits, sizeof(struct reduc_work_unit));
	if (!u) {
		perror("calloc() failed");
		return -1;
	}

	/* set constants */
	for (size_t i = 0; i < nbunits; ++i) {
		u[i].key2i_bits_15_2 = key2i_bits_15_2;
		u[i].key2im1_bits_15_2 = key2im1_bits_15_2;
		u[i].common_bits_mask = common_bits_mask;
	}

	if (!rem) {
		for (size_t i = 0; i < nbunits; ++i) {
			u[i].key2ip1 = &key2ip1[i * nbkeys_per_thread];
			u[i].key2ip1_size = nbkeys_per_thread;
		}
	} else {
		/* evenly distribute keys to work units */
		size_t total = 0;
		for (size_t i = 0; i < nbunits; ++i) {
			u[i].key2ip1 = &key2ip1[total];
			u[i].key2ip1_size = nbkeys_per_thread;
			total += nbkeys_per_thread;
			if (rem) {
				u[i].key2ip1_size++;
				total++; rem--;
			}
		}
	}

	/* submit work */
	for (size_t i = 0; i < nbunits; ++i)
		threadpool_submit_work(pool, &u[i].list);

	threadpool_wait_idle(pool);

	free(u);

	return 0;
}

static int alloc_reduc(void *in, void **data)
{
	struct reduc_data *d;
	struct reduc_input_param *p = (struct reduc_input_param *)in;

	d = calloc(1, sizeof(struct reduc_data));
	if (!d) {
		perror("calloc() failed");
		return -1;
	}

	d->tmp = calloc(KEY2_ARRAY_LEN, sizeof(uint32_t));
	if (!d->tmp) {
		perror("calloc() failed");
		free(d);
		return -1;
	}

	/* worker's input parameters */
	d->in = p;

	*data = d;

	return 0;
}

static void dealloc_reduc(void *data)
{
	struct reduc_data *d = (struct reduc_data *)data;
	free(d->tmp);
	free(d);
}

static int do_work_reduc(void *data, struct list_head *list)
{
	struct reduc_data *d = (struct reduc_data *)data;
	struct reduc_work_unit *unit = list_entry(list, struct reduc_work_unit, list);
	size_t total = 0;

	for (size_t i = 0; i < unit->key2ip1_size; ++i)
		total += key2r_compute_single(unit->key2ip1[i],
					      &d->tmp[total],
					      unit->key2i_bits_15_2,
					      unit->key2im1_bits_15_2,
					      unit->common_bits_mask);

	/* copy back results to final shared buffer */
	pthread_mutex_lock(&d->in->mutex);
	size_t current = d->in->key2i_size;
	d->in->key2i_size += total;
	pthread_mutex_unlock(&d->in->mutex);

	memcpy(&d->in->key2i[current], d->tmp, total * sizeof(uint32_t));

	return TPEMORE;
}

#define SWAP(x, y) do { typeof(x) SWAP = x; x = y; y = SWAP; } while (0)

ZC_EXPORT int zc_crk_ptext_key2_reduction(struct zc_crk_ptext *ptext)
{
	uint32_t *key2ip1;
	uint8_t key3i, key3im1;
	size_t key2ip1_size;
	struct reduc_input_param reduc_input;
	struct threadpool_ops ops;
	int err = -1;

	/* first gen key2 (key2ip1) */
	key3i = generate_key3(ptext, ptext->text_size - 1);
	key2ip1 = calloc(KEY2_ARRAY_LEN, sizeof(uint32_t));
	if (!key2ip1)
		return -1;

	generate_all_key2_bits_31_2(key2ip1, get_bits_15_2(ptext->bits_15_2, key3i));
	key2ip1_size = KEY2_ARRAY_LEN;

	/* first destination buffer is key2i */
	reduc_input.key2i = calloc(KEY2_ARRAY_LEN, sizeof(uint32_t));
	if (!reduc_input.key2i)
		goto err1;
	reduc_input.key2i_size = 0;
	pthread_mutex_init(&reduc_input.mutex, NULL);

	ops.in = &reduc_input;
	ops.alloc_worker = alloc_reduc;
	ops.dealloc_worker = dealloc_reduc;
	ops.do_work = do_work_reduc;

	err = threadpool_start(ptext->pool, &ops, threads_to_create(ptext->force_threads));
	if (err)
		goto err2;

	size_t start_index = ptext->text_size - 2;
	for (size_t i = start_index; i >= 12; --i) {
		key3i = generate_key3(ptext, i);
		key3im1 = generate_key3(ptext, i - 1);
		key2r_compute_next_array(ptext->pool,
					 key2ip1,
					 key2ip1_size,
					 get_bits_15_2(ptext->bits_15_2, key3i),
					 get_bits_15_2(ptext->bits_15_2, key3im1),
					 i == start_index ? KEY2_MASK_6BITS : KEY2_MASK_8BITS);
		uniq(reduc_input.key2i, &reduc_input.key2i_size);
		SWAP(reduc_input.key2i, key2ip1);
		key2ip1_size = reduc_input.key2i_size;
		reduc_input.key2i_size = 0;
	}

	ptext->key2 = realloc(key2ip1, key2ip1_size * sizeof(uint32_t));
	ptext->key2_size = key2ip1_size;
	free(reduc_input.key2i);

	threadpool_cancel(ptext->pool);

	pthread_mutex_destroy(&reduc_input.mutex);

	return 0;

err2:
	free(reduc_input.key2i);
err1:
	free(key2ip1);
	return err;
}
