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

#include "ptext_private.h"

struct key2r {
	uint16_t *bits_15_2_cache;
};

static void generate_key2_bits_15_2(uint16_t *value, uint8_t key3)
{
	uint32_t valuei = 0;
	for (uint32_t i = 0; i < pow2(16); i += 4) {
		uint8_t key3tmp = ((i | 2) * (i | 3)) >> 8;
		if (key3 == key3tmp) {
			value[valuei] = i;
			++valuei;
		}
	}
}

static uint16_t *generate_bits_15_2(void)
{
	uint16_t *tmp;

	tmp = malloc(256 * 64 * sizeof(uint16_t));
	if (!tmp)
		return NULL;

	for (uint32_t key3 = 0; key3 < 256; ++key3)
		generate_key2_bits_15_2(&tmp[key3 * 64], key3);

	return tmp;
}

static void generate_all_key2_bits_31_2(uint32_t *key2,
					const uint16_t *key2_bits_15_2)
{
	uint32_t i, j;
	for (i = 0; i < pow2(16); ++i)
		for (j = 0; j < 64; ++j)
			key2[i * 64 + j] = (i << 16) | key2_bits_15_2[j];
}

int key2r_new(struct key2r **k2r)
{
	struct key2r *tmp;
	uint16_t *bits_15_2_tmp;

	tmp = calloc(1, sizeof(struct key2r));
	if (!tmp)
		return -1;

	bits_15_2_tmp = generate_bits_15_2();
	if (!bits_15_2_tmp) {
		free(tmp);
		return -1;
	}

	tmp->bits_15_2_cache = bits_15_2_tmp;
	*k2r = tmp;

	return 0;
}

void key2r_free(struct key2r *k2r)
{
	free(k2r->bits_15_2_cache);
	free(k2r);
}

uint16_t *key2r_get_bits_15_2(const struct key2r *k2r, uint8_t key3)
{
	return &k2r->bits_15_2_cache[key3 * 64];
}

struct kvector *key2r_compute_first_gen(const uint16_t *key2_bits_15_2)
{
	struct kvector *v;

	if (kalloc(&v, pow2(22)))
		return NULL;

	generate_all_key2_bits_31_2(v->buf, key2_bits_15_2);
	return v;
}

static uint32_t bits_1_0_key2i(uint32_t key2im1, uint32_t key2i)
{
	uint32_t tmp = key2im1 ^ crc_32_invtab[msb(key2i)];
	tmp = (tmp >> 8) & 0x3;      /* keep only bit 9 and 8 */
	return tmp;
}

static int generate_all_key2i_with_bits_1_0(struct kvector *key2i_array,
					    uint32_t key2i,
					    const uint16_t *key2im1_bits_15_2)

{
	const uint32_t key2im1_bits_31_10 = (key2i << 8) ^ crc_32_invtab[key2i >> 24];
	const uint32_t key2im1_bits_15_10_rhs = key2im1_bits_31_10 & 0xfc00;

	for (int j = 0; j < 64; ++j) {
		const uint32_t key2im1_bits_15_10_lhs = key2im1_bits_15_2[j] & 0xfc00;

		/* the left and right hand side share 6 bits in position
		   [15..10]. See biham & kocher 3.1. */
		if (key2im1_bits_15_10_rhs == key2im1_bits_15_10_lhs) {
			uint32_t key2im1;
			key2im1 = key2im1_bits_31_10 & 0xfffffc00;
			key2im1 |= key2im1_bits_15_2[j];
			if (kappend(key2i_array, key2i | bits_1_0_key2i(key2im1, key2i)))
				return -1;
		}
	}

	return 0;
}

int key2r_compute_single(uint32_t key2i_plus_1,
			 struct kvector *key2i,
			 const uint16_t *key2i_bits_15_2,
			 const uint16_t *key2im1_bits_15_2,
			 uint32_t common_bits_mask)
{
	const uint32_t key2i_bits31_8 = (key2i_plus_1 << 8) ^ crc_32_invtab[key2i_plus_1 >> 24];
	const uint32_t key2i_bits15_10_rhs = key2i_bits31_8 & common_bits_mask;

	for (uint32_t i = 0; i < 64; ++i) {
		const uint32_t key2i_bits15_10_lhs = key2i_bits_15_2[i] & common_bits_mask;

		/* the left and right hand side share the same 6 bits in
		   position [15..10]. See biham & kocher 3.1. */
		if (key2i_bits15_10_rhs == key2i_bits15_10_lhs) {
			uint32_t key2i_tmp;

			/* save 22 most significant bits [31..10] */
			key2i_tmp = key2i_bits31_8 & 0xfffffc00;

			/* save bits [15..2] with common 6 bits */
			key2i_tmp |= key2i_bits_15_2[i];

			/* save bits [1..0] */
			if (generate_all_key2i_with_bits_1_0(key2i, key2i_tmp, key2im1_bits_15_2))
				return -1;
		}
	}

	return 0;
}

static int key2r_compute_next_array(struct kvector *key2i_plus_1,
				    struct kvector *key2i,
				    const uint16_t *key2i_bits_15_2,
				    const uint16_t *key2im1_bits_15_2,
				    uint32_t common_bits_mask)
{
	kempty(key2i);

	for (uint32_t i = 0; i < key2i_plus_1->size; ++i) {
		if (key2r_compute_single(kat(key2i_plus_1, i),
					 key2i,
					 key2i_bits_15_2,
					 key2im1_bits_15_2,
					 common_bits_mask))
			return -1;
	}

	return 0;
}

#define SWAP(x, y) do { typeof(x) SWAP = x; x = y; y = SWAP; } while (0)

ZC_EXPORT int zc_crk_ptext_key2_reduction(struct zc_crk_ptext *ptext)
{
	struct kvector *key2i_plus_1;
	struct kvector *key2i;
	uint8_t key3i;
	uint8_t key3im1;

	/* first gen key2 */
	key3i = generate_key3(ptext, ptext->size - 1);
	key2i_plus_1 = key2r_compute_first_gen(key2r_get_bits_15_2(ptext->k2r, key3i));
	if (!key2i_plus_1)
		return -1;

	/* allocate space for second array */
	if (kalloc(&key2i, pow2(22))) {
		kfree(key2i_plus_1);
		return -1;
	}

	/* perform reduction */
	const uint32_t start_index = ptext->size - 2;
	for (uint32_t i = start_index; i >= 12; --i) {
		key3i = generate_key3(ptext, i);
		key3im1 = generate_key3(ptext, i - 1);
		if (key2r_compute_next_array(key2i_plus_1,
					     key2i,
					     key2r_get_bits_15_2(ptext->k2r, key3i),
					     key2r_get_bits_15_2(ptext->k2r, key3im1),
					     i == start_index ? KEY2_MASK_6BITS : KEY2_MASK_8BITS))
			goto err;

		kuniq(key2i);
		SWAP(key2i, key2i_plus_1);
	}

	ksqueeze(key2i_plus_1); /* note: we swapped key2i and key2i+1 */

	ptext->key2 = key2i_plus_1;  /* here, key2i_plus_1, is the array at
                                 * index 13 (n=14) this leaves 13
                                 * bytes for the actual attack */
	kfree(key2i);
	return 0;

err:
	kfree(key2i);
	kfree(key2i_plus_1);
	return -1;
}
