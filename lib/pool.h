/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2019 Marc Ferland
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

#ifndef _POOL_H_
#define _POOL_H_

#include <stdbool.h>
#include "list.h"

struct threadpool;

enum {
	TPEMORE = 0,
	TPEEXIT,
	TPECANCELSIBLINGS,
	TPECOUNT,
};

struct threadpool_ops {
	/*
	 * Allocate resources for a single worker thread.
	 */
	int (*alloc_worker)(void **data);

	/*
	 * Deallocate resources for a single worker thread.
	 */
	void (*dealloc_worker)(void *data);

	/*
	 * Function called to do the actual work. Returning a non-zero
	 * value from do_work, will make the worker thread exit.
	 */
	int (*do_work)(void *data, struct list_head *list);
};

int threadpool_new(size_t nbthreads, struct threadpool **p);

size_t threadpool_get_nbthreads(const struct threadpool *p);

void threadpool_destroy(struct threadpool *p);

int threadpool_start(struct threadpool *p, struct threadpool_ops *ops);

void threadpool_cancel(struct threadpool *p);

void threadpool_wait(struct threadpool *p);

void threadpool_wait_idle(struct threadpool *p);

int threadpool_submit_work(struct threadpool *p, struct list_head *list);

#endif	/* _POOL_H_ */
