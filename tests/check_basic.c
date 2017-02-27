/*
 *  zc - zip crack library
 *  Copyright (C) 2017  Marc Ferland
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

#include <check.h>
#include <stdlib.h>

/* libzc */
#include <libzc.h>

struct zc_ctx *ctx;

void setup(void)
{
    zc_new(&ctx);
}

void teardown(void)
{
    zc_unref(ctx);
}

START_TEST(test_zc_log_priority)
{
    zc_set_log_priority(ctx, 2);
    ck_assert_int_eq(zc_get_log_priority(ctx), 2);
}
END_TEST

START_TEST(test_zc_refcount)
{
    ck_assert_ptr_eq(zc_ref(ctx), ctx);    /* inc */
    ck_assert_ptr_eq(zc_unref(ctx), ctx);  /* dec */
    ck_assert_ptr_eq(zc_unref(ctx), NULL); /* dec */
    ck_assert_ptr_eq(zc_unref(NULL), NULL);
}
END_TEST

START_TEST(test_zc_file_refcount)
{
    struct zc_file *file;
    int ret;

    ret = zc_file_new_from_filename(ctx, "dummy", &file);
    ck_assert_int_eq(ret, 0);
    ck_assert_ptr_eq(zc_file_ref(file), file);   /* inc */
    ck_assert_ptr_eq(zc_file_unref(file), file); /* dec */
    ck_assert_ptr_eq(zc_file_unref(file), NULL); /* dec */
    ck_assert_ptr_eq(zc_file_unref(NULL), NULL); /* dec */
}
END_TEST

START_TEST(test_zc_crk_dict_refcount)
{
    struct zc_crk_dict *p;
    int ret;

    ret = zc_crk_dict_new(ctx, &p);
    ck_assert_int_eq(ret, 0);
    ck_assert_ptr_eq(zc_crk_dict_ref(p), p);         /* inc */
    ck_assert_ptr_eq(zc_crk_dict_unref(p), p);       /* dec */
    ck_assert_ptr_eq(zc_crk_dict_unref(p), NULL);    /* dec */
    ck_assert_ptr_eq(zc_crk_dict_unref(NULL), NULL); /* dec */
}
END_TEST

START_TEST(test_zc_crk_bforce_refcount)
{
    struct zc_crk_bforce *p;
    int ret;

    ret = zc_crk_bforce_new(ctx, &p);
    ck_assert_int_eq(ret, 0);
    ck_assert_ptr_eq(zc_crk_bforce_ref(p), p);         /* inc */
    ck_assert_ptr_eq(zc_crk_bforce_unref(p), p);       /* dec */
    ck_assert_ptr_eq(zc_crk_bforce_unref(p), NULL);    /* dec */
    ck_assert_ptr_eq(zc_crk_bforce_unref(NULL), NULL); /* dec */
}
END_TEST

START_TEST(test_zc_crk_ptext_refcount)
{
    struct zc_crk_ptext *p;
    int ret;

    ret = zc_crk_ptext_new(ctx, &p);
    ck_assert_int_eq(ret, 0);
    ck_assert_ptr_eq(zc_crk_ptext_ref(p), p);         /* inc */
    ck_assert_ptr_eq(zc_crk_ptext_unref(p), p);       /* dec */
    ck_assert_ptr_eq(zc_crk_ptext_unref(p), NULL);    /* dec */
    ck_assert_ptr_eq(zc_crk_ptext_unref(NULL), NULL); /* dec */
}
END_TEST

Suite * basic_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Basic");

    tc_core = tcase_create("Core");

    tcase_add_checked_fixture(tc_core, setup, teardown);
    tcase_add_test(tc_core, test_zc_log_priority);
    tcase_add_test(tc_core, test_zc_refcount);
    tcase_add_test(tc_core, test_zc_file_refcount);
    tcase_add_test(tc_core, test_zc_crk_dict_refcount);
    tcase_add_test(tc_core, test_zc_crk_bforce_refcount);
    tcase_add_test(tc_core, test_zc_crk_ptext_refcount);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(int argc, char *argv[])
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = basic_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}