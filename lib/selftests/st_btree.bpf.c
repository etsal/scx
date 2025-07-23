#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/btree.h>

#include "selftest.h"

u64 keys[] = { 51, 43,  37, 3, 301,  46, 383, 990, 776, 729, 871, 96, 189, 213, 
	376, 167, 131, 939, 626, 119, 374, 700, 772, 154, 883, 620, 641, 5, 
	428, 516, 105, 622, 988, 811, 931, 973, 246, 690, 934, 744, 210, 311, 
	32, 255, 960, 830, 523, 429, 541, 738, 705, 774, 715, 446, 98, 578, 
	777, 191, 279, 91, 767 };

__weak int scx_selftest_btree_find_nonexistent(btree_t __arg_arena *btree)
{
	u64 key = 0xdeadbeef;
	u64 value = 0;
	int ret;

	if (!btree)
		return 1;

	/* Should return -EINVAL */
	ret = bt_find(btree, key, &value);
	if (!ret)
		return 2;

	return 0;
}

__weak int scx_selftest_btree_insert_existing(btree_t __arg_arena *btree)
{
	u64 key = 525252;
	u64 value = 24;
	int ret;

	if (!btree)
		return 1;

	/* Should return -EINVAL. */
	ret = bt_insert(btree, key, value, false);
	if (ret)
		return 2;

	/* Should return -EALREADY. */
	ret = bt_insert(btree, key, value, false);
	if (ret != -EALREADY) {
		return 3;
	}

	return 0;
}

__weak int scx_selftest_btree_update_existing(btree_t __arg_arena *btree)
{
	u64 key = 33333;
	u64 value;
	int ret;

	if (!btree)
		return 1;

	/* Should return -EINVAL. */
	value = 52;
	ret = bt_insert(btree, key, value, true);
	if (ret)
		return 2;

	ret = bt_find(btree, key, &value);
	if (ret)
		return 3;

	if (value != 52)
		return 4;

	value = 65;

	/* Should succeed. */
	ret = bt_insert(btree, key, value, true);
	if (ret)
		return 5;

	/* Should be updated. */
	ret = bt_find(btree, key, &value);
	if (ret)
		return 6;

	if (value != 65)
		return 7;

	return 0;
}


__weak int scx_selftest_btree_insert_one(btree_t __arg_arena *btree)
{
	u64 key = 202020;
	u64 value = 0xbadcafe;
	int ret;

	ret = bt_insert(btree, key, value, true);
	if (ret)
		return 1;

	ret = bt_find(btree, key, &value);
	if (ret)
		return 2;

	if (value != 0xbadcafe)
		return 3;

	return 0;
}

__weak int scx_selftest_btree_insert_ten(btree_t __arg_arena *btree)
{
	u64 key, value;
	int ret, i;

	if (!btree)
		return 1;

	for (i = 0; i < 10 && can_loop; i++) {
		key = keys[i];
		ret = bt_insert(btree, key, 2 * key, true);
		if (ret)
			return 2 + 3 * i;

		/* Read it back. */
		ret = bt_find(btree, key, &value);
		if (ret)
			return 2 + 3 * i + 1;

		if (value != 2 * key)
			return 2 + 3 * i + 2;
	}

	/* Go find all inserted pairs. */
	for (i = 0; i < 10 && can_loop; i++) {
		key = keys[i];

		ret = bt_find(btree, key, &value);
		if (ret)
			return 35 + 2 * i;

		if (value != 2 * key)
			return 35 + 2 * i + 1;
	}

	return -EOPNOTSUPP;
}

__weak int scx_selftest_btree_insert_many(btree_t __arg_arena *btree)
{
	if (!btree)
		return 1;

	return -EOPNOTSUPP;
}

#define SCX_BTREE_SELFTEST(suffix) SCX_SELFTEST(scx_selftest_btree_ ## suffix, btree)

__weak
int scx_selftest_btree(void)
{
	btree_t __arg_arena *btree;

	btree = bt_create();
	if (!btree)
		return -ENOMEM;

	SCX_BTREE_SELFTEST(find_nonexistent);

	bt_print(btree);

	SCX_BTREE_SELFTEST(insert_one);

	bt_print(btree);

	SCX_BTREE_SELFTEST(insert_existing);

	bt_print(btree);

	SCX_BTREE_SELFTEST(update_existing);

	bt_print(btree);

	SCX_BTREE_SELFTEST(insert_ten);

	bt_print(btree);

	return 0;
}
