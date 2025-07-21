/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include <lib/sdt_task.h>
#include <lib/btree.h>

/*
 * XXXETSAL TODO:
 *	- Add removes
 *	- Add merges on removes
 *	- More testing
 *	- Iterations
 */

/*
 * Temporary replacements for memcpy/arrzero, which the BPF
 * LLVM backend does not support.
 */

static inline void arrzero(u64 __arg_arena __arena *arr, size_t nelems)
{
	int i;

	for (i = 0; i < nelems && can_loop; i++)
		arr[i] = 0ULL;
}

static inline void arrcpy(u64 __arg_arena __arena *dst, u64 __arg_arena __arena *src, size_t nelems)
{
	int i;

	for (i = 0; i < nelems && can_loop; i++)
		dst[i] = src[i];
}

static bt_node *btnode_alloc(bt_node __arg_arena *parent, bool flags)
{
	bt_node *btn;

	btn = scx_static_alloc(sizeof(*btn), 1);
	if (!btn)
		return NULL;

	arrzero(&btn->keys[0], BT_LEAFSZ);

	btn->flags |= flags;
	btn->parent = parent;

	return btn;
}

static bool btnode_isroot(bt_node *btn)
{
	return btn->flags & BT_F_ROOT;
}

static bool btnode_isleaf(bt_node *btn)
{
	return btn->flags & BT_F_LEAF;
}

static u64 btnode_numkeys(bt_node *btn)
{
	int i;

	/*
	 * Check for size 0 by checking if both
	 * keys are the same (0).
	 */
	if (btn->keys[0] == btn->keys[1])
		return 0;

	for (i = 1; i < BT_LEAFSZ && can_loop; i++) {
		if (btn->keys[i] == 0)
			return i;
	}

	return BT_LEAFSZ;
}

__weak
u64 bt_create_internal(void)
{
	btree_t __arg_arena *btree;

	btree = scx_static_alloc(sizeof(*btree), 1);
	if (!btree)
		return (u64)NULL;

	btree->root = btnode_alloc(NULL, BT_F_ROOT | BT_F_LEAF);
	if (!btree->root) {
		/* XXX Fix once we use the buddy allocator. */
		//scx_buddy_free(buddy, btree);
		return (u64)NULL;
	}

	return (u64)btree;
}

static
u64 btn_node_index(bt_node *btn, u64 key)
{
	int i;

	/*
	 * We use BT_LEAFSZ - 1 keys to hold
	 * BT_LEAFSZ values [0, BT_LEAFSZ - 1].
	 */
	for (i = 0; i < BT_LEAFSZ - 1 && can_loop; i++) {
		/* 
		 * It's strict inequality because we
		 * want nodes equal to the key to be to
		 * the _right_ of the key. 
		 */
		if (key < btn->keys[i])
			return i;
	}

	return BT_LEAFSZ -  1;
}


static
u64 btn_leaf_index(bt_node *btn, u64 key)
{
	int i;

	for (i = 0; i < BT_LEAFSZ && can_loop; i++) {
		if (key == btn->keys[i])
			return i;

		if (key < btn->keys[i])
			break;
	}

	return BT_LEAFSZ;
}

static bt_node *bt_find_leaf(btree_t __arg_arena *btree, u64 key)
{
	bt_node *btn = btree->root;
	u64 ind;

	while (!btnode_isleaf(btn) && can_loop) {
		ind = btn_node_index(btn, key);
		btn = (bt_node *)btn->values[ind];
	}

	return btn;
}

static int btnode_add_internal(bt_node __arg_arena *btn, u64 ind, u64 key, bt_node *value)
{
	u64 nelems;
	u64 size;

	/* We can have up to BT_LEAFSZ - 1 keys and BT_LEAFSZ values.*/
	size = btnode_numkeys(btn); 
	if (unlikely(ind >= BT_LEAFSZ - 1)) {
		bpf_printk("internal node overflow");
		return -EINVAL;
	}

	nelems = size - ind;

	arrcpy(&btn->keys[ind + 1], &btn->keys[ind], nelems);

	u64 __arena *dst = &btn->values[ind + 2];
	u64 __arena *src = &btn->values[ind + 1];

	arrcpy(dst, src, nelems);

	btn->keys[ind] = key;
	btn->values[ind + 1] = (u64)value;

	return 0;
}


static int btnode_add_leaf(bt_node *btn, u64 ind, u64 key, u64 value)
{
	u64 nelems;
	u64 size;

	size = btnode_numkeys(btn); 
	if (unlikely(ind > size)) {
		bpf_printk("leaf node overflow");
		return -EINVAL;
	}

	nelems = size - ind;

	/* Scooch the keys over and add the new one. */
	arrcpy(&btn->keys[ind + 1], &btn->keys[ind], nelems);
	arrcpy(&btn->values[ind + 1], &btn->values[ind], nelems);

	btn->keys[ind] = key;
	btn->values[ind] = value;

	return 0;
}

u64 btnode_split_leaf(bt_node *btn_new, bt_node *btn_old)
{
	u64 off, nelems;
	u64 key;

	off = (BT_LEAFSZ / 2);
	nelems = BT_LEAFSZ - off;

	key = btn_old->keys[off];

	/* Copy the data over and wipe them from the previous node. */
	arrcpy(&btn_new->keys[0], &btn_old->keys[off], nelems);
	arrcpy(&btn_new->values[0], &btn_old->values[off], nelems);

	arrzero(&btn_old->keys[off], nelems);
	arrzero(&btn_old->values[off], nelems);

	return key;
}

u64 btnode_split_internal(bt_node *btn_new, bt_node *btn_old)
{
	u64 keycopies;
	u64 off;
	u64 key;

	off = (BT_LEAFSZ / 2);
	key = btn_old->keys[off];
	keycopies = BT_LEAFSZ - off - 1;

	/* We have numkeys + 1 values. */
	arrcpy(&btn_new->keys[0], &btn_old->keys[off + 1], keycopies);
	arrcpy(&btn_new->values[0], &btn_old->values[off + 1], keycopies + 1);

	/* Wipe away the removed and copied keys. */
	arrzero(&btn_old->keys[off], keycopies + 1);
	arrzero(&btn_old->values[off + 1], keycopies + 1);

	return key;
}

static 
int bt_split(btree_t __arg_arena *btree, bt_node *btn_old)
{
	bt_node *btn_new, *btn_root, *btn_parent;
	u64 key, ind, size;
	int ret;

	do {
		btn_parent = btn_old->parent;
		btn_new = btnode_alloc(btn_parent, btn_old->flags);

		if (btn_old->flags & BT_F_LEAF)
			key = btnode_split_leaf(btn_new, btn_old);
		else
			key = btnode_split_internal(btn_new, btn_old);

		if (btnode_isroot(btn_old)) {
			btn_old->flags &= ~BT_F_ROOT;
			btn_new->flags &= ~BT_F_ROOT;

			btn_root = btnode_alloc(NULL, BT_F_ROOT);
			btn_root->keys[0] = key;
			btn_root->values[0] = (u64)btn_old;
			btn_root->values[1] = (u64)btn_new;

			btree->root = btn_root;

			return 0;
		}
		

		ind = btn_node_index(btn_parent, key);
		
		ret = btnode_add_internal(btn_parent, ind, key, btn_new);
		if (ret)
			return ret;
		
		btn_old = btn_old->parent;
		size = btnode_numkeys(btn_old);

	/* Loop around while the node is full. */
	} while (size >= BT_LEAFSZ - 1);

	return 0;
}

__weak
int bt_insert(btree_t __arg_arena *btree, u64 key, u64 value, bool update)
{
	u64 size, ind;
	bt_node *btn;
	int ret;

	btn = bt_find_leaf(btree, key);
	if (!btn)
		return -EINVAL;

	ind = btn_leaf_index(btn, key);

	/* Update in place. */
	if (ind != BT_LEAFSZ) {
		if (!update)
			return -EALREADY;

		btn->keys[ind] = key;
		btn->values[ind] = value;
		return 0;
	}

	/* Integrity check, node splitting should prevent this. */
	size = btnode_numkeys(btn);
	if (unlikely(size >= BT_LEAFSZ)) {
		bpf_printk("node overflow");
		return -EINVAL;
	}

	ret = btnode_add_leaf(btn, ind, key, value);
	if (ret)
		return ret;

	if (size + 1 <  BT_LEAFSZ)
		return 0;

	return bt_split(btree, btn);
}

__weak
int bt_remove(btree_t __arg_arena *btree, u64 key)
{
	return -EOPNOTSUPP;
}

__weak
int bt_find(btree_t __arg_arena *btree, u64 key, u64 *value)
{
	bt_node *btn = bt_find_leaf(btree, key);
	u64 ind;

	ind = btn_leaf_index(btn, key);
	if (ind == BT_LEAFSZ)
		return -EINVAL;

	if (unlikely(!value))
		return -EINVAL;

	*value = btn->values[ind];

	return 0;
}

__weak
int bt_destroy(btree_t __arg_arena *btree)
{
	return -EOPNOTSUPP;
}

__weak
int bt_print(btree_t __arg_arena *btree)
{
	return -EOPNOTSUPP;
}
