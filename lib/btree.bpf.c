/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include <lib/sdt_task.h>
#include <lib/btree.h>

/*
 * Temporary replacements for memcpy/arrzero, which the BPF
 * LLVM backend does not support.
 */

__weak int arrzero(u64 __arg_arena __arena *arr, size_t nelems)
{
	int i;

	for (i = 0; i < nelems && can_loop; i++)
		arr[i] = 0ULL;

	return 0;
}

__weak int arrcpy(u64 __arg_arena __arena *dst, u64 __arg_arena __arena *src, size_t nelems)
{
	int i;

	for (i = 0; i < nelems && can_loop; i++) {
		if (src < dst)
			dst[nelems - 1 - i] = src[nelems - 1 - i];
		else
			dst[i] = src[i];
	}

	return 0;
}

static bt_node *btnode_alloc(btree_t *btree, bt_node __arg_arena *parent, u64 flags)
{
	bt_node *btn;
	bt_node *freelist;

	do  {
		freelist = btree->freelist;
		if (!freelist)
			break;

	} while (cmpxchg(&btree->freelist, freelist, freelist->parent) && can_loop);

	btn = scx_static_alloc(sizeof(*btn), 1);
	if (!btn)
		return NULL;

	arrzero(&btn->keys[0], BT_LEAFSZ);

	btn->flags = flags;
	btn->parent = parent;

	return btn;
}

static inline void btnode_free(btree_t *btree, bt_node *btn)
{
	bt_node *old;

	do {
		old = btree->freelist;
		btn->parent = old;
	} while (cmpxchg(&btree->freelist, old, btn) && can_loop);
}

static inline bool btnode_isroot(bt_node *btn)
{
	return btn->flags & BT_F_ROOT;
}

static inline bool btnode_isleaf(bt_node *btn)
{
	return btn->flags & BT_F_LEAF;
}

__weak
u64 bt_create_internal(void)
{
	btree_t __arg_arena *btree;

	btree = scx_static_alloc(sizeof(*btree), 1);
	if (!btree)
		return (u64)NULL;

	btree->root = btnode_alloc(btree, NULL, BT_F_ROOT | BT_F_LEAF);
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

	for (i = 0; i < btn->numkeys && can_loop; i++) {
		/*
		 * It's strict inequality because we
		 * want nodes equal to the key to be to
		 * the _right_ of the key.
		 */
		if (key < btn->keys[i])
			return i;
	}

	return btn->numkeys;
}


__weak u64 btn_leaf_index(bt_node __arg_arena *btn, u64 key)
{
	int i;

	for (i = 0; i < btn->numkeys && can_loop; i++) {
		if (key <= btn->keys[i])
			break;
	}

	return i;
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

__weak
int btnode_remove_internal(bt_node __arg_arena *btn, u64 ind)
{
	volatile u64 __arena *val;
	u64 nelems;

	/* We can have to btn->numkeys - 1 keys and btn->numkeys values.*/
	if (unlikely(ind > btn->numkeys - 1)) {
		bpf_printk("internal removal overflow (%ld, %ld)", ind, btn->numkeys - 1);
		return -EINVAL;
	}

	nelems = btn->numkeys - ind;

	if (nelems)
		arrcpy(&btn->keys[ind], &btn->keys[ind + 1], nelems);
	btn->keys[btn->numkeys] = 0;

	/* The next value will be to the right of the new key. */
	ind += 1;
	if (nelems)
		arrcpy(&btn->values[ind], &btn->values[ind + 1], nelems);

	/*
	 * XXXETSAL The verifier currently complains when doing complex pointer
	 * arithmetic. Break the computation down to help it along.
	 */
	val = (u64 __arena *)&btn->values;
	val[btn->numkeys + 1] = 0;

	btn->numkeys -= 1;

	return 0;
}

__weak
int btnode_add_internal(bt_node __arg_arena *btn, u64 ind, u64 key, bt_node __arg_arena *value)
{
	u64 nelems;

	/* We can have up to BT_LEAFSZ - 1 keys and BT_LEAFSZ values.*/
	if (unlikely(ind >= BT_LEAFSZ - 1)) {
		bpf_printk("internal add overflow (%ld, %ld)", ind, BT_LEAFSZ - 1);
		return -EINVAL;
	}

	nelems = btn->numkeys - ind;

	if (nelems)
		arrcpy(&btn->keys[ind + 1], &btn->keys[ind], nelems);
	btn->keys[ind] = key;

	/* The next value will be to the right of the new key. */
	ind += 1;
	if (nelems)
		arrcpy(&btn->values[ind + 1], &btn->values[ind], nelems);

	btn->values[ind] = (u64)value;

	btn->numkeys += 1;

	return 0;
}

static int btnode_remove_leaf(bt_node *btn, u64 ind)
{
	u64 nelems;

	if (unlikely(ind >= btn->numkeys)) {
		bpf_printk("leaf remove overflow (%ld,  %ld)", ind, btn->numkeys);
		return -EINVAL;
	}

	nelems = btn->numkeys - ind;

	/* Overwite the key with the rest of the array. */
	arrcpy(&btn->keys[ind], &btn->keys[ind + 1], nelems);
	arrcpy(&btn->values[ind], &btn->values[ind + 1], nelems);

	btn->keys[btn->numkeys] = 0;
	btn->values[btn->numkeys] = 0;
	btn->numkeys -= 1;

	return 0;
}


static int btnode_add_leaf(bt_node *btn, u64 ind, u64 key, u64 value)
{
	u64 nelems;

	if (unlikely(ind > btn->numkeys)) {
		bpf_printk("leaf add overflow (%ld,  %ld)", ind, btn->numkeys);
		return -EINVAL;
	}

	nelems = btn->numkeys - ind;

	/* Scooch the keys over and add the new one. */
	arrcpy(&btn->keys[ind + 1], &btn->keys[ind], nelems);
	arrcpy(&btn->values[ind + 1], &btn->values[ind], nelems);

	btn->keys[ind] = key;
	btn->values[ind] = value;
	btn->numkeys += 1;

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
	btn_new->numkeys = nelems;

	arrzero(&btn_old->keys[off], nelems);
	arrzero(&btn_old->values[off], nelems);
	btn_old->numkeys = off;

	return key;
}

__weak
u64 btnode_split_internal(bt_node __arg_arena *btn_new, bt_node __arg_arena *btn_old)
{
	bt_node *btn_child;
	u64 keycopies;
	u64 off;
	u64 key;
	int i;

	off = (BT_LEAFSZ / 2);
	key = btn_old->keys[off];
	keycopies = BT_LEAFSZ - off - 1;

	/* We have numkeys + 1 values. */
	arrcpy(&btn_new->keys[0], &btn_old->keys[off + 1], keycopies);
	arrcpy(&btn_new->values[0], &btn_old->values[off + 1], keycopies + 1);
	btn_new->numkeys = keycopies - 1;

	/* Update the parent pointer for the children of the new node. */
	for (i = 0; i <= keycopies && can_loop; i++) {
		btn_child = (bt_node *)btn_new->values[i];
		btn_child->parent = btn_new;
	}

	/* Wipe away the removed and copied keys. */
	arrzero(&btn_old->keys[off], keycopies + 1);
	arrzero(&btn_old->values[off + 1], keycopies);
	btn_old->numkeys = off;

	return key;
}

int btnode_print(u64 depth, u64 ind, bt_node __arg_arena *btn);

static
int bt_split(btree_t __arg_arena *btree, bt_node *btn_old)
{
	bt_node *btn_new, *btn_root, *btn_parent;
	u64 key, ind;
	int ret;

	do {

		btn_parent = btn_old->parent;
		btn_new = btnode_alloc(btree, btn_parent, btn_old->flags);
		if (!btn_new)
			return -ENOMEM;

		if (btn_old->flags & BT_F_LEAF)
			key = btnode_split_leaf(btn_new, btn_old);
		else
			key = btnode_split_internal(btn_new, btn_old);

		if (btnode_isroot(btn_old)) {
			btn_old->flags &= ~BT_F_ROOT;
			btn_new->flags &= ~BT_F_ROOT;

			btn_root = btnode_alloc(btree, NULL, BT_F_ROOT);
			if (!btn_root) {
				btnode_free(btree, btn_new);
				return -ENOMEM;
			}

			btn_root->keys[0] = key;
			btn_root->values[0] = (u64)btn_old;
			btn_root->values[1] = (u64)btn_new;
			btn_root->numkeys = 1;

			btn_old->parent = btn_root;
			btn_new->parent = btn_root;

			btree->root = btn_root;

			return 0;
		}

		ind = btn_node_index(btn_parent, key);

		ret = btnode_add_internal(btn_parent, ind, key, btn_new);
		if (ret) {
			btnode_free(btree, btn_new);
			return ret;
		}

		btn_old = btn_old->parent;

	/* Loop around while the node is full. */
	} while (btn_old->numkeys >= BT_LEAFSZ - 1 && can_loop);

	return 0;
}

__weak
int bt_insert(btree_t __arg_arena *btree, u64 key, u64 value, bool update)
{
	bt_node *btn;
	u64 ind;
	int ret;


	btn = bt_find_leaf(btree, key);
	if (!btn)
		return -EINVAL;

	/* Update in place. */
	ind = btn_leaf_index(btn, key);
	if (ind < btn->numkeys && btn->keys[ind] == key) {
		if (!update)
			return -EALREADY;

		btn->keys[ind] = key;
		btn->values[ind] = value;
		return 0;
	}

	/* Integrity check, node splitting should prevent this. */
	if (unlikely(btn->numkeys >= BT_LEAFSZ)) {
		bpf_printk("node overflow");
		return -EINVAL;
	}

	ret = btnode_add_leaf(btn, ind, key, value);
	if (ret)
		return ret;

	if (btn->numkeys < BT_LEAFSZ)
		return 0;

	return bt_split(btree, btn);
}

static inline int bt_balance_left(bt_node *parent, int ind, bt_node *left, bt_node *right)
{
	u64 key = left->keys[left->numkeys - 1];
	bt_node *value = (bt_node *)left->values[left->numkeys];
	int ret;

	ret = btnode_remove_internal(left, left->numkeys);
	if (unlikely(ret))
		return ret;

	ret = btnode_add_internal(right, 0, key, value);
	if (unlikely(ret))
		return ret;

	parent->keys[ind] = key;
	return 0;
}

static inline int bt_balance_right(bt_node *parent, int ind, bt_node *left, bt_node *right)
{
	u64 key = right->keys[0];
	bt_node *value = (bt_node *)left->values[0];
	int ret;

	ret = btnode_remove_internal(right, 0);
	if (unlikely(ret))
		return ret;

	ret = btnode_add_internal(left, left->numkeys, key, value);
	if (unlikely(ret))
		return ret;

	parent->keys[ind] = right->keys[0];
	return 0;
}

__weak
bool bt_balance(bt_node __arg_arena *btn, bt_node __arg_arena *parent, int ind)
{
	volatile bt_node *tmp;
	bt_node *sibling;

	/* Try to steal from the left sibling node to avoid merging. */

	if (ind == 0)
		goto steal_right;

	sibling = (bt_node *)parent->values[ind - 1];
	if (sibling->numkeys - 1 < BT_LEAFSZ / 2)
		goto steal_right;


	if (!bt_balance_left(parent, ind - 1, sibling, btn))
		return true;

steal_right:

	/* Failed to steal from the left node, look for the right node. */
	if (ind >= parent->numkeys)
		return false;

	tmp = (bt_node *)parent->values;
	sibling = (bt_node *)&tmp[ind + 1];
	if (sibling->numkeys - 1 < BT_LEAFSZ / 2) {
		return false;
	}

	return bt_balance_right(parent, ind, btn, sibling);
}

static inline int bt_merge(btree_t *btree, bt_node *btn, bt_node *parent, int ind)
{
	bt_node *left, *right;
	u64 key;

	if (ind == 0) {
		left = btn;
		right = (bt_node *)parent->values[ind + 1];
		key = parent->keys[ind];
	} else {
		left = (bt_node *)parent->values[ind - 1];
		right = btn;
		key = parent->keys[ind - 1];
	}

	if (unlikely(left->numkeys + right->numkeys + 2) > BT_LEAFSZ)
		return -E2BIG;

	left->keys[left->numkeys] = key;
	arrcpy(&left->keys[left->numkeys + 1], right->keys, right->numkeys);
	arrcpy(&left->values[left->numkeys + 1], right->values, right->numkeys + 1);

	left->numkeys = left->numkeys + 1 + right->numkeys;
	btnode_remove_internal(parent, ind + 1);
	btnode_free(btree, right);

	return 0;
}

__weak
int bt_remove(btree_t __arg_arena *btree, u64 key)
{
	bt_node *btn, *parent;
	u64 ind;
	int ret;

	btn = bt_find_leaf(btree, key);
	if (!btn)
		return -EINVAL;

	/* Update in place. */
	ind = btn_leaf_index(btn, key);
	if (ind >= BT_LEAFSZ)
		return -ENOENT;

	btnode_remove_leaf(btn, ind);

	/* Do not load balance leaves. */
	if (btn->numkeys || btnode_isroot(btn))
		return 0;

	parent = btn->parent;
	ind = btn_node_index(parent, btn->keys[0]);

	ret = btnode_remove_internal(parent, ind);
	if (unlikely(ret))
		return ret;

	btnode_free(btree, parent);

	btn = parent;

	while (btn->parent && btn->numkeys < BT_LEAFSZ / 2 && can_loop) {
		parent = btn->parent;
		ind = btn_node_index(parent, btn->keys[0]);

		/* Try to avoid merging. */
		if (bt_balance(btn, parent, ind)) {
			btn = btn->parent;
			continue;
		}

		ret = bt_merge(btree, btn, parent, ind);
		if (ret)
			return ret;

		btn = parent;
	}

	return 0;
}

__weak
int bt_find(btree_t __arg_arena *btree, u64 key, u64 *value)
{
	bt_node *btn = bt_find_leaf(btree, key);
	u64 ind;

	if (unlikely(!value))
		return -EINVAL;

	ind = btn_leaf_index(btn, key);
	if (ind == btn->numkeys || btn->keys[ind] != key)
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
int btnode_print(u64 depth, u64 ind, bt_node __arg_arena *btn)
{
	bool isleaf = btnode_isleaf(btn);

	bpf_printk("==== [%ld/%ld] BTREE %s %p ====", depth, ind,
			isleaf ? "LEAF" : "NODE", btn);

	/* Hardcode it for now make it nicer once we use streams. */
	_Static_assert(BT_LEAFSZ == 5, "Unexpected btree fanout");

	bpf_printk("[KEY] %ld %ld %ld %ld %ld",
			btn->keys[0], btn->keys[1], btn->keys[2],
			btn->keys[3], btn->keys[4]);
	if (isleaf) {
		bpf_printk("[VAL] %ld %ld %ld %ld %ld",
				btn->values[0], btn->values[1], btn->values[2],
				btn->values[3], btn->values[4]);
	} else {
		bpf_printk("[VAL] 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx",
				btn->values[0], btn->values[1], btn->values[2],
				btn->values[3], btn->values[4]);
	}

	bpf_printk("");

	return 0;
}

__weak
int bt_print(btree_t __arg_arena *btree)
{
	const int BT_PRINT_MAXITER = 100;
	bt_node *btn = btree->root;
	u8 stack[BT_MAXLVL_PRINT];
	u8 depth;
	int i, j;
	u8 ind;

	depth = 0;
	ind = 0;

	bpf_printk("=== BPF PRINTK START ===");

	btnode_print(depth, ind, btn);

	/* Even with can_loop, the verifier doesn't like infinite loops. */
	bpf_for(i, 0, BT_PRINT_MAXITER) {
		/* If we can, go to the next unvisited child. */
		if (!btnode_isleaf(btn) && ind <= btn->numkeys) {

			if (btn->numkeys == 0)
				break;

			if (depth < 0 || depth >= BT_MAXLVL_PRINT)
				return 0;

			btn = (bt_node *)btn->values[ind];
			btnode_print(depth, ind, btn);

			stack[depth++] = ind + 1;
			ind = 0;

			if (depth >= BT_MAXLVL_PRINT) {
				bpf_printk("Max level reached, aborting btree print.");
				return 0;
			}

			continue;
		}

		/* Otherwise, go as far up as possible. */
		bpf_for (j, 0, BT_MAXLVL_PRINT) {
			if (!btnode_isleaf(btn) && ind <= btn->numkeys)
				break;

			depth -= 1;
			if (depth < 0 || depth >= BT_MAXLVL_PRINT)
				return 0;

			ind = stack[depth];
			btn = btn->parent;

		}
	}

	bpf_printk("=== BPF PRINTK END ===");

	return 0;
}
