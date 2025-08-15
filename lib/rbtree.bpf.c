/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include <lib/sdt_task.h>
#include <lib/rbtree.h>

int rbnode_rotate(rbtree_t *rbtree, rbnode_t *node, bool with_left)
{
	rbnode_t *tmp;
	bool is_root;
	int dir;

	is_root = !node->parent;

	/* If we're doing a root change, are we the root? */
	if (unlikely(is_root && rbtree->root != node))
		return -EINVAL;

	dir = with_left ? 0 : 1;

	/* Does the node we're rotating into exist? */
	if (unlikely(with_left ? !node->left : !node->right))
		return -EINVAL;

	/* 0 is for the left child, 1 for the right. */
	tmp = node->child[dir];
	node->child[dir] = node->child[dir]->child[1 - dir];
	node->parent = tmp;
	node->child[dir]->child[1 - dir] = node;

	if (is_root)
		rbtree->root = tmp;

	return 0;
}

__weak
int rbtree_insert(rbtree_t *rbtree, uint64_t key, uint64_t value, bool update)
{
	rbnode_t *grandparent, *parent = rbtree->root;
	rbnode_t *node, *uncle, *child;
	int dir;

	node = (rbnode_t *)scx_static_alloc(sizeof(*node), 1);
	if (!node)
		return -ENOMEM;

	node->key = key;
	node->value = value;
	node->is_red = true;

	if (!parent) {
		rbtree->root = node;
		return 0;
	}

	while (can_loop) {
		if (key == parent->key) {
			if (!update)
				return -EALREADY;
			parent->value = value;
			return 0;
		}

		dir = (key < parent->key) ? 0 : 1;

		child = parent->child[dir];
		if (!child) {
			parent->child[dir] = node;
			break;
		}

		parent = child;
	}

	while (node != rbtree->root && can_loop) {
		parent = node->parent;
		if (!parent->is_red)
			return 0;

		grandparent = parent->parent;
		if (!grandparent) {
			parent->is_red = false;
			return 0;
		}

		dir = grandparent->left == parent ? 0 : 1;
		uncle = grandparent->child[1 - dir];

		if (!uncle || !uncle->is_red) {
			if (node == parent->child[1 - dir]) {
				rbnode_rotate(rbtree, parent, dir);
				node = parent;
				parent = grandparent->child[dir];
			}

			rbnode_rotate(rbtree, grandparent, 1 - dir);
			parent->is_red = false;
			grandparent->is_red = true;
			return 0;
		}

		parent->is_red = false;
		uncle->is_red = false;
		grandparent->is_red = true;

		node = grandparent;
	}

	return 0;
}

__weak
int rbtree_find(rbtree_t *rbtree, uint64_t key, uint64_t *value)
{
	rbnode_t *node = rbtree->root;

	while (node && can_loop) {
		if (node->key == key) {
			*value = node->value;
			return 0;
		}

		node = (key < node->key) ? node->left : node->right;
	}

	return -ENOENT;
}

__weak
int rbtree_remove(rbtree_t *rbtree, u64 key)
{
	return -EOPNOTSUPP;
}

__weak
int rbtree_init()
{
	return -EOPNOTSUPP;
}

static inline void rbnode_print(size_t depth, rbnode_t *rbn)
{
	bpf_printk("[DEPTH %d/ %s] %p (%s)", depth, rbn, rbn->is_red ? "red" : "black");
	bpf_printk("\tKV (%ld, %ld) LEFT %p RIGHT]", rbn->key, rbn->value, rbn->left, rbn->right);
}

enum rb_print_state {
	RB_NONE_VISITED,
	RB_LEFT_VISITED,
	RB_RIGHT_VISITED,
};

__weak
int rb_print(rbtree_t __arg_arena *rbtree)
{
	const int RB_PRINT_MAXITER = 100;
	rbnode_t *rbnode = rbtree->root;
	enum rb_print_state stack[RB_MAXLVL_PRINT];
	enum rb_print_state state;
	rbnode_t *next;
	u8 depth;
	int i, j;

	depth = 0;
	state = RB_NONE_VISITED;

	bpf_printk("=== BPF PRINTK START ===");

	/* Even with can_loop, the verifier doesn't like infinite loops. */
	bpf_for(i, 0, RB_PRINT_MAXITER) {
		rbnode_print(depth, rbnode);

		next = NULL;

		/* Find which child to traverse next. */

		switch (state) {
		case RB_NONE_VISITED:
			if (rbnode->left) {
				next = rbnode->left;
				state = RB_LEFT_VISITED;
				break;
			}

			/* FALLTHROUGH */

		case RB_LEFT_VISITED:
			if (rbnode->right) {
				next = rbnode->right;
				state = RB_RIGHT_VISITED;
				break;
			}

			/* FALLTHROUGH */

		default:
			next = NULL;
			state = RB_RIGHT_VISITED;
		}

		/* Child found. Store the node state and go on. */
		if (next) {
			if (depth < 0 || depth >= RB_MAXLVL_PRINT)
				return 0;

			stack[depth++] = state;

			rbnode = next;
			state = RB_NONE_VISITED;

			continue;
		}

		if (depth >= RB_MAXLVL_PRINT) {
			bpf_printk("Max level reached, aborting btree print.");
			return 0;
		}

		/* Otherwise, go as far up as possible. */

		bpf_for (j, 0, RB_MAXLVL_PRINT) {
			if (state != RB_RIGHT_VISITED)
				break;

			depth -= 1;
			if (depth < 0 || depth >= RB_MAXLVL_PRINT)
				return 0;

			state = stack[depth];
			rbnode = rbnode->parent;
		}
	}

	bpf_printk("=== BPF PRINTK END ===");

	return 0;
}
