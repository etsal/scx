#pragma once

#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>

#define RB_MAXLVL_PRINT (20)

struct rbnode;

typedef struct rbnode __arena rbnode_t;

struct rbnode {
	rbnode_t *parent;
	union {
		struct {
			rbnode_t *left;
			rbnode_t *right;
		};

		rbnode_t *child[2];
	};
	uint64_t key;
	uint64_t value;
	bool is_red;
};

struct rbtree {
	rbnode_t *root;
};

typedef struct rbtree __arena rbtree_t;

u64 rb_create_internal(void);
#define rb_create() ((rbtree_t *)(rb_create_internal()))

int rb_destroy(rbtree_t *rbtree);
int rb_insert(rbtree_t *rbtree, u64 key, u64 value, bool update);
int rb_remove(rbtree_t *rbtree, u64 key);
int rb_find(rbtree_t *rbtree, u64 key, u64 *value);
int rb_print(rbtree_t *rbtree);
