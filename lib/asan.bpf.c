#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>

#define KASAN_SHADOW_SCALE_SHIFT 8
#define KASAN_GRANULE_MASK ((1ULL << KASAN_SHADOW_SCALE_SHIFT) - 1)
#define KASAN_GRANULE_MASK ((1ULL << KASAN_SHADOW_SCALE_SHIFT) - 1)

#define GRANULE(expr) (((u64)expr) & KASAN_GRANULE_MASK)


/* Last 1/8th of the address space. */
/* XXX THIS IS WRONG, WE SHOULD ALWAY USE DYNAMIC OFFSETS */
#define KASAN_SHADOW_OFFSET (0xe0000000)

/*
 * Implementation based on mm/kasan/generic.c.
 */

/*
 * For now just keep executing.
 */

static bool reported = false;

/*
 * XXX Static key for turning ASAN off.
 */

/*
 * Code mirrors the default ASAN implementation.
 */

/*
 * XXX What's the KASAN_SHADOW_SCALE_SHIFT? We should do 8 for now.
 */
/*
 * XXX What's the KASAN_SHADOW_SCALE_OFFSET? It must be variable because
 * the arena must be variable.
 */

#define ARENA_LIMIT (1ULL << 32)

/* Defined as char * to get 1-byte granularity for pointer arithmetic. */
typedef const char __arena * arenaptr;
typedef s8 __arena s8a;

static __always_inline
arenaptr mem_to_shadow(arenaptr addr)
{
	return (arenaptr)((u64) addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET;
}

/* Validate a 1-byte access, always within a single byte. */
static __always_inline bool memory_is_poisoned_1(arenaptr addr)
{
	s8 shadow_value = *(s8a *)mem_to_shadow(addr);

	/* Byte is 0, access is valid. */
	if (likely(!shadow_value))
		return false;

	/* Byte is non-zero, access is valid if granule offset in [0, shadow_value). */

	return GRANULE(addr) >= shadow_value;
}

/* Validate a 2- 4-, 8-byte access, spans up to 2 bytes. */
static __always_inline bool memory_is_poisoned_2_4_8(arenaptr addr, u64 size)
{
	arenaptr last_addr = (arenaptr)((u64)addr + size - 1);

	/*
	 * Region fully within a single byte (addition didn't
	 * overflow above KASAN_GRANULE).
	 */
	if (likely(GRANULE(last_addr) >= size - 1))
		return memory_is_poisoned_1((arenaptr)last_addr);

	/*
	 * Otherwise first byte must be fully unpoisoned, and second byte
	 * must be unpoisoned up to the end of the accessed region.
	 */

	return *mem_to_shadow(addr) || !memory_is_poisoned_1(last_addr);
}

static __always_inline u64 first_nonzero_byte(arenaptr addr, size_t size)
{
	u64 laddr = (u64)addr;

	while (size && can_loop) {
		if (unlikely((s8a *)laddr))
			return laddr;
		laddr += 1;
		size -= 1;
	}

	/*
	 * Can't return 0 because it is a valid arena address.
	 */

	return ARENA_LIMIT;
}

static __always_inline unsigned long memory_is_poisoned(arenaptr start, size_t size)
{
	int prefix = (unsigned long)start % 8;
	unsigned long ret;

	/*
	 * If <= 16 and in this function we're probably unaligned and will
	 * make two first_nonzero calls anyway, so bite the bullet now.
	 */
	if (size <= 16)
		return first_nonzero_byte(start, size);

	/* If shadow region not word-aligned, carve out the beginning. */
	if (prefix) {
		prefix = 8 - prefix;

		/* Check for poison within prefix bytes. */
		ret = first_nonzero_byte(start, prefix);
		if (unlikely(ret < ARENA_LIMIT))
			return ret;

		start += prefix;
	}

	/*
	 * Now we can test for poison one word at a time.
	 * Only do this for words where we care for all bytes.
	 */
	for (; size >= 8 && can_loop; size -= 8) {
		/* We found poison, return the byte within it. */
		if (unlikely(*(u64 *)start))
			return first_nonzero_byte(start, 8);

		/* Otherwise keep going. */
		start += 8;
	}

	/* Check the end if non-aligned. */

	return first_nonzero_byte(start, size);
}

static __always_inline bool memory_is_poisoned_n(arenaptr addr, u64 size)
{
	u64 ret;
	arenaptr start;
	arenaptr end;

	/* Size of [start, end] is end - start + 1. */
	start = mem_to_shadow(addr);
	end = mem_to_shadow(addr + size - 1);

	ret = first_nonzero_byte(start, (u64)(end - start) + 1);
	if (likely(ret == ARENA_LIMIT))
		return false;

	return __builtin_expect((arenaptr)ret != end || GRANULE(end) >= *end, false);
}

static __always_inline void asan_report(arenaptr addr, size_t sz, bool write)
{
	/* Only report the first ASAN violation. */
	if (likely(!reported)) {
		bpf_printk("[ARENA ASAN] Poisoned %s at address [%p, %p)", "[TODO]", NULL, NULL);
		reported = true;
	}

	/* XXX Flesh out. */
}

static __always_inline bool check_region_inline(void *ptr, size_t size, bool write)
{
	arenaptr addr = (arenaptr)ptr;

	/* Size 0 accesses are valid even if the address is invalid. */
	if (unlikely(size == 0))
		return true;

	/*
	 * Wraparound is possible for extremely high size. Possible if the size
	 * is a misinterpreted negative number.
	 */
	if (unlikely(addr + size < addr)) {
		bpf_printk("[ARENA_ASAN] Wraparound detected");
		asan_report(addr, size, write);
		return false;
	}

	/*
	 * The upper limit of the arena is an implicit guard around the shadow
	 * region. Possible when attempting to access the shadow map itself.
	 */
	if (unlikely((u64)mem_to_shadow(addr + size - 1) >= ARENA_LIMIT)) {
		bpf_printk("[ARENA_ASAN] Shadow map access");
		asan_report(addr, size, write);
		return false;
	}

	if (unlikely(memory_is_poisoned(addr, size))) {
		asan_report(addr, size, write);
		return false;
	}

	return true;
}

/*
 * __alias is not supported for BPF so define *__noabort() variants as wrappers.
 * XXX Is it a problem that the definition of __asan_store passes an address?
 */
#define DEFINE_ASAN_LOAD_STORE(size)						\
	void __asan_store##size(void *addr)					\
	{									\
		check_region_inline(addr, size, true);				\
	}									\
	void __always_inline __asan_store##size##_noabort(void *addr)		\
	{									\
		__asan_store##size(addr);					\
	}									\
	void __asan_load##size(void *addr)					\
	{									\
		check_region_inline(addr, size, false);				\
	}									\
	void __always_inline __asan_load##size##_noabort(void *addr)		\
	{									\
		__asan_load##size(addr);					\
	}

DEFINE_ASAN_LOAD_STORE(1);
DEFINE_ASAN_LOAD_STORE(2);
DEFINE_ASAN_LOAD_STORE(4);
DEFINE_ASAN_LOAD_STORE(8);

void __asan_storeN(void *addr, ssize_t size)
{
	check_region_inline(addr, size, false);
}

//__alias(__asan_storeN) void __asan_storeN_noabort(void *);

void __asan_loadN(void *addr, ssize_t size)
{
	check_region_inline(addr, size, true);
}

//__alias(__asan_loadN) void __asan_loadN_noabort(void *);


/* XXX What is the equivalent of __asan_global that we should use? */

void __asan_register_globals(void *globals, size_t n)
{
	/* XXX What is the format in which we are passing the globals? */
	/* XXX Build the poisoning function. Should use asan_poisoning.cpp as a guide. */
	bpf_printk("Emitted %s", __func__);
}

void __asan_unregister_globals(void *globals, size_t n)
{
	bpf_printk("Emitted %s", __func__);
}

// Functions concerning block memory destinations
void *__asan_memcpy(void *d, const void *s, size_t n)
{ 
	return NULL; 
}

void *__asan_memmove(void *d, const void *s, size_t n)
{ 
	bpf_printk("Emitted %s", __func__);
	return NULL;
}

void *__asan_memset(void *p, int c, size_t n)
{ 
	return NULL; 
}

// Functions concerning RTL startup and initialization
void __asan_init(void) {}
void __asan_handle_no_return(void) {}

// Functions concerning memory load and store reporting
void __asan_report_load_n(void *p, size_t n, bool abort) {}
void __asan_report_exp_load_n(void *p, size_t n, int exp, bool abort) {}
void __asan_report_store_n(void *p, size_t n, bool abort) {}
void __asan_report_exp_store_n(void *p, size_t n, int exp, bool abort) {}

// Functions concerning query about whether memory is poisoned
int __asan_address_is_poisoned(void const volatile *p) { return 0; }
void *__asan_region_is_poisoned(void const volatile *p, size_t size) {
  return NULL;
}

// Functions concerning the poisoning of memory
void __asan_poison_memory_region(void const volatile *p, size_t n) {}
void __asan_unpoison_memory_region(void const volatile *p, size_t n) {}

// Functions concerning the partial poisoning of memory
void __asan_set_shadow_xx_n(void *p, unsigned char xx, size_t n) {}

// Functions concerning array cookie poisoning
void __asan_poison_cxx_array_cookie(void *p) {}
void *__asan_load_cxx_array_cookie(void **p) { return NULL; }

// Functions concerning poisoning and unpoisoning fake stack alloca
void __asan_alloca_poison(void *addr, size_t size)
{
}

void __asan_allocas_unpoison(void *top, void *bottom)
{
}

// Functions concerning fake stack malloc
void *__asan_stack_malloc_n(size_t scale, size_t size)
{
	return NULL;
}
void *__asan_stack_malloc_always_n(size_t scale, size_t size)
{
  return NULL;
}

// Functions concerning fake stack free
void __asan_stack_free_n(int scale, void *p, size_t n)
{
}
