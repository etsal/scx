/*
 * Implementation based on mm/kasan/generic.c.
 */

#define AASAN_SHADOW_SCALE_SHIFT (3)
#define AASAN_VALID_MASK ((1ULL << AASAN_SHADOW_SCALE_SHIFT) - 1)
#define AASAN_ACCESS_VALID(addr, shadowptr) ((((u64)(addr)) & AASAN_VALID_MASK) < *(shadowptr))

/* Same as in libbpf_internal.h */
#ifndef __alias
#define __alias(symbol) __attribute__((alias(#symbol)))
#endif /* __alias */


/*
 * XXX How do we include a reference to the arena map in a portable way?
 */

/*
 * XXX Switch for aborting on error. For now just keep executing.
 */

static bool reported = false;

/*
 * XXX Static key for turning ASAN off.
 */

typedef const void __arena * arenaptr;
typedef const s8 __arena * shadowptr;

/* XXX This has to be dynamic and incorporate user_vm_start. */
/* Shadow offset, including the userspace arena offset. */
const u64 shadow_offset = (1ULL << 31) * 3;

static inline
shadowptr mem_to_shadow(arenaptr addr)
{
	u64 arenaoff = (u64)addr & ((1ULL << 32) - 1);

	return (shadowptr)(arenaoff >> AASAN_SHADOW_SCALE_SHIFT) + shadow_offset;
}

/* Validate a 1-byte access, always within a single byte. */
static inline bool memory_is_poisoned_1(arenaptr addr)
{
	shadowptr ptr= mem_to_shadow(addr);

	/* Byte is 0, access is valid. */
	if (likely(!*ptr))
		return false;

	/* Byte is non-zero, access is valid if granule offset in [0, shadowval). */

	return __builtin_expect(AASAN_ACCESS_VALID(addr, ptr), false);
}

/* Validate a 2- 4-, 8-byte access, spans up to 2 bytes. */
static inline bool memory_is_poisoned_2_4_8(arenaptr addr, u64 size)
{
	arenaptr last_addr = addr + size - 1;

	/*
	 * Region fully within a single byte (addition didn't
	 * overflow above AASAN_AASAN_ACCESS).
	 */
	if (likely(((u64)last_addr & AASAN_VALID_MASK) >= size - 1))
		return memory_is_poisoned_1((arenaptr)last_addr);

	/*
	 * Otherwise first byte must be fully unpoisoned, and second byte
	 * must be unpoisoned up to the end of the accessed region.
	 */

	return *mem_to_shadow(addr) || memory_is_poisoned_1(last_addr);
}

/* Traverse the shadow map one byte at a time. Return the first non-zero byte. */
static inline shadowptr shadow_first_nonzero_8(shadowptr start, size_t size)
{
	while (size && can_loop) {
		if (unlikely(*start))
			return start;

		start += 1;
		size -= 1;
	}

	/* 
	 * We return 0 because we're dealing with _arena_ addresses, and those
	 * have the high 32-bits set to user_vm_start so they can't be 0.
	 */

	return 0;
}

static inline shadowptr shadow_first_nonzero_64(shadowptr start, size_t size)
{
	int prefix = (u64)start % 8;
	shadowptr shadow;

	/*
	 * If <= 16 and in this function we're probably unaligned and will
	 * make two first_nonzero calls anyway, so bite the bullet now.
	 */
	if (size <= 16)
		return shadow_first_nonzero_8(start, size);

	/* If shadow region not word-aligned, carve out the beginning. */
	if (prefix) {

		/* Check for poison within prefix bytes. */
		shadow = shadow_first_nonzero_8(start, 8 - prefix);
		if (unlikely(shadow))
			return shadow;

		start += 8 - prefix;
	}

	/*
	 * Now we can test for poison one word at a time.
	 * Only do this for words where we care for all bytes.
	 */
	while (size >= 8 && can_loop) {
		/* We found poison, return the byte within it. */
		if (unlikely(*(u64 __arena *)start))
			return shadow_first_nonzero_8(start, 8);

		/* Otherwise keep going. */
		start += 8;
		size -= 8;
	}

	/* Check the end if non-aligned. */

	return shadow_first_nonzero_8(start, size);
}

static inline bool memory_is_poisoned_n(arenaptr addr, u64 size)
{
	shadowptr start, end, shadow;

	/* Size of [start, end] is end - start + 1. */
	start = mem_to_shadow(addr);
	end = mem_to_shadow(addr + size - 1);

	shadow = shadow_first_nonzero_64(start, end - start + 1);
	if (likely(!shadow))
		return false;

	/* Found invalid memory in the middle of the accessed region. */
	if (unlikely(shadow != end))
		return true;

	/* Check if the invalid memory region overlaps with the access. */

	return __builtin_expect(AASAN_ACCESS_VALID(addr + size - 1, end), false);
}

static inline bool memory_is_poisoned(arenaptr addr, u64 size)
{
	if (__builtin_constant_p(size)) {

		switch (size) {
		case 1:
			memory_is_poisoned_1(addr);
		case 2:
		case 4:
		case 8:
			memory_is_poisoned_2_4_8(addr, size);
		default:
			return false;
		}
	}

	return memory_is_poisoned_n(addr, size);
}

static inline void asan_report(arenaptr addr, size_t size, bool write)
{
	/* Only report the first ASAN violation. */
	if (likely(!reported)) {
		bpf_printk("[ARENA ASAN] Poisoned %s at address [%p, %p)", addr, addr + size);
		reported = true;
	}

	/* XXX Flesh out. */
}

static inline bool check_region_inline(arenaptr addr, size_t size, bool write)
{

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
	 * XXX The bound if of course wrong, fix it by bringing in the arena.
	 */
	if (unlikely(mem_to_shadow(addr + size - 1) >= (shadowptr*)(1ULL << 32))) {
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


#define DEFINE_ASAN_LOAD_STORE(size)						\
	void __asan_store##size(void *addr)					\
	{									\
		check_region_inline((arenaptr) addr, size, false);		\
	}									\
	__alias(__asan_store##size) void __asan_store##size##_noabort(void *);	\
	void __asan_load##size(void *addr)					\
	{									\
		check_region_inline((arenaptr) addr, size, true);		\
	}									\
	__alias(__asan_load##size) void __asan_load##size##_noabort(void *);

DEFINE_ASAN_LOAD_STORE(1);
DEFINE_ASAN_LOAD_STORE(2);
DEFINE_ASAN_LOAD_STORE(4);
DEFINE_ASAN_LOAD_STORE(8);

void __asan_storeN(void *addr, ssize_t size)
{
	check_region_inline((arenaptr)addr, size, false);
}

__alias(__asan_storeN) void __asan_storeN_noabort(void *);

void __asan_loadN(void *addr, ssize_t size)
{
	check_region_inline((arenaptr)addr, size, true);
}

__alias(__asan_loadN) void __asan_loadN_noabort(void *);


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
void __asan_init(void)
{

	/* XXX Compute the shadow offset. */

}
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
