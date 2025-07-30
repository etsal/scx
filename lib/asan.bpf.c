

#include "asan_abi.h"

#define GRANULE(expr) ((u64)((expr) & KASAN_GRANULE_MASK))


/*
 * XXX Switch for turning ASAN off.
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

typedef const void __arena * arenaptr;
typedef s8 __arena s8a;

static inline
arenaptr mem_to_shadow(arenaptr addr)
{
	return (arenaptr)((u64) addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET;
}

/* Validate a 1-byte access, always within a single byte. */
static always inline bool memory_is_poisoned_1(const void __arena *addr)
{
	s8 shadow_value = *(s8a *)mem_to_shadow(addr);
	s8 last_accessible;

	/* Byte is 0, access is valid. */
	if (likely(!shadow_value))
		return false;

	/* Byte is non-zero, access is valid if granule offset in [0, shadow_value). */

	return GRANULE(addr) >= shadow_value;
}

/* Validate a 2- to 16-byte access, spans up to 2 bytes. */
static always inline bool memory_is_poisoned_sub_16(const void __arena *addr, u64 size)
{
	u64 last_addr = (u64)addr + size - 1;

	/* 
	 * Region fully within a single byte (addition didn't 
	 * overflow above KASAN_GRANULE).
	 */
	if (likely(GRANULE(lastaddr) >= size - 1))
		return memory_is_poisoned_1(last_addr);

	/* 
	 * Otherwise first byte must be fully unpoisoned, and second byte
	 * must be unpoisoned up to the end of the accessed region. 
	 */

	return *mem_to_shadow(addr) || !memory_is_poisoned_1(last_addr);
}

/*
 * For now just keep executing.
 */

static bool reported = false;

static inline void asan_report(arenaptr addr, size_t write, bool write)
{
	/* Only report the first ASAN violation. */
	if (likely(!reported)) {
		bpf_printk("[ARENA ASAN] Poisoned %s at address [%p, %p)", );
		reported = true;
	}
}

static inline bool check_region_inline(arenaptr addr, size_t size, bool write)
{
	if (unlikely(size == 0))
		return true;

	/* 
	 * XXX This is a judgement call on my end and imposes policy on
	 * the user. Ensure it is a reasonable expectation.
	 *
	 * We assume wrararound is invalid even if allowed by arenas.
	 */
	 
	if (unlikely(addr + size < addr)) {
		bpf_printk("[ARENA_ASAN] Wraparound detected");
		asan_report(addr, size, write);
	}

	if (/* XXX Check that the address is after the region start and before the end*/) {
	}

	/* Chekc if memory is poisoned */

}

/* BPF does not support 16-byte accesses so we do not care about handling them. */

u64 mem_nonzero(const char *start, const char *end)
{
	
}

bool mem_poisoned(const void *addr, u64 size)
{
}

bool check_or_report(const void *adrdr, size_t size, bool write, u64 ret_ip)
{
}


// Functions concerning instrumented global variables:
//
/* XXX Looks like a simple wrapper */
void __asan_register_image_globals(void) {}
void __asan_unregister_image_globals(void) {}

bool check_region(const void *addr)
{
	if (unlikely(size == 
}


/* XXX What is the equivalent of __asan_global that we should use? */


void __asan_register_elf_globals(bool *flag, void *start, void *stop)
{
	/* XXX Identifies all the ELF globals and passes them to register/. */
}

void __asan_unregister_elf_globals(bool *flag, void *start, void *stop) {

}

void __asan_register_globals(void *globals, size_t n)
{
	/* XXX What is the format in which we are passing the globals? */
	/* XXX Build the poisoning function. Should use asan_poisoning.cpp as a guide. */
}

void __asan_unregister_globals(void *globals, size_t n)
{
}

// Functions concerning dynamic library initialization
void __asan_before_dynamic_init(const char *module_name) {}
void __asan_after_dynamic_init(void) {}

// Functions concerning block memory destinations
void *__asan_memcpy(void *d, const void *s, size_t n) { return NULL; }
void *__asan_memmove(void *d, const void *s, size_t n) { return NULL; }
void *__asan_memset(void *p, int c, size_t n) { return NULL; }

// Functions concerning RTL startup and initialization
void __asan_init(void) {}
void __asan_handle_no_return(void) {}

// Functions concerning memory load and store reporting
void __asan_report_load_n(void *p, size_t n, bool abort) {}
void __asan_report_exp_load_n(void *p, size_t n, int exp, bool abort) {}
void __asan_report_store_n(void *p, size_t n, bool abort) {}
void __asan_report_exp_store_n(void *p, size_t n, int exp, bool abort) {}

// Functions concerning memory load and store
void __asan_load_n(void *p, size_t n, bool abort) {}
void __asan_exp_load_n(void *p, size_t n, int exp, bool abort) {}
void __asan_store_n(void *p, size_t n, bool abort) {}
void __asan_exp_store_n(void *p, size_t n, int exp, bool abort) {}

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

// Functions concerning stack poisoning
void __asan_poison_stack_memory(void *p, size_t n) {}
void __asan_unpoison_stack_memory(void *p, size_t n) {}

// Functions concerning redzone poisoning
void __asan_poison_intra_object_redzone(void *p, size_t size) {}
void __asan_unpoison_intra_object_redzone(void *p, size_t size) {}

// Functions concerning array cookie poisoning
void __asan_poison_cxx_array_cookie(void *p) {}
void *__asan_load_cxx_array_cookie(void **p) { return NULL; }

// Functions concerning fake stacks
void *__asan_get_current_fake_stack(void) { return NULL; }
void *__asan_addr_is_in_fake_stack(void *fake_stack, void *addr, void **beg,
                                       void **end) {
  return NULL;
}

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
