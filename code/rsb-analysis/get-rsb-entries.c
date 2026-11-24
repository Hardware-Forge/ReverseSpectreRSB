#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <emmintrin.h>
#include <x86intrin.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <stdbool.h>
#include <string.h>

void pin_cpu0()
{
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);  // Pin to CPU 0

	if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == -1) {
		perror("sched_setaffinity");
		exit(EXIT_FAILURE);
	}
}

#define N 64
#define CACHE_LINE 0x400  // It's smaller, but it's better to be safe

char pad1[0x1000];
uint8_t target[CACHE_LINE * N];
char pad2[0x1000];
volatile uint8_t foo;

void setup()
{
	pin_cpu0();
	for (size_t i = 0; i < N; i++) {
		target[i * CACHE_LINE] = 1;
	}
}


#define TIME_ACCESS(acc, start, end) \
	_mm_mfence(); \
	*start = __rdtsc(); \
	_mm_mfence(); \
	acc; \
	_mm_mfence(); \
	*end = __rdtsc(); \
	_mm_mfence(); \


extern void attack(uint64_t, void*, uint8_t*);

#define GADGET(X, Y) \
	void gadget##X(size_t rsb, void* rbp) \
	{ \
		gadget##Y(rsb, rbp); \
		foo &= target[CACHE_LINE * (N - 1 - X)]; \
		_mm_mfence(); \
	} \


void gadget63(size_t rsb, void* rbp)
{
	__asm__ __volatile__ (" \
		jmp attack; \
	"
		:
		: "D"(rsb), "S"(rbp), "d"(target) 
	);
}

GADGET(62, 63)
GADGET(61, 62)
GADGET(60, 61)
GADGET(59, 60)
GADGET(58, 59)
GADGET(57, 58)
GADGET(56, 57)
GADGET(55, 56)
GADGET(54, 55)
GADGET(53, 54)
GADGET(52, 53)
GADGET(51, 52)
GADGET(50, 51)
GADGET(49, 50)
GADGET(48, 49)
GADGET(47, 48)
GADGET(46, 47)
GADGET(45, 46)
GADGET(44, 45)
GADGET(43, 44)
GADGET(42, 43)
GADGET(41, 42)
GADGET(40, 41)
GADGET(39, 40)
GADGET(38, 39)
GADGET(37, 38)
GADGET(36, 37)
GADGET(35, 36)
GADGET(34, 35)
GADGET(33, 34)
GADGET(32, 33)
GADGET(31, 32)
GADGET(30, 31)
GADGET(29, 30)
GADGET(28, 29)
GADGET(27, 28)
GADGET(26, 27)
GADGET(25, 26)
GADGET(24, 25)
GADGET(23, 24)
GADGET(22, 23)
GADGET(21, 22)
GADGET(20, 21)
GADGET(19, 20)
GADGET(18, 19)
GADGET(17, 18)
GADGET(16, 17)
GADGET(15, 16)
GADGET(14, 15)
GADGET(13, 14)
GADGET(12, 13)
GADGET(11, 12)
GADGET(10, 11)
GADGET( 9, 10)
GADGET( 8,  9)
GADGET( 7,  8)
GADGET( 6,  7)
GADGET( 5,  6)
GADGET( 4,  5)
GADGET( 3,  4)
GADGET( 2,  3)
GADGET( 1,  2)
GADGET( 0,  1)

/*
void gadget(size_t depth, size_t rsb, void* rbp)
{
	if (depth) {
		_mm_mfence();
		gadget(depth - 1, rsb, rbp);
		foo &= target[CACHE_LINE * depth];
		_mm_mfence();
	}
	// attack(rsb, rbp, target);

	__asm__ __volatile__ (" \
		jmp attack; \
	"
		:
		: "D"(rsb), "S"(rbp), "d"(target) 
	);
}
*/

void launch_attack(size_t rsb)
{
	void* rbp;
	__asm__ __volatile__ (
		"mov %0, rbp;\n"
		: "=r"(rbp)
	);
	for (size_t i = 0; i < N; i++) {
		_mm_clflush(&target[CACHE_LINE * i]);
	}
	_mm_mfence();
	gadget0(rsb, rbp);
}

uint64_t check_depth(size_t rsb, size_t bt_freq[static N])
{
	uint64_t start, end;
	uint64_t min_time = 10000000000;

	memset(bt_freq, 0, N * sizeof(*bt_freq));

	size_t mix_i;
	for (size_t i = 0; i < 0x1000; i++) {
		launch_attack(rsb);
		foo = 0;
		_mm_mfence();

		for (size_t j = 0; j < N; j++) {
			mix_i = ((j * 167) + 13) & (N - 1);
			TIME_ACCESS(foo = target[CACHE_LINE * mix_i], &start, &end);
			if (end - start < min_time) {
				min_time = end - start;
				memset(bt_freq, 0, N * sizeof(*bt_freq));
			}
			if (end - start == min_time) {
				bt_freq[mix_i]++;
			}
		}
	}

	// for (size_t i = 0; i < N; i++) {
	// 	printf("%3zu: %zu\n", i, times[i]);
	// }

	return min_time;
}

struct el_t {
	size_t ind;
	size_t val;
};

int comp_el(const void* a, const void* b)
{
	const struct el_t* a_ = a;
	const struct el_t* b_ = b;
	return a_->val < b_->val;
}

void print_res(size_t depth, uint64_t time, size_t bt_freq[static N])
{
	struct el_t arr[N];
	for (size_t i = 0; i < N; i++) {
		arr[i] = (struct el_t){i, bt_freq[i]};
	}

	qsort(arr, N, sizeof(struct el_t), comp_el);

	printf("Depth %2zu: time %zu, entries: ", depth, time);

	size_t ind = 0;
	while (ind < N && arr[ind].val) {
		printf("%2zu: %4zu%s", arr[ind].ind, arr[ind].val, ind + 1 < N && arr[ind + 1].val ? ", " : "\n");
		ind++;
	}
}

int main() {
	setup();

	size_t bt_freq[N];

	for (size_t i = 1; i <= N; i++) {
		uint64_t min_time = check_depth(i, bt_freq);
		print_res(i, min_time, bt_freq);
	}
}
