// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <math.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

struct fuzzer_buf_desc {
	uint64 ptr;
	uint64 sz;
};

#define FUZZER_IOCTL_MAP _IOWR('K', 8, struct fuzzer_buf_desc)
#define FUZZER_IOCTL_START _IOW('K', 10, uint16_t)
#define FUZZER_IOCTL_STOP _IO('K', 20)
#define FUZZER_IOCTL_UNMAP _IO('K', 30)
#define FUZZER_IOCTL_KASLR _IOR('K', 60, uint64_t)

// On arm64e the kext returns a PAC-signed function pointer: the upper bits hold
// the signature, the real VA lives in bits 47:0. Drop the signature and
// sign-extend bit 47 to rebuild the canonical kernel address.
static uint64_t strip_pac(uint64_t ptr)
{
	uint64_t va = ptr & 0x0000ffffffffffffULL;
	if (va & (1ULL << 47))
		va |= 0xffff000000000000ULL;
	return va;
}

// Reads the runtime address of _sanitizer_cov_trace_pc from the helper kext.
// Returns 0 (and leaves no trace beyond a debug line) on any failure, so the
// handshake never fails just because the slide could not be determined.
static uint64_t read_kaslr_runtime_addr(const char* device)
{
	if (device == NULL || device[0] == '\0')
		return 0;
	int fd = open(device, O_RDWR);
	if (fd == -1) {
		debug("kaslr: open of %s failed\n", device);
		return 0;
	}
	uint64_t addr = 0;
	if (ioctl(fd, FUZZER_IOCTL_KASLR, &addr) == -1) {
		debug("kaslr: FUZZER_IOCTL_KASLR failed\n");
		close(fd);
		return 0;
	}
	close(fd);
	return strip_pac(addr);
}

// Written by parse_handshake() before cover_open() is called.
// Empty kcov_device_g means no coverage device is configured.
static char kcov_device_g[256] = "";
static uint32_t kext_id_g = 1;

static fuzzer_buf_desc mc = {0};
static int kcov_fd = -1;

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	// Note: We use is_kernel_64_bit in executor.cc to decide which PC pointer
	// size to expect. However in KSANCOV we always get back 32bit pointers,
	// which then get reconstructed to 64bit pointers by adding a fixed offset.
	// This is not true with coverage collected with Pishi/KextFuzz
	is_kernel_64_bit = true;

	// int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	int prot = PROT_READ | PROT_WRITE;
	int flags = MAP_ANON | MAP_PRIVATE | MAP_FIXED;

	void* got = mmap(data, data_size, prot, flags, -1, 0);
	if (data != got)
		failmsg("mmap of data segment failed", "want %p, got %p", data, got);

	// Makes sure the file descriptor limit is sufficient to map control pipes.
	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = kMaxFd;
	setrlimit(RLIMIT_NOFILE, &rlim);
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	if (c->call == (syscall_t)syz_IOConnectCallMethod || c->call == (syscall_t)syz_IOConnectCallAsyncMethod) {
		iokitcall_t call = (iokitcall_t)c->call;
		return call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]);
	}

	if (c->call)
		return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);

	return __syscall(c->sys_nr, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
}

static void cover_open(cover_t* cov, bool extra)
{
	if (kcov_device_g[0] == '\0')
		fail("coverage requested but no kcov device configured: "
		     "set kext_coverage.kcov_device in config or disable cover");

	if (kcov_fd == -1) {
		kcov_fd = open(kcov_device_g, O_RDWR);
		if (kcov_fd == -1)
			failmsg("open of kcov device failed", "device=%s", kcov_device_g);

		if (ioctl(kcov_fd, FUZZER_IOCTL_MAP, &mc) == -1)
			fail("FUZZER_IOCTL_MAP failed");
		if (mc.ptr == 0)
			fail("FUZZER_IOCTL_MAP returned NULL pointer");
	}

	cov->fd = kcov_fd;
	cov->data = (char*)(uintptr_t)mc.ptr;
	cov->data_end = (char*)(uintptr_t)(mc.ptr + mc.sz);
}

static void cover_mmap(cover_t* cov)
{
}

static void cover_protect(cover_t* cov)
{
}

static void cover_unprotect(cover_t* cov)
{
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
	if (collect_comps)
		// fail("TRACE_CMP not implemented on darwin");
		return;
	if (extra)
		// fail("Extra coverage collection not implemented on darwin");
		return;
}

static void cover_reset(cover_t* cov)
{
	__atomic_store_n((uint64_t*)cov->data, 0, __ATOMIC_RELAXED);
	uint32_t target_id = kext_id_g;
	if (ioctl(kcov_fd, FUZZER_IOCTL_START, &target_id))
		exitf("FUZZER_IOCTL_START FAILED");
}

static void cover_collect(cover_t* cov)
{
	if (ioctl(kcov_fd, FUZZER_IOCTL_STOP, NULL) == -1)
		exitf("FUZZER_IOCTL_STOP FAILED");

	uint64 num = __atomic_load_n((uint64_t*)cov->data, __ATOMIC_RELAXED);
	if (num > kCoverSize / sizeof(uint64_t))
		num = kCoverSize / sizeof(uint64_t);

	cov->size = num;
	cov->data_offset = sizeof(uint64);
	cov->pc_offset = 0;
}
