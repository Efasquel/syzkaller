// Adapted from SyzGenPlusPlus
#include <IOKit/IOKitLib.h>
#include <errno.h>
#include <mach/mach.h>

struct async_reference {
	mach_port_t port;
	void (*fptr)(void);
	uint64 something;
};

static long __attribute__((unused)) syz_IOServiceOpen(volatile long name, volatile int typ, volatile long port)
{
	const char* service_name = (const char*)name;
	io_connect_t* port_ptr = (io_connect_t*)port;
	if (service_name == NULL || port_ptr == NULL)
		return -1;

	io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault,
							   IOServiceMatching(service_name));
	if (!service) {
		return -1;
	}
	kern_return_t kr = IOServiceOpen(service, mach_task_self(), typ, port_ptr);
	IOObjectRelease(service);
	if (kr != kIOReturnSuccess) {
		return kr;
	}
	return 0;
}

static long __attribute__((unused)) syz_IOServiceClose(volatile long arg)
{
	io_connect_t port = (io_connect_t)arg;
	return IOServiceClose(port);
}

static long check_input(long scalar_input, long scalar_inputCnt, long inband_input, long inband_inputCnt,
			long scalar_output, long scalar_outputCnt, long ool_output, long ool_output_size)
{
	if ((const uint64*)scalar_input == NULL && (uint32)scalar_inputCnt != 0)
		return 1;
	if ((const void*)inband_input == NULL && (size_t)inband_inputCnt != 0)
		return 1;
	// A NULL output with a count pointer is how a selector says "no output":
	// IOKit only writes through the buffer when the count is non-zero. Rejecting
	// on the pointer alone dropped every grammar-valid call to such selectors
	// before it reached the kernel. Reading the count is safe here: the call runs
	// under NONFAILING, so a bad count pointer faults recoverably.
	if ((uint64*)scalar_output == NULL && (uint32*)scalar_outputCnt != NULL &&
	    *(uint32*)scalar_outputCnt != 0)
		return 1;
	if ((void*)ool_output == NULL && (size_t*)ool_output_size != NULL &&
	    *(size_t*)ool_output_size != 0)
		return 1;
	return 0;
}

#if SYZ_EXECUTOR
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

// Index of the call being executed on this thread, set by execute_call().
static __thread int syz_iokit_call_index = -1;

// IOKit outputs never reach the manager: CallInfo carries only the error. When
// SYZ_IOKIT_OUTPUT_LOG names a file, append one JSON line per IOConnectCall*
// with the request id (the manager's ExecRequest id), call index, selector,
// IOReturn and the scalar/struct outputs, so freq_lab can join them with its
// records. The pointers were already used by IOKit, and this runs under
// NONFAILING, so reading them is safe.
static void log_iokit_outputs(uint32 selector, kern_return_t kr, const uint64* scalar_out, const uint32* scalar_cnt,
			      const void* struct_out, const size_t* struct_cnt)
{
	static const char* path = (const char*)-1;
	if (path == (const char*)-1)
		path = getenv("SYZ_IOKIT_OUTPUT_LOG");
	if (path == NULL)
		return;
	enum { kMaxScalars = 16,
	       kMaxStructBytes = 4096 };
	char buf[512 + kMaxScalars * 24 + kMaxStructBytes * 2];
	size_t n = snprintf(buf, sizeof(buf), "{\"req\":%llu,\"call\":%d,\"sel\":%u,\"kr\":%d,\"scalar_out\":[",
			    (unsigned long long)request_id, syz_iokit_call_index, selector, kr);
	uint32 ns = (scalar_out && scalar_cnt) ? *scalar_cnt : 0;
	if (ns > kMaxScalars)
		ns = kMaxScalars;
	for (uint32 i = 0; i < ns; i++)
		n += snprintf(buf + n, sizeof(buf) - n, "%s%llu", i ? "," : "", (unsigned long long)scalar_out[i]);
	n += snprintf(buf + n, sizeof(buf) - n, "],\"struct_out\":\"");
	size_t nb = (struct_out && struct_cnt) ? *struct_cnt : 0;
	size_t full = nb;
	if (nb > kMaxStructBytes)
		nb = kMaxStructBytes;
	for (size_t i = 0; i < nb; i++)
		n += snprintf(buf + n, sizeof(buf) - n, "%02x", ((const uint8*)struct_out)[i]);
	n += snprintf(buf + n, sizeof(buf) - n, "\",\"struct_out_size\":%zu}\n", full);
	if (n >= sizeof(buf))
		n = sizeof(buf) - 1;
	int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (fd < 0)
		return;
	if (write(fd, buf, n) > 0)
		fsync(fd);
	close(fd);
}
#define LOG_IOKIT_OUTPUTS(sel, kr, so, sc, oo, oc) log_iokit_outputs(sel, kr, so, sc, oo, oc)
#else
#define LOG_IOKIT_OUTPUTS(sel, kr, so, sc, oo, oc)
#endif

static long __attribute__((unused)) syz_IOConnectCallMethod(volatile long arg0, volatile long arg1, volatile long arg2, volatile long arg3,
							    volatile long arg4, volatile long arg5, volatile long arg6, volatile long arg7, volatile long arg8,
							    volatile long arg9)
{
	long ret;

	// Avoid SIGSEG
	if (check_input(arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)) {
		// Say so: otherwise errno is whatever the last call left behind, and a
		// rejected call reads in the log as a kernel error it never produced.
		errno = EINVAL;
		return -1;
	}

	ret = IOConnectCallMethod((mach_port_t)arg0, (uint32)arg1,
				  (const uint64*)arg2, (uint32)arg3,
				  (const void*)arg4, (size_t)arg5,
				  (uint64*)arg6, (uint32*)arg7,
				  (void*)arg8, (size_t*)arg9);
	LOG_IOKIT_OUTPUTS((uint32)arg1, ret, (const uint64*)arg6, (const uint32*)arg7, (const void*)arg8, (const size_t*)arg9);
	errno = ret;
	if (ret != 0)
		return -1;
	return 0;
}

static long __attribute__((unused)) syz_IOConnectCallAsyncMethod(volatile long arg0, volatile long arg1, volatile long arg2, volatile long arg3,
								 volatile long arg4, volatile long arg5, volatile long arg6, volatile long arg7, volatile long arg8,
								 volatile long arg9)
{

	long ret;
	mach_port_t p = MACH_PORT_NULL;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
	mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);

	struct async_reference async_ref = {0};
	async_ref.port = p;

	// Avoid SIGSEG
	if (check_input(arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)) {
		// Say so: otherwise errno is whatever the last call left behind, and a
		// rejected call reads in the log as a kernel error it never produced.
		errno = EINVAL;
		return -1;
	}

	ret = IOConnectCallAsyncMethod((mach_port_t)arg0, (uint32)arg1,
				       p, (uint64*)&async_ref, 1,
				       (const uint64*)arg2, (uint32)arg3,
				       (const void*)arg4, (size_t)arg5,
				       (uint64*)arg6, (uint32*)arg7,
				       (void*)arg8, (size_t*)arg9);
	LOG_IOKIT_OUTPUTS((uint32)arg1, ret, (const uint64*)arg6, (const uint32*)arg7, (const void*)arg8, (const size_t*)arg9);
	errno = ret;
	if (ret != 0)
		return -1;
	return 0;
}

// Traps hand six raw words straight to the handler with no marshalling, so
// unlike IOConnectCallMethod there is deliberately no check_input() here.
// All seven arities are defined so descriptions can name any of them.
#define SYZ_IOCONNECT_TRAP(call)    \
	kern_return_t kr = (call);  \
	errno = kr;                 \
	if (kr != kIOReturnSuccess) \
		return -1;          \
	return 0;

static long __attribute__((unused)) syz_IOConnectTrap0(volatile long port, volatile long index)
{
	SYZ_IOCONNECT_TRAP(IOConnectTrap0((io_connect_t)port, (uint32)index))
}

static long __attribute__((unused)) syz_IOConnectTrap1(volatile long port, volatile long index, volatile long p1)
{
	SYZ_IOCONNECT_TRAP(IOConnectTrap1((io_connect_t)port, (uint32)index, (uintptr_t)p1))
}

static long __attribute__((unused)) syz_IOConnectTrap2(volatile long port, volatile long index, volatile long p1, volatile long p2)
{
	SYZ_IOCONNECT_TRAP(IOConnectTrap2((io_connect_t)port, (uint32)index, (uintptr_t)p1, (uintptr_t)p2))
}

static long __attribute__((unused)) syz_IOConnectTrap3(volatile long port, volatile long index, volatile long p1, volatile long p2, volatile long p3)
{
	SYZ_IOCONNECT_TRAP(IOConnectTrap3((io_connect_t)port, (uint32)index, (uintptr_t)p1, (uintptr_t)p2, (uintptr_t)p3))
}

static long __attribute__((unused)) syz_IOConnectTrap4(volatile long port, volatile long index, volatile long p1, volatile long p2, volatile long p3, volatile long p4)
{
	SYZ_IOCONNECT_TRAP(IOConnectTrap4((io_connect_t)port, (uint32)index, (uintptr_t)p1, (uintptr_t)p2, (uintptr_t)p3, (uintptr_t)p4))
}

static long __attribute__((unused)) syz_IOConnectTrap5(volatile long port, volatile long index, volatile long p1, volatile long p2, volatile long p3, volatile long p4, volatile long p5)
{
	SYZ_IOCONNECT_TRAP(IOConnectTrap5((io_connect_t)port, (uint32)index, (uintptr_t)p1, (uintptr_t)p2, (uintptr_t)p3, (uintptr_t)p4, (uintptr_t)p5))
}

static long __attribute__((unused)) syz_IOConnectTrap6(volatile long port, volatile long index, volatile long p1, volatile long p2, volatile long p3, volatile long p4, volatile long p5, volatile long p6)
{
	SYZ_IOCONNECT_TRAP(IOConnectTrap6((io_connect_t)port, (uint32)index, (uintptr_t)p1, (uintptr_t)p2, (uintptr_t)p3, (uintptr_t)p4, (uintptr_t)p5, (uintptr_t)p6))
}
