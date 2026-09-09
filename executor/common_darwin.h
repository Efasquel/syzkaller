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
	if ((uint64*)scalar_output == NULL && (uint32*)scalar_outputCnt != NULL)
		return 1;
	if ((void*)ool_output == NULL && (size_t*)ool_output_size != NULL)
		return 1;
	return 0;
}

static long __attribute__((unused)) syz_IOConnectCallMethod(volatile long arg0, volatile long arg1, volatile long arg2, volatile long arg3,
							    volatile long arg4, volatile long arg5, volatile long arg6, volatile long arg7, volatile long arg8,
							    volatile long arg9)
{
	long ret;

	// Avoid SIGSEG
	if (check_input(arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9))
		return -1;

	ret = IOConnectCallMethod((mach_port_t)arg0, (uint32)arg1,
				  (const uint64*)arg2, (uint32)arg3,
				  (const void*)arg4, (size_t)arg5,
				  (uint64*)arg6, (uint32*)arg7,
				  (void*)arg8, (size_t*)arg9);
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
	if (check_input(arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9))
		return -1;

	ret = IOConnectCallAsyncMethod((mach_port_t)arg0, (uint32)arg1,
				       p, (uint64*)&async_ref, 1,
				       (const uint64*)arg2, (uint32)arg3,
				       (const void*)arg4, (size_t)arg5,
				       (uint64*)arg6, (uint32*)arg7,
				       (void*)arg8, (size_t*)arg9);
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
