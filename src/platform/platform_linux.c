/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer main module.

Environment:

    Linux

--*/

#define _GNU_SOURCE
#include "platform_internal.h"
#include "quic_platform.h"
#ifdef QUIC_PLATFORM_LINUX
#include <sys/syscall.h>
#endif

#include <limits.h>
#include <sched.h>
#include <fcntl.h>
#include <syslog.h>
#include <dlfcn.h>
#include "quic_trace.h"
#include "quic_platform_dispatch.h"

#define QUIC_MAX_LOG_MSG_LEN        1024 // Bytes

QUIC_PLATFORM Quicform = { NULL };

int RandomFd; // Used for reading random numbers.

QUIC_TRACE_RUNDOWN_CALLBACK* QuicTraceRundownCallback;


static const char TpLibName[] = "libmsquic.lttng.so";

uint32_t QuicProcessorCount;

uint64_t QuicTotalMemory;

__attribute__((noinline, noreturn))
void
quic_bugcheck(
    void
    )
{
    //
    // We want to prevent this routine from being inlined so that we can
    // easily detect when our bugcheck conditions have occurred just by
    // looking at callstack. However, even after specifying inline attribute,
    // it is possible certain optimizations will cause inlining. asm technique
    // is the gcc documented way to prevent such optimizations.
    //
    asm("");

    //
    // abort() sends a SIGABRT signal and it triggers termination and coredump.
    //
    abort();
}

void
QuicPlatformSystemLoad(
    void
    )
{
    //
    // Following code is modified from coreclr.
    // https://github.com/dotnet/coreclr/blob/ed5dc831b09a0bfed76ddad684008bebc86ab2f0/src/pal/src/misc/tracepointprovider.cpp#L106
    //
    //
    //arm64 macOS has no way to get the current proc, so treat as single core.
    //Intel macOS can return incorrect values for CPUID, so treat as single core.
    //          
    QuicProcessorCount = (uint32_t)sysconf(_SC_NPROCESSORS_ONLN);

    //
    //Following code is modified from coreclr.
    //https://github.com/dotnet/coreclr/blob/ed5dc831b09a0bfed76ddad684008bebc86ab2f0/src/pal/src/misc/tracepointprovider.cpp#L106
    //          

    long ShouldLoad = 1;

    //
    // Check if loading the LTTng providers should be disabled.
    //
    char *DisableValue = getenv("QUIC_LTTng");
    if (DisableValue != NULL) {
        ShouldLoad = strtol(DisableValue, NULL, 10);
    }

    if (!ShouldLoad) {
        return;
    }

    //
    // Get the path to the currently executing shared object (libmsquic.so).
    //
    Dl_info Info;
    int Succeeded = dladdr((void *)QuicPlatformSystemLoad, &Info);
    if (!Succeeded) {
        return;
    }

    size_t PathLen = strlen(Info.dli_fname);

    //
    // Find the length of the full path without the shared object name, including the trailing slash.
    //
    int LastTrailingSlashLen = -1;
    for (int i = PathLen; i >= 0; i--) {
        if (Info.dli_fname[i] == '/') {
            LastTrailingSlashLen = i + 1;
            break;
        }
    }

    if (LastTrailingSlashLen == -1) {
        return;
    }

    size_t TpLibNameLen = strlen(TpLibName);
    size_t ProviderFullPathLength = TpLibNameLen + LastTrailingSlashLen + 1;

    char* ProviderFullPath = QUIC_ALLOC_PAGED(ProviderFullPathLength);
    if (ProviderFullPath == NULL) {
        return;
    }

    QuicCopyMemory(ProviderFullPath, Info.dli_fname, LastTrailingSlashLen);
    QuicCopyMemory(ProviderFullPath + LastTrailingSlashLen, TpLibName, TpLibNameLen);
    ProviderFullPath[LastTrailingSlashLen + TpLibNameLen] = '\0';

    //
    // Load the tracepoint provider.
    // It's OK if this fails - that just means that tracing dependencies aren't available.
    //
    dlopen(ProviderFullPath, RTLD_NOW | RTLD_GLOBAL);

    QUIC_FREE(ProviderFullPath);

#ifdef DEBUG
    Quicform.AllocFailDenominator = 0;
    Quicform.AllocCounter = 0;
#endif

}

void
QuicPlatformSystemUnload(
    void
    )
{
}

QUIC_STATUS
QuicPlatformInitialize(
    void
    )
{

    RandomFd = open("/dev/urandom", O_RDONLY|O_CLOEXEC);
    if (RandomFd == -1) {
        return (QUIC_STATUS)errno;
    }


    QuicTotalMemory = 0x40000000; // TODO - Hard coded at 1 GB. Query real value.

    return QUIC_STATUS_SUCCESS;
}

void
QuicPlatformUninitialize(
    void
    )
{
    close(RandomFd);
}

void*
QuicAlloc(
    _In_ size_t ByteCount
    )
{
#ifdef DEBUG
    uint32_t Rand;
    if ((Quicform.AllocFailDenominator > 0 && (QuicRandom(sizeof(Rand), &Rand), Rand % Quicform.AllocFailDenominator) == 1) ||
        (Quicform.AllocFailDenominator < 0 && InterlockedIncrement(&Quicform.AllocCounter) % Quicform.AllocFailDenominator == 0)) {
        return NULL;
    }
#endif
    return malloc(ByteCount);

}

void
QuicFree(
        __drv_freesMem(Mem) _Frees_ptr_opt_ void* Mem
    )
{
    free(Mem);
}

void
QuicRefInitialize(
    _Inout_ QUIC_REF_COUNT* RefCount
    )
{
    *RefCount = 1;
}

void
QuicRefIncrement(
    _Inout_ QUIC_REF_COUNT* RefCount
    )
{
    if (__atomic_add_fetch(RefCount, 1, __ATOMIC_SEQ_CST)) {
        return;
    }

    QUIC_FRE_ASSERT(FALSE);
}

BOOLEAN
QuicRefIncrementNonZero(
    _Inout_ volatile QUIC_REF_COUNT* RefCount
    )
{
    QUIC_REF_COUNT OldValue = *RefCount;

    for (;;) {
        QUIC_REF_COUNT NewValue = OldValue + 1;

        if (NewValue > 1) {
            if(__atomic_compare_exchange_n(RefCount, &OldValue, NewValue, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                return TRUE;
            }
			continue;
        } 

		if (NewValue == 1) {
            return FALSE;
        } 
        QUIC_FRE_ASSERT(false);
        return FALSE;   
    }
}

BOOLEAN
QuicRefDecrement(
    _In_ QUIC_REF_COUNT* RefCount
    )
{
    QUIC_REF_COUNT NewValue = __atomic_sub_fetch(RefCount, 1, __ATOMIC_SEQ_CST);

    if (NewValue > 0) {
        return FALSE;
    } else if (NewValue == 0) {
        return TRUE;
    }

    QUIC_FRE_ASSERT(FALSE);

    return FALSE;
}

void
QuicRundownInitialize(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    QuicRefInitialize(&((Rundown)->RefCount));
    QuicEventInitialize(&((Rundown)->RundownComplete), false, false);
}

void
QuicRundownInitializeDisabled(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    (Rundown)->RefCount = 0;
    QuicEventInitialize(&((Rundown)->RundownComplete), false, false);
}

void
QuicRundownReInitialize(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    (Rundown)->RefCount = 1;
}

void
QuicRundownUninitialize(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    QuicEventUninitialize((Rundown)->RundownComplete);
}

BOOLEAN
QuicRundownAcquire(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    return QuicRefIncrementNonZero(&(Rundown)->RefCount);
}

void
QuicRundownRelease(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    if (QuicRefDecrement(&(Rundown)->RefCount)) {
        QuicEventSet((Rundown)->RundownComplete);
    }
}

void
QuicRundownReleaseAndWait(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    )
{
    if (!QuicRefDecrement(&(Rundown)->RefCount)) {
        QuicEventWaitForever((Rundown)->RundownComplete);
    }
}

uint64_t
QuicTimespecToUs(
    _In_ const struct timespec *Time
    )
{
    return (Time->tv_sec * QUIC_MICROSEC_PER_SEC) + (Time->tv_nsec / QUIC_NANOSEC_PER_MICROSEC);
}

uint64_t
QuicGetTimerResolution(
    void
    )
{
    struct timespec Res = {0};
    int ErrorCode = clock_getres(CLOCK_MONOTONIC, &Res);
    QUIC_DBG_ASSERT(ErrorCode == 0);
    UNREFERENCED_PARAMETER(ErrorCode);
    return QuicTimespecToUs(&Res);
}

uint64_t
QuicTimeUs64(
    void
    )
{
    struct timespec CurrTime = {0};
    int ErrorCode = clock_gettime(CLOCK_MONOTONIC, &CurrTime);
    QUIC_DBG_ASSERT(ErrorCode == 0);
    UNREFERENCED_PARAMETER(ErrorCode);
    return QuicTimespecToUs(&CurrTime);
}

void
QuicGetAbsoluteTime(
    _In_ unsigned long DeltaMs,
    _Out_ struct timespec *Time
    )
{
    int ErrorCode = 0;

    QuicZeroMemory(Time, sizeof(struct timespec));

#if defined(QUIC_PLATFORM_LINUX)
    ErrorCode = clock_gettime(CLOCK_MONOTONIC, Time);
#elif defined(QUIC_PLATFORM_DARWIN)
    //
    //timespec_get is used on darwin, as CLOCK_MONOTONIC isn't actually
    //monotonic according to our tests.
    //           
    timespec_get(Time, TIME_UTC);
#endif // QUIC_PLATFORM_DARWIN	

    QUIC_DBG_ASSERT(ErrorCode == 0);
    UNREFERENCED_PARAMETER(ErrorCode);

    Time->tv_sec += (DeltaMs / QUIC_MS_PER_SECOND);
    Time->tv_nsec += ((DeltaMs % QUIC_MS_PER_SECOND) * QUIC_NANOSEC_PER_MS);

    if (Time->tv_nsec > QUIC_NANOSEC_PER_SEC)
    {
        Time->tv_sec += 1;
        Time->tv_nsec -= QUIC_NANOSEC_PER_SEC;
    }

    QUIC_DBG_ASSERT(Time->tv_sec >= 0);
    QUIC_DBG_ASSERT(Time->tv_nsec >= 0);
    QUIC_DBG_ASSERT(Time->tv_nsec < QUIC_NANOSEC_PER_SEC);

}

void
QuicSleep(
    _In_ uint32_t DurationMs
    )
{
    int ErrorCode = 0;
    struct timespec TS = {
        .tv_sec = (DurationMs / QUIC_MS_PER_SECOND),
        .tv_nsec = (QUIC_NANOSEC_PER_MS * (DurationMs % QUIC_MS_PER_SECOND))
    };

    ErrorCode = nanosleep(&TS, &TS);
    QUIC_DBG_ASSERT(ErrorCode == 0);
    UNREFERENCED_PARAMETER(ErrorCode);
}

uint32_t QuicProcCurrentNumber(void)
{
#if defined(QUIC_PLATFORM_LINUX)
    return (uint32_t)sched_getcpu() % QuicProcessorCount;
#elif defined(QUIC_PLATFORM_DARWIN)

    //
    //arm64 macOS has no way to get the current proc, so treat as single core.
    //Intel macOS can return incorrect values for CPUID, so treat as single core.
    //           
    return 0;
#endif // QUIC_PLATFORM_DARWIN

}

QUIC_STATUS
QuicRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    )
{
    if (read(RandomFd, Buffer, BufferLen) == -1) {
        return (QUIC_STATUS)errno;
    }
    return QUIC_STATUS_SUCCESS;
}

void
QuicConvertToMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    )
{
    QUIC_DBG_ASSERT(!(InAddr == OutAddr));

    QuicZeroMemory(OutAddr, sizeof(QUIC_ADDR));

    if (InAddr->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
        OutAddr->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
        OutAddr->Ipv6.sin6_port = InAddr->Ipv4.sin_port;
        memset(&(OutAddr->Ipv6.sin6_addr.s6_addr[10]), 0xff, 2);
        memcpy(&(OutAddr->Ipv6.sin6_addr.s6_addr[12]), &InAddr->Ipv4.sin_addr.s_addr, 4);
    } else {
        *OutAddr = *InAddr;
    }
}

void
QuicConvertFromMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    )
{
    QUIC_DBG_ASSERT(InAddr->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6);

    if (IN6_IS_ADDR_V4MAPPED(&InAddr->Ipv6.sin6_addr)) {
        QUIC_ADDR TmpAddrS;
		memset(&TmpAddrS, 0, sizeof(QUIC_ADDR));
        QUIC_ADDR* TmpAddr = &TmpAddrS;

        QuicZeroMemory(&TmpAddrS, sizeof(QUIC_ADDR));
        TmpAddr->Ipv4.sin_family = QUIC_ADDRESS_FAMILY_INET;
        TmpAddr->Ipv4.sin_port = InAddr->Ipv6.sin6_port;
        memcpy(&TmpAddr->Ipv4.sin_addr.s_addr, &InAddr->Ipv6.sin6_addr.s6_addr[12], 4);
        *OutAddr = *TmpAddr;
    } else if (OutAddr != InAddr) {
        *OutAddr = *InAddr;
    }
}

#ifdef DEBUG
void
QuicSetAllocFailDenominator(
    _In_ int32_t Value
    )
{
    Quicform.AllocFailDenominator = Value;
    Quicform.AllocCounter = 0;
}

int32_t
QuicGetAllocFailDenominator(
    )
{
    return Quicform.AllocFailDenominator;
}
#endif

#if defined(QUIC_PLATFORM_LINUX)



QUIC_STATUS
QuicThreadCreate(
    _In_ QUIC_THREAD_CONFIG* Config,
    _Out_ QUIC_THREAD* Thread
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    pthread_attr_t Attr;
    if (pthread_attr_init(&Attr)) {
        QuicTraceLogError(
            "LibraryErrorStatus: [lib] ERROR, %u, %s.",
            errno,
            "pthread_attr_init failed");
        return errno;
    }

#ifdef __GLIBC__
    if (Config->Flags & QUIC_THREAD_FLAG_SET_AFFINITIZE) {
        cpu_set_t CpuSet;
        CPU_ZERO(&CpuSet);
        CPU_SET(Config->IdealProcessor, &CpuSet);
        if (pthread_attr_setaffinity_np(&Attr, sizeof(CpuSet), &CpuSet)) {
            QuicTraceLogWarning(
                "LibraryError: [lib] ERROR, %s.Cpu id:%d",
                "pthread_attr_setaffinity_np failed", Config->IdealProcessor);
        }
    } else {
        // TODO - Set Linux equivalent of NUMA affinity.
    }
    // There is no way to set an ideal processor in Linux.
#endif

    if (Config->Flags & QUIC_THREAD_FLAG_HIGH_PRIORITY) {
        struct sched_param Params;
        Params.sched_priority = sched_get_priority_max(SCHED_FIFO);
        if (!pthread_attr_setschedparam(&Attr, &Params)) {
            QuicTraceLogWarning(
                "LibraryErrorStatus: [lib] ERROR, %u, %s.",
                errno,
                "pthread_attr_setschedparam failed");
        }
    }

#ifdef QUIC_USE_CUSTOM_THREAD_CONTEXT

    QUIC_THREAD_CUSTOM_CONTEXT* CustomContext =
        QUIC_ALLOC_NONPAGED(sizeof(QUIC_THREAD_CUSTOM_CONTEXT), QUIC_POOL_CUSTOM_THREAD);
    if (CustomContext == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceLogError(
            "Allocation of '%s' failed. (%u bytes)",
            "Custom thread context",
            sizeof(QUIC_THREAD_CUSTOM_CONTEXT));
    }
    CustomContext->Callback = Config->Callback;
    CustomContext->Context = Config->Context;

    if (pthread_create(Thread, &Attr, QuicThreadCustomStart, CustomContext)) {
        Status = errno;
        QuicTraceLogError(
            "[ lib] ERROR, %u, %s.",
            Status,
            "pthread_create failed");
        QUIC_FREE(CustomContext, QUIC_POOL_CUSTOM_THREAD);
    }

#else // QUIC_USE_CUSTOM_THREAD_CONTEXT

    if (pthread_create(Thread, &Attr, Config->Callback, Config->Context)) {
        Status = errno;
        QuicTraceLogWarning(
            "LibraryErrorStatus: [lib] ERROR, %u, %s.",
            Status,
            "pthread_create failed");
    }
#endif  // !QUIC_USE_CUSTOM_THREAD_CONTEXT


#if !defined(__GLIBC__) && !defined(__ANDROID__)
    if (Status == QUIC_STATUS_SUCCESS) {
        if (Config->Flags & QUIC_THREAD_FLAG_SET_AFFINITIZE) {
            cpu_set_t CpuSet;
            CPU_ZERO(&CpuSet);
            CPU_SET(Config->IdealProcessor, &CpuSet);
            if (!pthread_setaffinity_np(*Thread, sizeof(CpuSet), &CpuSet)) {
                QuicTraceLogWarning(
                    "LibraryError: [lib] ERROR, %s.",
                    "pthread_setaffinity_np failed");
            }
        } else {
            // TODO - Set Linux equivalent of NUMA affinity.
        }
    }
#endif

    pthread_attr_destroy(&Attr);

    return Status;
}

QUIC_STATUS
QuicSetCurrentThreadProcessorAffinity(
    _In_ uint16_t ProcessorIndex
    )
{
#ifndef __ANDROID__
    cpu_set_t CpuSet;
    pthread_t Thread = pthread_self();
    CPU_ZERO(&CpuSet);
    CPU_SET(ProcessorIndex, &CpuSet);

    if (!pthread_setaffinity_np(Thread, sizeof(CpuSet), &CpuSet)) {
        QuicTraceLogError(
            "[ lib] ERROR, %s.",
            "pthread_setaffinity_np failed");
    }

    return QUIC_STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(ProcessorIndex);
    return QUIC_STATUS_SUCCESS;
#endif
}


#elif defined(CX_PLATFORM_DARWIN)

QUIC_STATUS
QuicThreadCreate(
    _In_ QUIC_THREAD_CONFIG* Config,
    _Out_ QUIC_THREAD* Thread
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    pthread_attr_t Attr;
    if (pthread_attr_init(&Attr)) {
        QuicTraceLogError(
            "[ lib] ERROR, %u, %s.",
            errno,
            "pthread_attr_init failed");
        return errno;
    }
    // XXX: Set processor affinity
    if (Config->Flags & CXPLAT_THREAD_FLAG_HIGH_PRIORITY) {
        struct sched_param Params;
        Params.sched_priority = sched_get_priority_max(SCHED_FIFO);
        if (!pthread_attr_setschedparam(&Attr, &Params)) {
            QuicTraceLogError(
                "[ lib] ERROR, %u, %s.",
                errno,
                "pthread_attr_setschedparam failed");
        }
    }

    if (pthread_create(Thread, &Attr, Config->Callback, Config->Context)) {
        Status = errno;
        QuicTraceLogError(
            "[ lib] ERROR, %u, %s.",
            Status,
            "pthread_create failed");
    }

    pthread_attr_destroy(&Attr);

    return Status;
}    

QUIC_STATUS
QuicSetCurrentThreadProcessorAffinity(
    _In_ uint16_t ProcessorIndex
    )
{
    UNREFERENCED_PARAMETER(ProcessorIndex);
    return QUIC_STATUS_SUCCESS;
}

#endif //QUIC_PLATFORM

void
QuicThreadDelete(
    _Inout_ QUIC_THREAD* Thread
    )
{
    UNREFERENCED_PARAMETER(Thread);
}

void
QuicThreadWait(
    _Inout_ QUIC_THREAD* Thread
    )
{
    QUIC_DBG_ASSERT(pthread_equal(*Thread, pthread_self()) == 0);
    QUIC_FRE_ASSERT(pthread_join(*Thread, NULL) == 0);
}

uint32_t
QuicCurThreadID(
    void
    )
{
#if defined(QUIC_PLATFORM_LINUX)

    QUIC_STATIC_ASSERT(sizeof(pid_t) <= sizeof(QUIC_THREAD_ID), "PID size exceeds the expected size");
    return syscall(SYS_gettid);

#elif defined(QUIC_PLATFORM_DARWIN)
    // cppcheck-suppress duplicateExpression
    
    QUIC_STATIC_ASSERT(sizeof(uint32_t) == sizeof(QUIC_THREAD_ID), "The cast depends on thread id being 32 bits");
    uint64_t Tid;
    int Res = pthread_threadid_np(NULL, &Tid);
    UNREFERENCED_PARAMETER(Res);
    QUIC_DBG_ASSERT(Res == 0);
    QUIC_DBG_ASSERT(Tid <= UINT32_MAX);
    return (QUIC_THREAD_ID)Tid;

#endif // QUIC_PLATFORM_DARWIN
}

void
QuicPlatformLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
    )
{
    QuicTraceLogWarning(
        "LibraryAssert: [lib] ASSERT, %u:%s - %s.",
        (uint32_t)Line,
        File,
        Expr);
}
