/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains linux platform implementation.

Environment:

    Linux user mode

--*/

#pragma once

#ifndef QUIC_PLATFORM_TYPE
#error "Must be included from quic_platform.h"
#endif

#ifndef QUIC_PLATFORM_LINUX
#error "Incorrectly including Linux Platform Header from non-Linux platfrom"
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdalign.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <msquic_linux.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <quic_sal_stub.h>

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef NDEBUG
#define DEBUG 1
#endif

#define ALIGN_DOWN(length, type) \
    ((unsigned long)(length) & ~(sizeof(type) - 1))

#define ALIGN_UP(length, type) \
    (ALIGN_DOWN(((unsigned long)(length) + sizeof(type) - 1), type))


void
QuicPlatformSystemLoad(
    void
    );

void
QuicPlatformSystemUnload(
    void
    );

QUIC_STATUS
QuicPlatformInitialize(
    void
    );

void
QuicPlatformUninitialize(
    void
    );

#define max(a,b) (((a) > (b)) ? (a) : (b))
#define min(a,b) (((a) < (b)) ? (a) : (b))


//
// Generic stuff.
//

#define INVALID_SOCKET ((int)(-1))
#define SOCKET_ERROR (-1)
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#define UNREFERENCED_PARAMETER(P) (void)(P)
#define QuicNetByteSwapShort(x) htons((x))
#define SIZEOF_STRUCT_MEMBER(StructType, StructMember) sizeof(((StructType *)0)->StructMember)
#define TYPEOF_STRUCT_MEMBER(StructType, StructMember) typeof(((StructType *)0)->StructMember)

#if defined(__GNUC__) && __GNUC__ >= 7
#define __fallthrough __attribute__((fallthrough))
#else
#define __fallthrough // fall through
#endif /* __GNUC__ >= 7 */

//
// Interlocked implementations.
//
#ifdef QUIC_PLATFORM_DARWIN
#define YieldProcessor()
#else
#define YieldProcessor() pthread_yield()
#endif


inline
long
InterlockedIncrement(
    _Inout_ _Interlocked_operand_ long volatile *Addend
    )
{
    return __sync_add_and_fetch(Addend, (long)1);
}

inline
long
InterlockedDecrement(
    _Inout_ _Interlocked_operand_ long volatile *Addend
    )
{
    return __sync_sub_and_fetch(Addend, (long)1);
}

inline
long
InterlockedAnd(
    _Inout_ _Interlocked_operand_ long volatile *Destination,
    _In_ long Value
    )
{
    return __sync_and_and_fetch(Destination, Value);
}

inline
long
InterlockedOr(
    _Inout_ _Interlocked_operand_ long volatile *Destination,
    _In_ long Value
    )
{
    return __sync_or_and_fetch(Destination, Value);
}

inline
int64_t
InterlockedExchangeAdd64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Addend,
    _In_ int64_t Value
    )
{
    return __sync_fetch_and_add(Addend, Value);
}

inline
short
InterlockedCompareExchange16(
    _Inout_ _Interlocked_operand_ short volatile *Destination,
    _In_ short ExChange,
    _In_ short Comperand
    )
{
    return __sync_val_compare_and_swap(Destination, Comperand, ExChange);
}

inline
short
InterlockedCompareExchange(
    _Inout_ _Interlocked_operand_ long volatile *Destination,
    _In_ long ExChange,
    _In_ long Comperand
    )
{
    return __sync_val_compare_and_swap(Destination, Comperand, ExChange);
}

inline
int64_t
InterlockedCompareExchange64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Destination,
    _In_ int64_t ExChange,
    _In_ int64_t Comperand
    )
{
    return __sync_val_compare_and_swap(Destination, Comperand, ExChange);
}


inline
short
InterlockedIncrement16(
    _Inout_ _Interlocked_operand_ short volatile *Addend
    )
{
    return __sync_add_and_fetch(Addend, (short)1);
}

inline
short
InterlockedDecrement16(
    _Inout_ _Interlocked_operand_ short volatile *Addend
    )
{
    return __sync_sub_and_fetch(Addend, (short)1);
}

inline
int64_t
InterlockedIncrement64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Addend
    )
{
    return __sync_add_and_fetch(Addend, (int64_t)1);
}

//
// Assertion interfaces.
//

__attribute__((noinline))
void
quic_bugcheck(
    void
    );

void
QuicPlatformLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
    );

#define QUIC_STATIC_ASSERT(X,Y) static_assert(X, Y);
#define QUIC_ANALYSIS_ASSERT(X)
#define QUIC_ANALYSIS_ASSUME(X)
#define QUIC_FRE_ASSERT(exp) ((exp) ? (void)0 : (QuicPlatformLogAssert(__FILE__, __LINE__, #exp), quic_bugcheck()));
#define QUIC_FRE_ASSERTMSG(exp, Y) QUIC_FRE_ASSERT(exp)

#ifdef DEBUG
#define QUIC_DBG_ASSERT(exp) QUIC_FRE_ASSERT(exp)
#define QUIC_DBG_ASSERTMSG(exp, msg) QUIC_FRE_ASSERT(exp)
#else 
#define QUIC_DBG_ASSERT(exp)
#define QUIC_DBG_ASSERTMSG(exp, msg)
#endif 

#if DEBUG || QUIC_TELEMETRY_ASSERTS
#define QUIC_TEL_ASSERT(exp) QUIC_FRE_ASSERT(exp)
#define QUIC_TEL_ASSERTMSG(exp, Y) QUIC_FRE_ASSERT(exp)
#define QUIC_TEL_ASSERTMSG_ARGS(exp, _msg, _origin, _bucketArg1, _bucketArg2) QUIC_FRE_ASSERT(exp)
#else
#define QUIC_TEL_ASSERT(exp)
#define QUIC_TEL_ASSERTMSG(exp, Y)
#define QUIC_TEL_ASSERTMSG_ARGS(exp, _msg, _origin, _bucketArg1, _bucketArg2)
#define QUIC_FRE_ASSERTMSG(exp, Y)
#endif

//
// Debugger check.
//

#define QuicDebuggerPresent() FALSE

//
// Interrupt ReQuest Level.
//

#define QUIC_IRQL() 0
#define QUIC_PASSIVE_CODE()

//
// Memory management interfaces.
//

extern uint64_t QuicTotalMemory;

_Ret_maybenull_
void*
QuicAlloc(
    _In_ size_t ByteCount
    );

void
QuicFree(
    __drv_freesMem(Mem) _Frees_ptr_opt_ void* Mem
    );

#define QUIC_ALLOC_PAGED(Size) QuicAlloc(Size)
#define QUIC_ALLOC_NONPAGED(Size) QuicAlloc(Size)
#define QUIC_FREE(Mem) QuicFree((void*)Mem)

#define QuicZeroMemory(Destination, Length) memset((Destination), 0, (Length))
#define QuicCopyMemory(Destination, Source, Length) memcpy((Destination), (Source), (Length))
#define QuicMoveMemory(Destination, Source, Length) memmove((Destination), (Source), (Length))
#define QuicSecureZeroMemory QuicZeroMemory // TODO - Something better?

#define QuicByteSwapUint16(value) __builtin_bswap16((unsigned short)(value))
#define QuicByteSwapUint32(value) __builtin_bswap32((value))
#define QuicByteSwapUint64(value) __builtin_bswap64((value))

//
// Represents a QUIC lock.
//

typedef struct QUIC_LOCK {

    alignas(16) pthread_mutex_t Mutex;

} QUIC_LOCK;

#define QuicLockInitialize(Lock) { \
    pthread_mutexattr_t Attr; \
    QUIC_FRE_ASSERT(pthread_mutexattr_init(&Attr) == 0); \
    QUIC_FRE_ASSERT(pthread_mutexattr_settype(&Attr, PTHREAD_MUTEX_RECURSIVE) == 0); \
    QUIC_FRE_ASSERT(pthread_mutex_init(&(Lock)->Mutex, &Attr) == 0); \
    QUIC_FRE_ASSERT(pthread_mutexattr_destroy(&Attr) == 0); \
}

#define QuicLockUninitialize(Lock) \
        QUIC_FRE_ASSERT(pthread_mutex_destroy(&(Lock)->Mutex) == 0);

#define QuicLockAcquire(Lock) \
    QUIC_FRE_ASSERT(pthread_mutex_lock(&(Lock)->Mutex) == 0);

#define QuicLockRelease(Lock) \
    QUIC_FRE_ASSERT(pthread_mutex_unlock(&(Lock)->Mutex) == 0);

typedef QUIC_LOCK QUIC_DISPATCH_LOCK;

#define QuicDispatchLockInitialize QuicLockInitialize

#define QuicDispatchLockUninitialize QuicLockUninitialize

#define QuicDispatchLockAcquire QuicLockAcquire

#define QuicDispatchLockRelease QuicLockRelease

//
// Represents a QUIC RW lock.
//

typedef struct QUIC_RW_LOCK {

    pthread_rwlock_t RwLock;

} QUIC_RW_LOCK;

#define QuicRwLockInitialize(Lock) \
    QUIC_FRE_ASSERT(pthread_rwlock_init(&(Lock)->RwLock, NULL) == 0);

#define QuicRwLockUninitialize(Lock) \
    QUIC_FRE_ASSERT(pthread_rwlock_destroy(&(Lock)->RwLock) == 0);

#define QuicRwLockAcquireShared(Lock) \
    QUIC_FRE_ASSERT(pthread_rwlock_rdlock(&(Lock)->RwLock) == 0);

#define QuicRwLockAcquireExclusive(Lock) \
    QUIC_FRE_ASSERT(pthread_rwlock_wrlock(&(Lock)->RwLock) == 0);

#define QuicRwLockReleaseShared(Lock) \
    QUIC_FRE_ASSERT(pthread_rwlock_unlock(&(Lock)->RwLock) == 0);

#define QuicRwLockReleaseExclusive(Lock) \
    QUIC_FRE_ASSERT(pthread_rwlock_unlock(&(Lock)->RwLock) == 0);

typedef QUIC_RW_LOCK QUIC_DISPATCH_RW_LOCK;

#define QuicDispatchRwLockInitialize QuicRwLockInitialize

#define QuicDispatchRwLockUninitialize QuicRwLockUninitialize

#define QuicDispatchRwLockAcquireShared QuicRwLockAcquireShared

#define QuicDispatchRwLockAcquireExclusive QuicRwLockAcquireExclusive

#define QuicDispatchRwLockReleaseShared QuicRwLockReleaseShared

#define QuicDispatchRwLockReleaseExclusive QuicRwLockReleaseExclusive

//
// Represents a QUIC memory pool used for fixed sized allocations.
// This must be below the lock definitions.
//


FORCEINLINE
void
QuicListPushEntry(
    _Inout_ QUIC_SLIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem QUIC_SLIST_ENTRY* Entry
    );

FORCEINLINE
QUIC_SLIST_ENTRY*
QuicListPopEntry(
    _Inout_ QUIC_SLIST_ENTRY* ListHead
    );

typedef struct QUIC_POOL {

    //
    //List of free entries.
    //     
	QUIC_SLIST_ENTRY ListHead;

    //
    //Number of free entries in the list.
    //       
	uint16_t ListDepth;

    //
    //Lock to synchronize access to the List.
    //LINUX_TODO: Check how to make this lock free?
    //          
    QUIC_LOCK Lock;

    //
    //Size of entries.
    //        
    uint32_t Size;

    //
    //The memory tag to use for any allocation from this pool.
    //      
    uint32_t Tag;

} QUIC_POOL;

#define QUIC_POOL_MAXIMUM_DEPTH   256 // Copied from EX_MAXIMUM_LOOKASIDE_DEPTH_BASE

#if DEBUG
typedef struct QUIC_POOL_ENTRY {
    QUIC_SLIST_ENTRY ListHead;
    uint32_t SpecialFlag;
} QUIC_POOL_ENTRY;
#define QUIC_POOL_SPECIAL_FLAG    0xAAAAAAAA

int32_t
QuicGetAllocFailDenominator(
    );
#endif


inline
void
QuicPoolInitialize(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ QUIC_POOL* Pool
    )
{
#if DEBUG
    QUIC_DBG_ASSERT(Size >= sizeof(QUIC_POOL_ENTRY));
#endif
    Pool->Size = Size;
    Pool->Tag = Tag;
    QuicLockInitialize(&Pool->Lock);
    Pool->ListDepth = 0;
    QuicZeroMemory(&Pool->ListHead, sizeof(Pool->ListHead));
    UNREFERENCED_PARAMETER(IsPaged);
}

inline
void
QuicPoolUninitialize(
    _Inout_ QUIC_POOL* Pool
    )
{
    void* Entry;
    QuicLockAcquire(&Pool->Lock);
    while ((Entry = QuicListPopEntry(&Pool->ListHead)) != NULL) {
        QUIC_FRE_ASSERT(Pool->ListDepth > 0);
        Pool->ListDepth--;
        QuicLockRelease(&Pool->Lock);
        QuicFree(Entry);
        QuicLockAcquire(&Pool->Lock);
    }
    QuicLockRelease(&Pool->Lock);
    QuicLockUninitialize(&Pool->Lock);
}

inline
void*
QuicPoolAlloc(
    _Inout_ QUIC_POOL* Pool
    )
{
#if DEBUG
    if (QuicGetAllocFailDenominator()) {
        return QuicAlloc(Pool->Size);
    }
#endif
    QuicLockAcquire(&Pool->Lock);
    void* Entry = QuicListPopEntry(&Pool->ListHead);
    if (Entry != NULL) {
        QUIC_FRE_ASSERT(Pool->ListDepth > 0);
        Pool->ListDepth--;
    }
    QuicLockRelease(&Pool->Lock);
    if (Entry == NULL) {
        Entry = QuicAlloc(Pool->Size);
    }
#if DEBUG
    if (Entry != NULL) {
        ((QUIC_POOL_ENTRY*)Entry)->SpecialFlag = 0;
    }
#endif
    return Entry;
}

inline
void
QuicPoolFree(
    _Inout_ QUIC_POOL* Pool,
    _In_ void* Entry
    )
{
#if DEBUG
    if (QuicGetAllocFailDenominator()) {
        QuicFree(Entry);
        return;
    }
    QUIC_DBG_ASSERT(((QUIC_POOL_ENTRY*)Entry)->SpecialFlag != QUIC_POOL_SPECIAL_FLAG);
    ((QUIC_POOL_ENTRY*)Entry)->SpecialFlag = QUIC_POOL_SPECIAL_FLAG;
#endif
    if (Pool->ListDepth >= QUIC_POOL_MAXIMUM_DEPTH) {
        QuicFree(Entry);
    } else {
        QuicLockAcquire(&Pool->Lock);
        QuicListPushEntry(&Pool->ListHead, (QUIC_SLIST_ENTRY*)Entry);
        Pool->ListDepth++;
        QuicLockRelease(&Pool->Lock);
    }
}

//
// Reference Count Interface
//

typedef int64_t QUIC_REF_COUNT;

void
QuicRefInitialize(
    _Inout_ QUIC_REF_COUNT* RefCount
    );

void
QuicRefIncrement(
    _Inout_ QUIC_REF_COUNT* RefCount
    );

BOOLEAN
QuicRefIncrementNonZero(
    _Inout_ volatile QUIC_REF_COUNT* RefCount
    );

BOOLEAN
QuicRefDecrement(
    _In_ QUIC_REF_COUNT* RefCount
    );

#define QuicRefUninitialize(RefCount)
//
// Time Measurement Interfaces
//
#define QUIC_NANOSEC_PER_MS       (1000000)
#define QUIC_NANOSEC_PER_MICROSEC (1000)
#define QUIC_NANOSEC_PER_SEC      (1000000000)
#define QUIC_MICROSEC_PER_MS      (1000)
#define QUIC_MICROSEC_PER_SEC     (1000000)
#define QUIC_MS_PER_SECOND        (1000)

uint64_t
QuicGetTimerResolution(
    void
    );

uint64_t
QuicTimeUs64(
    void
    );

void
QuicGetAbsoluteTime(
    _In_ unsigned long DeltaMs,
    _Out_ struct timespec *Time
    );

#define QuicTimeUs32() (uint32_t)QuicTimeUs64()
#define QuicTimeMs64()  (QuicTimeUs64() / QUIC_MICROSEC_PER_MS)
#define QuicTimeMs32() (uint32_t)QuicTimeMs64()
#define QuicTimeUs64ToPlat(x) (x)

inline
int64_t
QuicTimeEpochMs64(
    void
    )
{
    struct timeval tv;
	QuicZeroMemory(&tv, sizeof(tv));
    gettimeofday(&tv, NULL);
    return S_TO_MS(tv.tv_sec) + US_TO_MS(tv.tv_usec);
}

inline
uint64_t
QuicTimeDiff64(
    _In_ uint64_t T1,
    _In_ uint64_t T2
    )
{
    //
    // Assume no wrap around.
    //

    return T2 - T1;
}

inline
uint32_t
QUIC_NO_SANITIZE("unsigned-integer-overflow")
QuicTimeDiff32(
    _In_ uint32_t T1,     // First time measured
    _In_ uint32_t T2      // Second time measured
    )
{
    if (T2 > T1) {
        return T2 - T1;
    } else { // Wrap around case.
        return T2 + (0xFFFFFFFF - T1) + 1;
    }
}

inline
BOOLEAN
QuicTimeAtOrBefore64(
    _In_ uint64_t T1,
    _In_ uint64_t T2
    )
{
    //
    // Assume no wrap around.
    //

    return T1 <= T2;
}

inline
BOOLEAN
QUIC_NO_SANITIZE("unsigned-integer-overflow")
QuicTimeAtOrBefore32(
    _In_ uint32_t T1,
    _In_ uint32_t T2
    )
{
    return (int32_t)(T1 - T2) <= 0;
}

void
QuicSleep(
    _In_ uint32_t DurationMs
    );

//
// Event Interfaces
//

//
// QUIC event object.
//

typedef struct QUIC_EVENT {
    //
    //Mutex and condition. The alignas is important, as the perf tanks
    //if the event is not aligned.
    //      
    alignas(16) pthread_mutex_t Mutex;
    pthread_cond_t Cond;

    //
    //Denotes if the event object is in signaled state.
    //       
    BOOLEAN Signaled;

    //
    //Denotes if the event object should be auto reset after it's signaled.
    //        
    BOOLEAN AutoReset;

} QUIC_EVENT;


inline
void
QuicEventInitialize(
    _Out_ QUIC_EVENT* Event,
    _In_ BOOLEAN ManualReset,
    _In_ BOOLEAN InitialState
    )
{
    pthread_condattr_t Attr;
    int Result;

    QuicZeroMemory(&Attr, sizeof(Attr));
    Event->AutoReset = !ManualReset;
    Event->Signaled = InitialState;

    Result = pthread_mutex_init(&Event->Mutex, NULL);
    QUIC_FRE_ASSERT(Result == 0);
    Result = pthread_condattr_init(&Attr);
    QUIC_FRE_ASSERT(Result == 0);
#if defined(QUIC_PLATFORM_LINUX)
    Result = pthread_condattr_setclock(&Attr, CLOCK_MONOTONIC);
    QUIC_FRE_ASSERT(Result == 0);
#endif // QUIC_PLATFORM_LINUX
    Result = pthread_cond_init(&Event->Cond, &Attr);
    QUIC_FRE_ASSERT(Result == 0);
    Result = pthread_condattr_destroy(&Attr);
    QUIC_FRE_ASSERT(Result == 0);
}


inline
void
QuicInternalEventUninitialize(
    _Inout_ QUIC_EVENT* Event
    )
{
    int Result;

    Result = pthread_cond_destroy(&Event->Cond);
    QUIC_FRE_ASSERT(Result == 0);
    Result = pthread_mutex_destroy(&Event->Mutex);
    QUIC_FRE_ASSERT(Result == 0);
}

inline
void
QuicInternalEventSet(
    _Inout_ QUIC_EVENT* Event
    )
{
    int Result;

    Result = pthread_mutex_lock(&Event->Mutex);
    QUIC_FRE_ASSERT(Result == 0);

    Event->Signaled = true;
    //
    //Signal the condition while holding the lock for predictable scheduling,
    //better performance and removing possibility of use after free for the
    //condition.
    //               
    Result = pthread_cond_broadcast(&Event->Cond);
    QUIC_FRE_ASSERT(Result == 0);

    Result = pthread_mutex_unlock(&Event->Mutex);
    QUIC_FRE_ASSERT(Result == 0);
}

inline
void
QuicInternalEventReset(
    _Inout_ QUIC_EVENT* Event
    )
{
    int Result;

    Result = pthread_mutex_lock(&Event->Mutex);
    QUIC_FRE_ASSERT(Result == 0);
    Event->Signaled = false;
    Result = pthread_mutex_unlock(&Event->Mutex);
    QUIC_FRE_ASSERT(Result == 0);
}

inline
void
QuicInternalEventWaitForever(
    _Inout_ QUIC_EVENT* Event
    )
{
    int Result;

    Result = pthread_mutex_lock(&Event->Mutex);
    QUIC_FRE_ASSERT(Result == 0);
    //
    //Spurious wake ups from pthread_cond_wait can occur. So the function needs
    //to be called in a loop until the predicate 'Signalled' is satisfied.
    //         
    while (!Event->Signaled) {
        Result = pthread_cond_wait(&Event->Cond, &Event->Mutex);
        QUIC_FRE_ASSERT(Result == 0);
    }

    if(Event->AutoReset) {
        Event->Signaled = false;
    }

    Result = pthread_mutex_unlock(&Event->Mutex);
    QUIC_FRE_ASSERT(Result == 0);
}

inline
BOOLEAN
QuicInternalEventWaitWithTimeout(
    _Inout_ QUIC_EVENT* Event,
    _In_ uint32_t TimeoutMs
    )
{
    BOOLEAN WaitSatisfied = FALSE;
    struct timespec Ts = {0, 0};
    int Result;

    //
    //Get absolute time.
    //        
    QuicGetAbsoluteTime(TimeoutMs, &Ts);

    Result = pthread_mutex_lock(&Event->Mutex);
    QUIC_FRE_ASSERT(Result == 0);

    while (!Event->Signaled) {

        Result = pthread_cond_timedwait(&Event->Cond, &Event->Mutex, &Ts);

        if (Result == ETIMEDOUT) {
            WaitSatisfied = FALSE;
            goto Exit;
        }

        QUIC_DBG_ASSERT(Result == 0);
        UNREFERENCED_PARAMETER(Result);
    }

    if (Event->AutoReset) {
        Event->Signaled = FALSE;
    }

    WaitSatisfied = TRUE;

Exit:

    Result = pthread_mutex_unlock(&Event->Mutex);
    QUIC_FRE_ASSERT(Result == 0);

    return WaitSatisfied;
}

#define QuicEventUninitialize(Event) QuicInternalEventUninitialize(&Event)
#define QuicEventSet(Event) QuicInternalEventSet(&Event)
#define QuicEventReset(Event) QuicInternalEventReset(&Event)
#define QuicEventWaitForever(Event) QuicInternalEventWaitForever(&Event)
#define QuicEventWaitWithTimeout(Event, TimeoutMs) QuicInternalEventWaitWithTimeout(&Event, TimeoutMs)

//
// Thread Interfaces.
//

//
// QUIC thread object.
//
typedef pthread_t QUIC_THREAD;

#define QUIC_THREAD_CALLBACK(FuncName, CtxVarName) \
    void* \
    FuncName( \
        void* CtxVarName \
        )

#define QUIC_THREAD_RETURN(Status) return NULL;

typedef void* (* LPTHREAD_START_ROUTINE)(void *);

typedef struct QUIC_THREAD_CONFIG {
    uint16_t Flags;
    uint16_t IdealProcessor;
    _Field_z_ const char* Name;
    LPTHREAD_START_ROUTINE Callback;
    void* Context;
} QUIC_THREAD_CONFIG;

#ifdef QUIC_USE_CUSTOM_THREAD_CONTEXT

//
// Extension point that allows additional platform specific logic to be executed
// for every thread created. The platform must define CXPLAT_USE_CUSTOM_THREAD_CONTEXT
// and implement the CxPlatThreadCustomStart function. CxPlatThreadCustomStart MUST
// call the Callback passed in. CxPlatThreadCustomStart MUST also free
// CustomContext (via CXPLAT_FREE(CustomContext, QUIC_POOL_CUSTOM_THREAD)) before
// returning.
//

typedef struct QUIC_THREAD_CUSTOM_CONTEXT {
    LPTHREAD_START_ROUTINE Callback;
    void* Context;
} QUIC_THREAD_CUSTOM_CONTEXT;

QUIC_THREAD_CALLBACK(QuicThreadCustomStart, CustomContext); // QUIC_THREAD_CUSTOM_CONTEXT* CustomContext

#endif // QUIC_USE_CUSTOM_THREAD_CONTEXT

QUIC_STATUS
QuicThreadCreate(
    _In_ QUIC_THREAD_CONFIG* Config,
    _Out_ QUIC_THREAD* Thread
    );

void
QuicThreadDelete(
    _Inout_ QUIC_THREAD* Thread
    );

void
QuicThreadWait(
    _Inout_ QUIC_THREAD* Thread
    );

typedef uint32_t QUIC_THREAD_ID;

QUIC_THREAD_ID
QuicCurThreadID(
    void
    );

//
// Processor Count and Index.
//

extern uint32_t QuicProcessorCount;

#define QuicProcMaxCount() QuicProcessorCount
#define QuicProcActiveCount() QuicProcessorCount

uint32_t
QuicProcCurrentNumber(
    void
    );


//
// Rundown Protection Interfaces.
//

typedef struct QUIC_RUNDOWN_REF {

    //
    //The completion event.
    //       
    QUIC_EVENT RundownComplete;
    //
    //The ref counter.
    //        
    QUIC_REF_COUNT RefCount;

} QUIC_RUNDOWN_REF;

void
QuicRundownInitialize(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

void
QuicRundownInitializeDisabled(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

void
QuicRundownReInitialize(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

void
QuicRundownUninitialize(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

BOOLEAN
QuicRundownAcquire(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

void
QuicRundownRelease(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

void
QuicRundownReleaseAndWait(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

//
// Crypto Interfaces
//
QUIC_STATUS
QuicRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    );

//
// Tracing stuff.
//
void
QuicConvertToMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    );

void
QuicConvertFromMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    );

QUIC_STATUS
QuicSetCurrentThreadProcessorAffinity(
    _In_ uint16_t ProcessorIndex
    );

#define QuicSetCurrentThreadGroupAffinity(ProcessorGroup) QUIC_STATUS_SUCCESS

#define QUIC_CPUID(FunctionId, eax, ebx, ecx, dx)

#if defined(__cplusplus)
}
#endif

