/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    When a packet is sent, a QUIC_SENT_PACKET_METADATA is allocated from
    this module and filled with information about the packet. When the
    packet is later acknowledged or inferred lost, this metadata is used
    to determine what exactly was acknowledged or lost.

    The size of a QUIC_SENT_PACKET_METADATA depends on the number of frames
    contained in the packet. The allocator uses a different pool for each
    possible size.

--*/

#include "precomp.h"

void
QuicSentPacketMetadataReleaseFrames(
    _In_ QUIC_SENT_PACKET_METADATA* Metadata
    )
{
    for (uint8_t i = 0; i < Metadata->FrameCount; i++) {
        switch (Metadata->Frames[i].Type)
        {
#pragma warning(push)
#pragma warning(disable:6001)
        case QUIC_FRAME_RESET_STREAM:
            QuicStreamSentMetadataDecrement(Metadata->Frames[i].RESET_STREAM.Stream);
            break;
        case QUIC_FRAME_MAX_STREAM_DATA:
            QuicStreamSentMetadataDecrement(Metadata->Frames[i].MAX_STREAM_DATA.Stream);
            break;
        case QUIC_FRAME_STREAM_DATA_BLOCKED:
            QuicStreamSentMetadataDecrement(Metadata->Frames[i].STREAM_DATA_BLOCKED.Stream);
            break;
        case QUIC_FRAME_STOP_SENDING:
            QuicStreamSentMetadataDecrement(Metadata->Frames[i].STOP_SENDING.Stream);
            break;
        case QUIC_FRAME_STREAM:
            QuicStreamSentMetadataDecrement(Metadata->Frames[i].STREAM.Stream);
            break;
#pragma warning(pop)
        default:
            //
            // Nothing to clean up for other frame types.
            //
            break;
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSentPacketPoolInitialize(
    _Inout_ QUIC_SENT_PACKET_POOL* Pool
    )
{
    for (uint32_t i = 0; i < ARRAYSIZE(Pool->Pools); i++) {
        uint32_t PacketMetadataSize =
            (i + 1) * sizeof(QUIC_SENT_FRAME_METADATA) +
            sizeof(QUIC_SENT_PACKET_METADATA);

        QuicPoolInitialize(
            FALSE,  // IsPaged
            PacketMetadataSize,
            QUIC_POOL_META,
            Pool->Pools + i);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSentPacketPoolUninitialize(
    _In_ QUIC_SENT_PACKET_POOL* Pool
    )
{
    for (size_t i = 0; i < ARRAYSIZE(Pool->Pools); i++) {
        QuicPoolUninitialize(Pool->Pools + i);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_SENT_PACKET_METADATA*
QuicSentPacketPoolGetPacketMetadata(
    _In_ QUIC_SENT_PACKET_POOL* Pool,
    _In_ uint8_t FrameCount
    )
{
    QUIC_SENT_PACKET_METADATA* Metadata =
        QuicPoolAlloc(Pool->Pools + FrameCount - 1);
#if DEBUG
    if (Metadata != NULL) {
        Metadata->Flags.Freed = FALSE;
    }
#endif
    return Metadata;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSentPacketPoolReturnPacketMetadata(
    _In_ QUIC_SENT_PACKET_POOL* Pool,
    _In_ QUIC_SENT_PACKET_METADATA* Metadata
    )
{
    _Analysis_assume_(
        Metadata->FrameCount > 0 &&
        Metadata->FrameCount <= QUIC_MAX_FRAMES_PER_PACKET);

#if DEBUG
    Metadata->Flags.Freed = TRUE;
#endif

    QuicSentPacketMetadataReleaseFrames(Metadata);
    QuicPoolFree(Pool->Pools + Metadata->FrameCount - 1, Metadata);
}
