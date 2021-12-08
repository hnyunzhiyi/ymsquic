/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file defines the logic for version negotiation.

--*/

#include "precomp.h"

typedef struct QUIC_COMPATIBLE_VERSION_MAP {
    const uint32_t OriginalVersion;
    const uint32_t CompatibleVersion;
} QUIC_COMPATIBLE_VERSION_MAP;

const QUIC_COMPATIBLE_VERSION_MAP CompatibleVersionsMap[] = {
    {QUIC_VERSION_MS_1, QUIC_VERSION_1},
    {QUIC_VERSION_1, QUIC_VERSION_MS_1}
};

//
// This list is the versions the server advertises support for.
//
const uint32_t DefaultSupportedVersionsList[3] = {
    QUIC_VERSION_1,
    QUIC_VERSION_MS_1,
    QUIC_VERSION_DRAFT_29
};

BOOLEAN
QuicVersionNegotiationExtIsVersionServerSupported(
    _In_ uint32_t Version
    )
{
    if (MsQuicLib.Settings.IsSet.DesiredVersionsList) {
        if (QuicIsVersionReserved(Version)) {
            return FALSE;
        }
        for (uint32_t i = 0; i < MsQuicLib.Settings.DesiredVersionsListLength; ++i) {
            if (MsQuicLib.Settings.DesiredVersionsList[i] == Version) {
                return TRUE;
            }
        }
    } else {
        return QuicIsVersionSupported(Version);
    }
    return FALSE;
}

BOOLEAN
QuicVersionNegotiationExtIsVersionClientSupported(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Version
    )
{
    if (Connection->Settings.IsSet.DesiredVersionsList) {
        if (QuicIsVersionReserved(Version)) {
            return FALSE;
        }
        for (uint32_t i = 0; i < Connection->Settings.DesiredVersionsListLength; ++i) {
            if (Connection->Settings.DesiredVersionsList[i] == Version) {
                return TRUE;
            }
        }
    } else {
        return QuicIsVersionSupported(Version);
    }
    return FALSE;
}

BOOLEAN
QuicVersionNegotiationExtAreVersionsCompatible(
    _In_ uint32_t OriginalVersion,
    _In_ uint32_t UpgradedVersion
    )
{
    if (OriginalVersion == UpgradedVersion) {
        return TRUE;
    }
    for (unsigned i = 0; i < ARRAYSIZE(CompatibleVersionsMap); ++i) {
        if (CompatibleVersionsMap[i].OriginalVersion == OriginalVersion) {
            while (i < ARRAYSIZE(CompatibleVersionsMap) && CompatibleVersionsMap[i].OriginalVersion == OriginalVersion) {
                if (CompatibleVersionsMap[i].CompatibleVersion == UpgradedVersion) {
                    return TRUE;
                }
                ++i;
            }
            return FALSE;
        }
    }
    return FALSE;
}

BOOLEAN
QuicVersionNegotiationExtIsVersionCompatible(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t NegotiatedVersion
    )
{
    const uint32_t* CompatibleVersions;
    uint32_t CompatibleVersionsLength;
    if (Connection->Settings.IsSet.DesiredVersionsList) {
        CompatibleVersions = Connection->Settings.DesiredVersionsList;
        CompatibleVersionsLength = Connection->Settings.DesiredVersionsListLength;
    } else {
        CompatibleVersions = MsQuicLib.DefaultCompatibilityList;
        CompatibleVersionsLength = MsQuicLib.DefaultCompatibilityListLength;
    }

    for (uint32_t i = 0; i < CompatibleVersionsLength; ++i) {
        if (CompatibleVersions[i] == NegotiatedVersion) {
            return TRUE;
        }
    }

    return FALSE;
}

QUIC_STATUS
QuicVersionNegotiationExtGenerateCompatibleVersionsList(
    _In_ uint32_t OriginalVersion,
    _In_reads_bytes_(DesiredVersionsLength * sizeof(uint32_t))
        const uint32_t* const DesiredVersions,
    _In_ uint32_t DesiredVersionsLength,
    _Out_writes_bytes_(*BufferLength) uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength
    )
{
    uint32_t NeededBufferLength = sizeof(OriginalVersion);
    for (uint32_t i = 0; i < ARRAYSIZE(CompatibleVersionsMap); ++i) {
        if (CompatibleVersionsMap[i].OriginalVersion == OriginalVersion) {
            for (uint32_t j = 0; j < DesiredVersionsLength; ++j) {
                if (CompatibleVersionsMap[i].CompatibleVersion == DesiredVersions[j]) {
                    NeededBufferLength += sizeof(uint32_t);
                    break; // bail from the inner loop
                }
            }
        }
    }
    if (*BufferLength < NeededBufferLength) {
        *BufferLength = NeededBufferLength;
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }
    if (Buffer == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    uint32_t Offset = sizeof(uint32_t);
    QuicCopyMemory(Buffer, &OriginalVersion, sizeof(uint32_t));
    for (uint32_t i = 0; i < DesiredVersionsLength; ++i) {
        for (uint32_t j = 0; j < ARRAYSIZE(CompatibleVersionsMap); ++j) {
            if (CompatibleVersionsMap[j].OriginalVersion == OriginalVersion &&
                CompatibleVersionsMap[j].CompatibleVersion == DesiredVersions[i]) {
                QuicCopyMemory(
                    Buffer + Offset,
                    &CompatibleVersionsMap[j].CompatibleVersion,
                    sizeof(CompatibleVersionsMap[j].CompatibleVersion));
                Offset += sizeof(CompatibleVersionsMap[j].CompatibleVersion);
                break;
            }
        }
    }
    QUIC_DBG_ASSERT(Offset <= *BufferLength);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicVersionNegotiationExtParseVersionInfo(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _In_ uint16_t BufferLength,
    _Out_ QUIC_VERSION_INFORMATION_V1* VersionInfo
    )
{
    uint16_t Offset = 0;
    if (BufferLength < sizeof(uint32_t)) {
        QuicTraceLogConnError(
            "Version info too short to contain Chosen Version (%hu bytes)",
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    QuicCopyMemory(&VersionInfo->ChosenVersion, Buffer, sizeof(VersionInfo->ChosenVersion));
    Offset += sizeof(uint32_t);

    if ((unsigned)(BufferLength - Offset) < sizeof(uint32_t)) {
        QuicTraceLogConnError(
            "Version info too short to contain any Other Versions (%hu bytes)",
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if ((BufferLength - Offset) % sizeof(uint32_t) > 0) {
        QuicTraceLogConnError(
            "Version info contains partial Other Version (%hu bytes vs. %u bytes)",
            (unsigned)(BufferLength - Offset),
            (BufferLength - Offset) / (unsigned)sizeof(uint32_t));
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    VersionInfo->OtherVersionsCount = (BufferLength - Offset) / sizeof(uint32_t);
    VersionInfo->OtherVersions = (uint32_t*)(Buffer + Offset);
    Offset += (uint16_t)(VersionInfo->OtherVersionsCount * sizeof(uint32_t));

    if (Offset != BufferLength) {
        QuicTraceLogConnError(
            "Version info parsed less than full buffer (%hu bytes vs. %hu bytes",
            Offset,
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QuicTraceLogConnInfo(
        "VerInfo Decoded: Chosen Ver:%x Other Ver Count:%u",
        VersionInfo->ChosenVersion,
        VersionInfo->OtherVersionsCount);

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
__drv_allocatesMem(Mem)
_Must_inspect_result_
_Success_(return != NULL)
const uint8_t*
QuicVersionNegotiationExtEncodeVersionInfo(
    _In_ QUIC_CONNECTION* Connection,
    _Out_ uint32_t* VerInfoLength
    )
{
    uint32_t VILen = 0;
    uint8_t* VIBuf = NULL;
    uint8_t* VersionInfo = NULL;
    *VerInfoLength = 0;
    if (QuicConnIsServer(Connection)) {
        const uint32_t* DesiredVersionsList = NULL;
        uint32_t DesiredVersionsListLength = 0;
        if (MsQuicLib.Settings.IsSet.DesiredVersionsList) {
            DesiredVersionsList = MsQuicLib.Settings.DesiredVersionsList;
            DesiredVersionsListLength = MsQuicLib.Settings.DesiredVersionsListLength;
        } else {
            DesiredVersionsList = DefaultSupportedVersionsList;
            DesiredVersionsListLength = ARRAYSIZE(DefaultSupportedVersionsList);
        }
        //
        // Generate Server Version Info.
        //
        VILen = sizeof(uint32_t) + (DesiredVersionsListLength * sizeof(uint32_t));
        QUIC_DBG_ASSERT((DesiredVersionsListLength * sizeof(uint32_t)) + sizeof(uint32_t) > DesiredVersionsListLength + sizeof(uint32_t));

        VersionInfo = QUIC_ALLOC_NONPAGED(VILen);
        if (VersionInfo == NULL) {
            QuicTraceLogError(
                "Allocation of '%s' failed. (%u bytes)",
                "Server Version Info",
                VILen);
            return NULL;
        }
        VIBuf = VersionInfo;

        QUIC_DBG_ASSERT(VILen >= sizeof(uint32_t));
        QuicCopyMemory(VIBuf, &Connection->Stats.QuicVersion, sizeof(Connection->Stats.QuicVersion));
        VIBuf += sizeof(Connection->Stats.QuicVersion);
        QUIC_DBG_ASSERT(VILen - sizeof(uint32_t) == DesiredVersionsListLength * sizeof(uint32_t));
        QuicCopyMemory(
            VIBuf,
            DesiredVersionsList,
            DesiredVersionsListLength * sizeof(uint32_t));

        QuicTraceLogConnInfo(
            "Server VI Encoded: Chosen Ver:%x Other Ver Count:%u",
            Connection->Stats.QuicVersion,
            DesiredVersionsListLength);
    } else {
        //
        // Generate Client Version Info.
        //
        uint32_t CompatibilityListByteLength = 0;
        VILen = sizeof(Connection->Stats.QuicVersion);
        if (Connection->Settings.IsSet.DesiredVersionsList) {
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                Connection->Stats.QuicVersion,
                Connection->Settings.DesiredVersionsList,
                Connection->Settings.DesiredVersionsListLength,
                NULL, &CompatibilityListByteLength);
            VILen += CompatibilityListByteLength;
        } else {
            QUIC_DBG_ASSERT(MsQuicLib.DefaultCompatibilityListLength * (uint32_t)sizeof(uint32_t) > MsQuicLib.DefaultCompatibilityListLength);
            VILen +=
                MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t);
        }

        VersionInfo = QUIC_ALLOC_NONPAGED(VILen);
        if (VersionInfo == NULL) {
            QuicTraceLogError(
                "Allocation of '%s' failed. (%u bytes)",
                "Client Version Info",
                VILen);
            return NULL;
        }
        VIBuf = VersionInfo;

        QUIC_DBG_ASSERT(VILen >= sizeof(uint32_t));
        QuicCopyMemory(VIBuf, &Connection->Stats.QuicVersion, sizeof(Connection->Stats.QuicVersion));
        VIBuf += sizeof(Connection->Stats.QuicVersion);
        if (Connection->Settings.IsSet.DesiredVersionsList) {
            uint32_t RemainingBuffer = VILen - (uint32_t)(VIBuf - VersionInfo);
            QUIC_DBG_ASSERT(RemainingBuffer == CompatibilityListByteLength);
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                Connection->Stats.QuicVersion,
                Connection->Settings.DesiredVersionsList,
                Connection->Settings.DesiredVersionsListLength,
                VIBuf,
                &RemainingBuffer);
            QUIC_DBG_ASSERT(VILen == (uint32_t)(VIBuf - VersionInfo) + RemainingBuffer);
        } else {
            QUIC_DBG_ASSERT(VILen - sizeof(uint32_t) == MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t));
            QuicCopyMemory(
                VIBuf,
                MsQuicLib.DefaultCompatibilityList,
                MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t));
        }
        QuicTraceLogConnInfo(
            "Client VI Encoded: Current Ver:%x Prev Ver:%x Compat Ver Count:%u",
            Connection->Stats.QuicVersion,
            Connection->PreviousQuicVersion,
            CompatibilityListByteLength == 0 ?
                MsQuicLib.DefaultCompatibilityListLength :
                (uint32_t)(CompatibilityListByteLength / sizeof(uint32_t)));

        }
    *VerInfoLength = VILen;
    return VersionInfo;
}
