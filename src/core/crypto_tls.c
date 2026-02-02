/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains all logic for processing TLS specific data structures.
    This includes the logic to decode the ALPN list and SNI from the Client
    Hello, on server, and the logic to read and write the QUIC transport
    parameter extension.

--*/

#include "precomp.h"


#define TLS1_PROTOCOL_VERSION 0x0301
#define TLS_MESSAGE_HEADER_LENGTH 4
#define TLS_RANDOM_LENGTH 32
#define TLS_SESSION_ID_LENGTH 32

typedef enum eTlsHandshakeType {
    TlsHandshake_ClientHello = 0x01
} eTlsHandshakeType;

typedef enum eTlsExtensions {
    TlsExt_ServerName               = 0x00,
    TlsExt_AppProtocolNegotiation   = 0x10,
    TlsExt_SessionTicket            = 0x23,
} eTlsExtensions;

typedef enum eSniNameType {
    TlsExt_Sni_NameType_HostName = 0
} eSniNameType;

//
// Core Transport Parameters
//
#define QUIC_TP_ID_ORIGINAL_DESTINATION_CONNECTION_ID       0   // uint8_t[]
#define QUIC_TP_ID_IDLE_TIMEOUT                             1   // varint
#define QUIC_TP_ID_STATELESS_RESET_TOKEN                    2   // uint8_t[16]
#define QUIC_TP_ID_MAX_UDP_PAYLOAD_SIZE                     3   // varint
#define QUIC_TP_ID_INITIAL_MAX_DATA                         4   // varint
#define QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL       5   // varint
#define QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE      6   // varint
#define QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_UNI              7   // varint
#define QUIC_TP_ID_INITIAL_MAX_STREAMS_BIDI                 8   // varint
#define QUIC_TP_ID_INITIAL_MAX_STREAMS_UNI                  9   // varint
#define QUIC_TP_ID_ACK_DELAY_EXPONENT                       10  // varint
#define QUIC_TP_ID_MAX_ACK_DELAY                            11  // varint
#define QUIC_TP_ID_DISABLE_ACTIVE_MIGRATION                 12  // N/A
#define QUIC_TP_ID_PREFERRED_ADDRESS                        13  // PreferredAddress
#define QUIC_TP_ID_ACTIVE_CONNECTION_ID_LIMIT               14  // varint
#define QUIC_TP_ID_INITIAL_SOURCE_CONNECTION_ID             15  // uint8_t[]
#define QUIC_TP_ID_RETRY_SOURCE_CONNECTION_ID               16  // uint8_t[]

//
// Extensions
//
#define QUIC_TP_ID_MAX_DATAGRAM_FRAME_SIZE                  32              // varint
#define QUIC_TP_ID_DISABLE_1RTT_ENCRYPTION                  0xBAAD          // N/A
#define QUIC_TP_ID_VERSION_NEGOTIATION_EXT                  0x11            // Blob
#define QUIC_TP_ID_MIN_ACK_DELAY                            0xFF04DE1BULL   // varint
#define QUIC_TP_ID_CIBIR_ENCODING                           0x1000          // {varint, varint}
#define QUIC_TP_ID_GREASE_QUIC_BIT                          0x2AB2          // N/A
#define QUIC_TP_ID_RELIABLE_RESET_ENABLED                   0x17f7586d2cb570   // varint
#define QUIC_TP_ID_ENABLE_TIMESTAMP                         0x7158          // varint

BOOLEAN
QuicTpIdIsReserved(
    _In_ QUIC_VAR_INT ID
    )
{
    //
    // Per spec: Transport parameters with an identifier of the form "31 * N + 27"
    // for integer values of N are reserved to exercise the requirement that
    // unknown transport parameters be ignored.
    //
    return (ID % 31ULL) == 27ULL;
}

static
uint16_t
TlsReadUint16(
    _In_reads_(2) const uint8_t* Buffer
    )
{
    return
        (((uint32_t)Buffer[0] << 8) +
          (uint32_t)Buffer[1]);
}

static
uint32_t
TlsReadUint24(
    _In_reads_(3) const uint8_t* Buffer
    )
{
    return
        (((uint32_t)Buffer[0] << 16) +
         ((uint32_t)Buffer[1] << 8) +
          (uint32_t)Buffer[2]);
}

//
// The following functions encode data in the QUIC TP format. This format
// consists of a var-int for the 'ID', a var-int for the 'Length', and then
// 'Length' bytes of data.
//

#define TlsTransportParamLength(Id, Length) \
    (QuicVarIntSize(Id) + QuicVarIntSize(Length) + (Length))

static
uint8_t*
TlsWriteTransportParam(
    _In_ QUIC_VAR_INT Id,
    _In_range_(0, QUIC_VAR_INT_MAX) uint16_t Length,
    _In_reads_bytes_opt_(Length) const uint8_t* Param,
    _Out_writes_bytes_(_Inexpressible_("Too Dynamic"))
        uint8_t* Buffer
    )
{
    Buffer = QuicVarIntEncode(Id, Buffer);
    Buffer = QuicVarIntEncode(Length, Buffer);
    CXPLAT_DBG_ASSERT(Param != NULL || Length == 0);
    if (Param) {
        CxPlatCopyMemory(Buffer, Param, Length);
        Buffer += Length;
    }
    return Buffer;
}

static
uint8_t*
TlsWriteTransportParamVarInt(
    _In_ QUIC_VAR_INT Id,
    _In_ QUIC_VAR_INT Value,
    _Out_writes_bytes_(_Inexpressible_("Too Dynamic"))
        uint8_t* Buffer
    )
{
    uint8_t Length = QuicVarIntSize(Value);
    Buffer = QuicVarIntEncode(Id, Buffer);
    Buffer = QuicVarIntEncode(Length, Buffer);
    Buffer = QuicVarIntEncode(Value, Buffer);
    return Buffer;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadSniExtension(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint16_t BufferLength,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    UNREFERENCED_PARAMETER(Connection);
    /*
      struct {
          NameType name_type;
          select (name_type) {
              case host_name: HostName;
          } name;
      } ServerName;

      enum {
          host_name(0), (255)
      } NameType;

      opaque HostName<1..2^16-1>;

      struct {
          ServerName server_name_list<1..2^16-1>
      } ServerNameList;
    */

    if (BufferLength < sizeof(uint16_t)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    //
    // We need at least 3 bytes to encode NameType(1) and empty HostName(2)
    //
    if (TlsReadUint16(Buffer) < 3) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint16_t);
    Buffer += sizeof(uint16_t);

    //
    // Loop through the contents of the extension to ensure it is properly
    // formatted, even though we will only return the first entry.
    //
    BOOLEAN Found = FALSE;
    while (BufferLength > 0) {

        uint8_t NameType = Buffer[0];
        BufferLength--;
        Buffer++;

        if (BufferLength < sizeof(uint16_t)) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        uint16_t NameLen = TlsReadUint16(Buffer);
        BufferLength -= 2;
        Buffer += 2;
        if (BufferLength < NameLen) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        //
        // Pick only the first name in the list of names
        //
        if (NameType == TlsExt_Sni_NameType_HostName && !Found) {
            Info->ServerName = (const char*)Buffer;
            Info->ServerNameLength = NameLen;
            Found = TRUE;
        }

        BufferLength -= NameLen;
        Buffer += NameLen;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadAlpnExtension(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint16_t BufferLength,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    /*
       enum {
           application_layer_protocol_negotiation(16), (65535)
       } ExtensionType;

       opaque ProtocolName<1..2^8-1>;

       struct {
           ProtocolName protocol_name_list<2..2^16-1>
       } ProtocolNameList;
    */

    (void)Connection;
    //
    // The client-side ALPN extension contains a protocol ID list with at least
    // one protocol ID 1 to 255 bytes long, plus 1 byte of protocol ID size, plus
    // 2 bytes for protocol ID list size.
    //
    if (BufferLength < sizeof(uint16_t) + 2 * sizeof(uint8_t)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (BufferLength != TlsReadUint16(Buffer) + sizeof(uint16_t)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint16_t);
    Buffer += sizeof(uint16_t);

    Info->ClientAlpnList = Buffer;
    Info->ClientAlpnListLength = BufferLength;

    //
    // Loop through the contents of the extension to ensure it is properly
    // formatted, even though we will return the whole extension.
    //
    while (BufferLength > 0) {
        uint16_t Len = Buffer[0];
        BufferLength--;
        Buffer++;

        if (BufferLength < 1 ||
            BufferLength < Len) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        BufferLength -= Len;
        Buffer += Len;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadExtensions(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint16_t BufferLength,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    /*
      enum {
          server_name(0), max_fragment_length(1),
          client_certificate_url(2), trusted_ca_keys(3),
          truncated_hmac(4), status_request(5), (65535)
      } ExtensionType;

      struct {
          ExtensionType extension_type;
          opaque extension_data<0..2^16-1>;
      } Extension;
    */

    BOOLEAN FoundSNI = FALSE;
    BOOLEAN FoundALPN = FALSE;
    BOOLEAN FoundTransportParameters = FALSE;
    while (BufferLength) {
        //
        // Each extension will have atleast 4 bytes of data. 2 to label
        // the extension type and 2 for the length.
        //
        if (BufferLength < 2 * sizeof(uint16_t)) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        uint16_t ExtType = TlsReadUint16(Buffer);
        uint16_t ExtLen = TlsReadUint16(Buffer + sizeof(uint16_t));
        BufferLength -= 2 * sizeof(uint16_t);
        Buffer += 2 * sizeof(uint16_t);
        if (BufferLength < ExtLen) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        if (ExtType == TlsExt_ServerName) {
            if (FoundSNI) {
                return QUIC_STATUS_INVALID_PARAMETER;
            }
            QUIC_STATUS Status =
                QuicCryptoTlsReadSniExtension(
                    Connection, Buffer, ExtLen, Info);
            if (QUIC_FAILED(Status)) {
                return Status;
            }
            FoundSNI = TRUE;

        } else if (ExtType == TlsExt_AppProtocolNegotiation) {
            if (FoundALPN) {
                return QUIC_STATUS_INVALID_PARAMETER;
            }
            QUIC_STATUS Status =
                QuicCryptoTlsReadAlpnExtension(
                    Connection, Buffer, ExtLen, Info);
            if (QUIC_FAILED(Status)) {
                return Status;
            }
            FoundALPN = TRUE;

        } else if (Connection->Stats.QuicVersion != QUIC_VERSION_DRAFT_29) {
            if (ExtType == TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS) {
                if (FoundTransportParameters) {
                    return QUIC_STATUS_INVALID_PARAMETER;
                }
                if (!QuicCryptoTlsDecodeTransportParameters(
                        Connection,
                        FALSE,
                        Buffer,
                        ExtLen,
                        &Connection->PeerTransportParams)) {
                    return QUIC_STATUS_INVALID_PARAMETER;
                }
                FoundTransportParameters = TRUE;
            }

        } else {
            if (ExtType == TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS_DRAFT) {
                if (FoundTransportParameters) {
                    return QUIC_STATUS_INVALID_PARAMETER;
                }
                if (!QuicCryptoTlsDecodeTransportParameters(
                        Connection,
                        FALSE,
                        Buffer,
                        ExtLen,
                        &Connection->PeerTransportParams)) {
                    return QUIC_STATUS_INVALID_PARAMETER;
                }
                FoundTransportParameters = TRUE;
            }
        }

        BufferLength -= ExtLen;
        Buffer += ExtLen;
    }

    if (!FoundTransportParameters) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadClientHello(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint32_t BufferLength,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    /*
      struct {
          ProtocolVersion client_version;
          Random random;
          SessionID session_id;
          CipherSuite cipher_suites<2..2^16-2>;
          CompressionMethod compression_methods<1..2^8-1>;
          select (extensions_present) {
              case false:
                  struct {};
              case true:
                  Extension extensions<0..2^16-1>;
          };
      } ClientHello;
    */

    //
    // Version
    //
    if (BufferLength < sizeof(uint16_t) ||
        TlsReadUint16(Buffer) < TLS1_PROTOCOL_VERSION) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint16_t);
    Buffer += sizeof(uint16_t);

    //
    // Random
    //
    if (BufferLength < TLS_RANDOM_LENGTH) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= TLS_RANDOM_LENGTH;
    Buffer += TLS_RANDOM_LENGTH;

    //
    // SessionID
    //
    if (BufferLength < sizeof(uint8_t) ||
        Buffer[0] > TLS_SESSION_ID_LENGTH ||
        BufferLength < sizeof(uint8_t) + Buffer[0]) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint8_t) + Buffer[0];
    Buffer += sizeof(uint8_t) + Buffer[0];

    //
    // CipherSuite
    //
    if (BufferLength < sizeof(uint16_t)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    uint16_t Len = TlsReadUint16(Buffer);
    if ((Len % 2) || BufferLength < (uint32_t)(sizeof(uint16_t) + Len)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint16_t) + Len;
    Buffer += sizeof(uint16_t) + Len;

    //
    // CompressionMethod
    //
    if (BufferLength < sizeof(uint8_t) ||
        Buffer[0] < 1 ||
        BufferLength < sizeof(uint8_t) + Buffer[0]) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint8_t) + Buffer[0];
    Buffer += sizeof(uint8_t) + Buffer[0];

    //
    // Extension List (optional)
    //
    if (BufferLength < sizeof(uint16_t)) {
        return QUIC_STATUS_SUCCESS; // OK to not have any more.
    }
    Len = TlsReadUint16(Buffer);
    if (BufferLength < (uint32_t)(sizeof(uint16_t) + Len)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    return
        QuicCryptoTlsReadExtensions(
            Connection,
            Buffer + sizeof(uint16_t),
            Len,
            Info);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicCryptoTlsGetCompleteTlsMessagesLength(
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint32_t BufferLength
    )
{
    uint32_t MessagesLength = 0;

    while (BufferLength >= TLS_MESSAGE_HEADER_LENGTH) {

        uint32_t MessageLength =
            TLS_MESSAGE_HEADER_LENGTH + TlsReadUint24(Buffer + 1);
        if (BufferLength < MessageLength) {
            break;
        }

        MessagesLength += MessageLength;
        Buffer += MessageLength;
        BufferLength -= MessageLength;
    }

    return MessagesLength;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadInitial(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint32_t BufferLength,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    do {
        if (BufferLength < TLS_MESSAGE_HEADER_LENGTH) {
            return QUIC_STATUS_PENDING;
        }

        if (Buffer[0] != TlsHandshake_ClientHello) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        uint32_t MessageLength = TlsReadUint24(Buffer + 1);
        if (BufferLength < TLS_MESSAGE_HEADER_LENGTH + MessageLength) {
            return QUIC_STATUS_PENDING;
        }

        QUIC_STATUS Status =
            QuicCryptoTlsReadClientHello(
                Connection,
                Buffer + TLS_MESSAGE_HEADER_LENGTH,
                MessageLength,
                Info);
        if (QUIC_FAILED(Status)) {
            return Status;
        }

        BufferLength -= MessageLength + TLS_MESSAGE_HEADER_LENGTH;
        Buffer += MessageLength + TLS_MESSAGE_HEADER_LENGTH;

    } while (BufferLength > 0);

    if (Info->ClientAlpnList == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (Info->ServerName == NULL) {
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadClientRandom(
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint32_t BufferLength,
    _Inout_ QUIC_TLS_SECRETS* TlsSecrets
    )
{
    UNREFERENCED_PARAMETER(BufferLength);
    CXPLAT_DBG_ASSERT(
        BufferLength >=
        TLS_MESSAGE_HEADER_LENGTH + sizeof(uint16_t) + TLS_RANDOM_LENGTH);

    Buffer += TLS_MESSAGE_HEADER_LENGTH + sizeof(uint16_t);
    memcpy(TlsSecrets->ClientRandom, Buffer, TLS_RANDOM_LENGTH);
    TlsSecrets->IsSet.ClientRandom = TRUE;

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
const uint8_t*
QuicCryptoTlsEncodeTransportParameters(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN IsServerTP,
    _In_ const QUIC_TRANSPORT_PARAMETERS *TransportParams,
    _In_opt_ const QUIC_PRIVATE_TRANSPORT_PARAMETER* TestParam,
    _Out_ uint32_t* TPLen
    )
{
    //
    // Precompute the required size so we can allocate all at once.
    //

    UNREFERENCED_PARAMETER(Connection);
    UNREFERENCED_PARAMETER(IsServerTP);


    size_t RequiredTPLen = 0;
    if (TransportParams->Flags & QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID) {
        CXPLAT_DBG_ASSERT(IsServerTP);
        CXPLAT_FRE_ASSERT(TransportParams->OriginalDestinationConnectionIDLength <= QUIC_MAX_CONNECTION_ID_LENGTH_V1);
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_ORIGINAL_DESTINATION_CONNECTION_ID,
                TransportParams->OriginalDestinationConnectionIDLength);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_IDLE_TIMEOUT) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_IDLE_TIMEOUT,
                QuicVarIntSize(TransportParams->IdleTimeout));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_STATELESS_RESET_TOKEN) {
        CXPLAT_DBG_ASSERT(IsServerTP);
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_STATELESS_RESET_TOKEN,
                QUIC_STATELESS_RESET_TOKEN_LENGTH);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_MAX_UDP_PAYLOAD_SIZE,
                QuicVarIntSize(TransportParams->MaxUdpPayloadSize));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_DATA) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_INITIAL_MAX_DATA,
                QuicVarIntSize(TransportParams->InitialMaxData));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                QuicVarIntSize(TransportParams->InitialMaxStreamDataBidiLocal));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                QuicVarIntSize(TransportParams->InitialMaxStreamDataBidiRemote));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_UNI,
                QuicVarIntSize(TransportParams->InitialMaxStreamDataUni));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_INITIAL_MAX_STREAMS_BIDI,
                QuicVarIntSize(TransportParams->InitialMaxBidiStreams));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_INITIAL_MAX_STREAMS_UNI,
                QuicVarIntSize(TransportParams->InitialMaxUniStreams));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_ACK_DELAY_EXPONENT) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_ACK_DELAY_EXPONENT,
                QuicVarIntSize(TransportParams->AckDelayExponent));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_ACK_DELAY) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_MAX_ACK_DELAY,
                QuicVarIntSize(TransportParams->MaxAckDelay));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_DISABLE_ACTIVE_MIGRATION,
                0);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_PREFERRED_ADDRESS) {
        CXPLAT_DBG_ASSERT(IsServerTP);
        CXPLAT_FRE_ASSERT(FALSE); // TODO - Implement
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_ACTIVE_CONNECTION_ID_LIMIT,
                QuicVarIntSize(TransportParams->ActiveConnectionIdLimit));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID) {
        CXPLAT_FRE_ASSERT(TransportParams->InitialSourceConnectionIDLength <= QUIC_MAX_CONNECTION_ID_LENGTH_V1);
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_INITIAL_SOURCE_CONNECTION_ID,
                TransportParams->InitialSourceConnectionIDLength);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID) {
        CXPLAT_DBG_ASSERT(IsServerTP);
        CXPLAT_FRE_ASSERT(TransportParams->RetrySourceConnectionIDLength <= QUIC_MAX_CONNECTION_ID_LENGTH_V1);
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_RETRY_SOURCE_CONNECTION_ID,
                TransportParams->RetrySourceConnectionIDLength);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_DATAGRAM_FRAME_SIZE) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_MAX_DATAGRAM_FRAME_SIZE,
                QuicVarIntSize(TransportParams->MaxDatagramFrameSize));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_DISABLE_1RTT_ENCRYPTION) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_DISABLE_1RTT_ENCRYPTION,
                0);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION) {
        RequiredTPLen += (size_t)
            TlsTransportParamLength(
                QUIC_TP_ID_VERSION_NEGOTIATION_EXT,
                TransportParams->VersionInfoLength);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MIN_ACK_DELAY) {
        CXPLAT_DBG_ASSERT(
            (TransportParams->Flags & QUIC_TP_FLAG_MIN_ACK_DELAY &&
             US_TO_MS(TransportParams->MinAckDelay) <= TransportParams->MaxAckDelay) ||
            (!(TransportParams->Flags & QUIC_TP_FLAG_MIN_ACK_DELAY) &&
             US_TO_MS(TransportParams->MinAckDelay) <= QUIC_TP_MAX_ACK_DELAY_DEFAULT));
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_MIN_ACK_DELAY,
                QuicVarIntSize(TransportParams->MinAckDelay));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_CIBIR_ENCODING) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_CIBIR_ENCODING,
                QuicVarIntSize(TransportParams->CibirLength) +
                QuicVarIntSize(TransportParams->CibirOffset));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_GREASE_QUIC_BIT) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_GREASE_QUIC_BIT,
                0);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_RELIABLE_RESET_ENABLED) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_RELIABLE_RESET_ENABLED,
                0);
    }
    if (TransportParams->Flags & (QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED | QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED)) {
        const uint32_t value =
            (TransportParams->Flags &
             (QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED | QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED))
            >> QUIC_TP_FLAG_TIMESTAMP_SHIFT;
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_ENABLE_TIMESTAMP,
                QuicVarIntSize(value));
    }
    if (TestParam != NULL) {
        RequiredTPLen +=
            TlsTransportParamLength(
                TestParam->Type,
                TestParam->Length);
    }

    CXPLAT_TEL_ASSERT(RequiredTPLen <= UINT16_MAX);
    if (RequiredTPLen > UINT16_MAX) {
        return NULL;
    }

    uint8_t* TPBufBase = CXPLAT_ALLOC_NONPAGED(CxPlatTlsTPHeaderSize + RequiredTPLen, QUIC_POOL_TLS_TRANSPARAMS);
    if (TPBufBase == NULL) {
        return NULL;
    }

    *TPLen = (uint32_t)(CxPlatTlsTPHeaderSize + RequiredTPLen);
    uint8_t* TPBuf = TPBufBase + CxPlatTlsTPHeaderSize;

    //
    // Now that we have allocated the exact size, we can freely write to the
    // buffer without checking any more lengths.
    //

    if (TransportParams->Flags & QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID) {
        CXPLAT_DBG_ASSERT(IsServerTP);
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_ORIGINAL_DESTINATION_CONNECTION_ID,
                TransportParams->OriginalDestinationConnectionIDLength,
                TransportParams->OriginalDestinationConnectionID,
                TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_IDLE_TIMEOUT) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_IDLE_TIMEOUT,
                TransportParams->IdleTimeout, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_STATELESS_RESET_TOKEN) {
        CXPLAT_DBG_ASSERT(IsServerTP);
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_STATELESS_RESET_TOKEN,
                QUIC_STATELESS_RESET_TOKEN_LENGTH,
                TransportParams->StatelessResetToken,
                TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_MAX_UDP_PAYLOAD_SIZE,
                TransportParams->MaxUdpPayloadSize, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_DATA) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_DATA,
                TransportParams->InitialMaxData, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                TransportParams->InitialMaxStreamDataBidiLocal, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                TransportParams->InitialMaxStreamDataBidiRemote, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_UNI,
                TransportParams->InitialMaxStreamDataUni, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAMS_BIDI,
                TransportParams->InitialMaxBidiStreams, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAMS_UNI,
                TransportParams->InitialMaxUniStreams, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_ACK_DELAY_EXPONENT) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_ACK_DELAY_EXPONENT,
                TransportParams->AckDelayExponent, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_ACK_DELAY) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_MAX_ACK_DELAY,
                TransportParams->MaxAckDelay, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION) {
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_DISABLE_ACTIVE_MIGRATION,
                0,
                NULL,
                TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_PREFERRED_ADDRESS) {
        CXPLAT_DBG_ASSERT(IsServerTP);
        CXPLAT_FRE_ASSERT(FALSE); // TODO - Implement
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT) {
        CXPLAT_DBG_ASSERT(TransportParams->ActiveConnectionIdLimit >= QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN);
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_ACTIVE_CONNECTION_ID_LIMIT,
                TransportParams->ActiveConnectionIdLimit, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID) {
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_INITIAL_SOURCE_CONNECTION_ID,
                TransportParams->InitialSourceConnectionIDLength,
                TransportParams->InitialSourceConnectionID,
                TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID) {
        CXPLAT_DBG_ASSERT(IsServerTP);
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_RETRY_SOURCE_CONNECTION_ID,
                TransportParams->RetrySourceConnectionIDLength,
                TransportParams->RetrySourceConnectionID,
                TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_DATAGRAM_FRAME_SIZE) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_MAX_DATAGRAM_FRAME_SIZE,
                TransportParams->MaxDatagramFrameSize, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_DISABLE_1RTT_ENCRYPTION) {
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_DISABLE_1RTT_ENCRYPTION,
                0,
                NULL,
                TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION) {
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_VERSION_NEGOTIATION_EXT,
                (uint16_t)TransportParams->VersionInfoLength,
                TransportParams->VersionInfo,
                TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MIN_ACK_DELAY) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_MIN_ACK_DELAY,
                TransportParams->MinAckDelay, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_CIBIR_ENCODING) {
        const uint8_t TPLength =
            QuicVarIntSize(TransportParams->CibirLength) +
            QuicVarIntSize(TransportParams->CibirOffset);
        TPBuf = QuicVarIntEncode(QUIC_TP_ID_CIBIR_ENCODING, TPBuf);
        TPBuf = QuicVarIntEncode(TPLength, TPBuf);
        TPBuf = QuicVarIntEncode(TransportParams->CibirLength, TPBuf);
        TPBuf = QuicVarIntEncode(TransportParams->CibirOffset, TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_GREASE_QUIC_BIT) {
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_GREASE_QUIC_BIT,
                0,
                NULL,
                TPBuf);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_RELIABLE_RESET_ENABLED) {
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_RELIABLE_RESET_ENABLED,
                0,
                NULL,
                TPBuf);
    }
    if (TransportParams->Flags & (QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED | QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED)) {
        const uint32_t value =
            (TransportParams->Flags &
             (QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED | QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED))
            >> QUIC_TP_FLAG_TIMESTAMP_SHIFT;
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_ENABLE_TIMESTAMP,
                value,
                TPBuf);
    }
    if (TestParam != NULL) {
        TPBuf =
            TlsWriteTransportParam(
                TestParam->Type,
                TestParam->Length,
                TestParam->Buffer,
                TPBuf);
    }

    size_t FinalTPLength = (TPBuf - (TPBufBase + CxPlatTlsTPHeaderSize));
    if (FinalTPLength != RequiredTPLen) {
        CXPLAT_TEL_ASSERT(FinalTPLength == RequiredTPLen);
        CXPLAT_FREE(TPBufBase, QUIC_POOL_TLS_TRANSPARAMS);
        return NULL;
    }

    return TPBufBase;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicCryptoTlsDecodeTransportParameters( // NOLINT(readability-function-size, google-readability-function-size, hicpp-function-size)
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN IsServerTP,
    _In_reads_(TPLen)
        const uint8_t* TPBuf,
    _In_ uint16_t TPLen,
    _Inout_ QUIC_TRANSPORT_PARAMETERS* TransportParams
    )
{
    BOOLEAN Result = FALSE;
    uint64_t ParamsPresent = 0;
    uint16_t Offset = 0;

    UNREFERENCED_PARAMETER(Connection);

    if (TransportParams->VersionInfo) {
        CXPLAT_FREE(TransportParams->VersionInfo, QUIC_POOL_VERSION_INFO);
    }
    CxPlatZeroMemory(TransportParams, sizeof(QUIC_TRANSPORT_PARAMETERS));
    TransportParams->MaxUdpPayloadSize = QUIC_TP_MAX_PACKET_SIZE_DEFAULT;
    TransportParams->AckDelayExponent = QUIC_TP_ACK_DELAY_EXPONENT_DEFAULT;
    TransportParams->MaxAckDelay = QUIC_TP_MAX_ACK_DELAY_DEFAULT;
    TransportParams->ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_DEFAULT;


    while (Offset < TPLen) {

        QUIC_VAR_INT Id = 0;
        if (!QuicVarIntDecode(TPLen, TPBuf, &Offset, &Id)) {
            goto Exit;
        }

        if (Id < (8 * sizeof(uint64_t))) { // We only duplicate detection for the first 64 IDs.

            if (ParamsPresent & (1ULL << Id)) {
                goto Exit;
            }

            ParamsPresent |= (1ULL << Id);
        }

        QUIC_VAR_INT ParamLength INIT_NO_SAL(0);
        if (!QuicVarIntDecode(TPLen, TPBuf, &Offset, &ParamLength)) {
            goto Exit;
        } else if (ParamLength + Offset > TPLen) {
            goto Exit;
        }

        uint16_t Length = (uint16_t)ParamLength;

        uint16_t VarIntLength = 0;
    #define TRY_READ_VAR_INT(Param) \
        QuicVarIntDecode(Length, TPBuf + Offset, &VarIntLength, &(Param))

        switch (Id) {

        case QUIC_TP_ID_ORIGINAL_DESTINATION_CONNECTION_ID:
            if (Length > QUIC_MAX_CONNECTION_ID_LENGTH_V1) {
                goto Exit;
            } else if (!IsServerTP) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID;
            TransportParams->OriginalDestinationConnectionIDLength = (uint8_t)Length;
            CxPlatCopyMemory(
                TransportParams->OriginalDestinationConnectionID,
                TPBuf + Offset,
                Length);
            break;

        case QUIC_TP_ID_IDLE_TIMEOUT:
            if (!TRY_READ_VAR_INT(TransportParams->IdleTimeout)) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_IDLE_TIMEOUT;
            break;

        case QUIC_TP_ID_STATELESS_RESET_TOKEN:
            if (Length != QUIC_STATELESS_RESET_TOKEN_LENGTH) {
                goto Exit;
            } else if (!IsServerTP) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_STATELESS_RESET_TOKEN;
            CxPlatCopyMemory(
                TransportParams->StatelessResetToken,
                TPBuf + Offset,
                QUIC_STATELESS_RESET_TOKEN_LENGTH);
            break;

        case QUIC_TP_ID_MAX_UDP_PAYLOAD_SIZE:
            if (!TRY_READ_VAR_INT(TransportParams->MaxUdpPayloadSize)) {
                goto Exit;
            }
            if (TransportParams->MaxUdpPayloadSize < QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MIN) {
                goto Exit;
            }
            if (TransportParams->MaxUdpPayloadSize > QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MAX) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE;
            break;

        case QUIC_TP_ID_INITIAL_MAX_DATA:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxData)) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_DATA;
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxStreamDataBidiLocal)) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL;
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxStreamDataBidiRemote)) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE;
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_UNI:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxStreamDataUni)) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI;
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAMS_BIDI:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxBidiStreams)) {
                goto Exit;
            }
            if (TransportParams->InitialMaxBidiStreams > QUIC_TP_MAX_STREAMS_MAX) {
                goto Exit;
            }
            if (TransportParams->InitialMaxBidiStreams > QUIC_TP_MAX_STREAMS_MAX) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI;
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAMS_UNI:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxUniStreams)) {
                goto Exit;
            }
            if (TransportParams->InitialMaxUniStreams > QUIC_TP_MAX_STREAMS_MAX) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
            break;

        case QUIC_TP_ID_ACK_DELAY_EXPONENT:
            if (!TRY_READ_VAR_INT(TransportParams->AckDelayExponent)) {
                goto Exit;
            }
            if (TransportParams->AckDelayExponent > QUIC_TP_ACK_DELAY_EXPONENT_MAX) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_ACK_DELAY_EXPONENT;
            break;

        case QUIC_TP_ID_MAX_ACK_DELAY:
            if (!TRY_READ_VAR_INT(TransportParams->MaxAckDelay)) {
                goto Exit;
            }
            if (TransportParams->MaxAckDelay > QUIC_TP_MAX_ACK_DELAY_MAX) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_MAX_ACK_DELAY;
            break;

        case QUIC_TP_ID_DISABLE_ACTIVE_MIGRATION:
            if (Length != 0) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION;
            break;

        case QUIC_TP_ID_PREFERRED_ADDRESS:
            if (!IsServerTP) {
                goto Exit;
            }
            // TODO - Implement
            break;

        case QUIC_TP_ID_ACTIVE_CONNECTION_ID_LIMIT:
            if (!TRY_READ_VAR_INT(TransportParams->ActiveConnectionIdLimit)) {
                goto Exit;
            }
            if (TransportParams->ActiveConnectionIdLimit < QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT;
            break;

        case QUIC_TP_ID_INITIAL_SOURCE_CONNECTION_ID:
            if (Length > QUIC_MAX_CONNECTION_ID_LENGTH_V1) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID;
            TransportParams->InitialSourceConnectionIDLength = (uint8_t)Length;
            CxPlatCopyMemory(
                TransportParams->InitialSourceConnectionID,
                TPBuf + Offset,
                Length);
            break;

        case QUIC_TP_ID_RETRY_SOURCE_CONNECTION_ID:
            if (Length > QUIC_MAX_CONNECTION_ID_LENGTH_V1) {
                goto Exit;
            } else if (!IsServerTP) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID;
            TransportParams->RetrySourceConnectionIDLength = (uint8_t)Length;
            CxPlatCopyMemory(
                TransportParams->RetrySourceConnectionID,
                TPBuf + Offset,
                Length);
            break;

        case QUIC_TP_ID_MAX_DATAGRAM_FRAME_SIZE:
            if (!TRY_READ_VAR_INT(TransportParams->MaxDatagramFrameSize)) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_MAX_DATAGRAM_FRAME_SIZE;
            break;

        case QUIC_TP_ID_CIBIR_ENCODING:
            if (!TRY_READ_VAR_INT(TransportParams->CibirLength) ||
                TransportParams->CibirLength < 1 ||
                TransportParams->CibirLength > QUIC_MAX_CONNECTION_ID_LENGTH_INVARIANT ||
                !TRY_READ_VAR_INT(TransportParams->CibirOffset) ||
                TransportParams->CibirOffset > QUIC_MAX_CONNECTION_ID_LENGTH_INVARIANT ||
                TransportParams->CibirLength + TransportParams->CibirOffset > QUIC_MAX_CONNECTION_ID_LENGTH_INVARIANT) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_CIBIR_ENCODING;
            break;

        case QUIC_TP_ID_DISABLE_1RTT_ENCRYPTION:
            if (Length != 0) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_DISABLE_1RTT_ENCRYPTION;
            break;

        case QUIC_TP_ID_VERSION_NEGOTIATION_EXT:
            if (Length > 0) {
                TransportParams->VersionInfo = CXPLAT_ALLOC_NONPAGED(Length, QUIC_POOL_VERSION_INFO);
                if (TransportParams->VersionInfo == NULL) {
                    break;
                }
                CxPlatCopyMemory((uint8_t*)TransportParams->VersionInfo, TPBuf + Offset, Length);
            } else {
                TransportParams->VersionInfo = NULL;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_VERSION_NEGOTIATION;
            TransportParams->VersionInfoLength = Length;
            break;

        case QUIC_TP_ID_MIN_ACK_DELAY:
            if (!TRY_READ_VAR_INT(TransportParams->MinAckDelay)) {
                goto Exit;
            }
            if (TransportParams->MinAckDelay > QUIC_TP_MIN_ACK_DELAY_MAX) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_MIN_ACK_DELAY;
            break;

        case QUIC_TP_ID_GREASE_QUIC_BIT:
            if (Length != 0) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_GREASE_QUIC_BIT;
            break;

        case QUIC_TP_ID_RELIABLE_RESET_ENABLED:
            if (Length != 0) {
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_RELIABLE_RESET_ENABLED;
            break;

        case QUIC_TP_ID_ENABLE_TIMESTAMP: {
            QUIC_VAR_INT value = 0;
            if (!TRY_READ_VAR_INT(value)) {
                goto Exit;
            }
            if (value > 3) {
                goto Exit;
            }
            value <<= QUIC_TP_FLAG_TIMESTAMP_SHIFT; // Convert to QUIC_TP_FLAG_TIMESTAMP_*
            TransportParams->Flags |= (uint32_t)value;
            break;
        }

        default:
            if (QuicTpIdIsReserved(Id)) {
            } else {
            }
            break;
        }

        Offset += Length;
    }

    if (TransportParams->Flags & QUIC_TP_FLAG_MIN_ACK_DELAY &&
        TransportParams->MinAckDelay > MS_TO_US(TransportParams->MaxAckDelay)) {
        goto Exit;
    }

    Result = TRUE;

Exit:

    return Result;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicCryptoTlsCopyTransportParameters(
    _In_ const QUIC_TRANSPORT_PARAMETERS* Source,
    _In_ QUIC_TRANSPORT_PARAMETERS* Destination
    )
{
    *Destination = *Source;
    if (Source->Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION) {
        Destination->VersionInfo =
            CXPLAT_ALLOC_NONPAGED((size_t)Source->VersionInfoLength, QUIC_POOL_VERSION_INFO);
        if (Destination->VersionInfo == NULL) {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        Destination->Flags |= QUIC_TP_FLAG_VERSION_NEGOTIATION;
        CxPlatCopyMemory(
            (uint8_t*)Destination->VersionInfo,
            Source->VersionInfo,
            (size_t)Source->VersionInfoLength);
        Destination->VersionInfoLength = Source->VersionInfoLength;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCryptoTlsCleanupTransportParameters(
    _In_ QUIC_TRANSPORT_PARAMETERS* TransportParams
    )
{
    if (TransportParams->Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION) {
        if (TransportParams->VersionInfo != NULL) {
            CXPLAT_FREE(TransportParams->VersionInfo, QUIC_POOL_VERSION_INFO);
            TransportParams->VersionInfo = NULL;
        }
        TransportParams->VersionInfoLength = 0;
        TransportParams->Flags &= ~QUIC_TP_FLAG_VERSION_NEGOTIATION;
    }
}
