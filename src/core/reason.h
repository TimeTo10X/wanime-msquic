/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

//
// Runtime data structures — used by core logic, not just tracing.
//

typedef enum QUIC_FLOW_BLOCK_REASON {
    QUIC_FLOW_BLOCKED_SCHEDULING            = 0x01,
    QUIC_FLOW_BLOCKED_PACING                = 0x02,
    QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT    = 0x04,
    QUIC_FLOW_BLOCKED_CONGESTION_CONTROL    = 0x08,
    QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL     = 0x10,
    QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL= 0x20,
    QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL   = 0x40,
    QUIC_FLOW_BLOCKED_APP                   = 0x80
} QUIC_FLOW_BLOCK_REASON;

typedef enum QUIC_TRACE_PACKET_TYPE {
    QUIC_TRACE_PACKET_VN,
    QUIC_TRACE_PACKET_INITIAL,
    QUIC_TRACE_PACKET_ZERO_RTT,
    QUIC_TRACE_PACKET_HANDSHAKE,
    QUIC_TRACE_PACKET_RETRY,
    QUIC_TRACE_PACKET_ONE_RTT
} QUIC_TRACE_PACKET_TYPE;

typedef enum QUIC_TRACE_PACKET_LOSS_REASON {
    QUIC_TRACE_PACKET_LOSS_RACK,
    QUIC_TRACE_PACKET_LOSS_FACK,
    QUIC_TRACE_PACKET_LOSS_PROBE
} QUIC_TRACE_PACKET_LOSS_REASON;

typedef enum QUIC_TRACE_API_TYPE {
    QUIC_TRACE_API_SET_PARAM,
    QUIC_TRACE_API_GET_PARAM,
    QUIC_TRACE_API_REGISTRATION_OPEN,
    QUIC_TRACE_API_REGISTRATION_CLOSE,
    QUIC_TRACE_API_REGISTRATION_SHUTDOWN,
    QUIC_TRACE_API_CONFIGURATION_OPEN,
    QUIC_TRACE_API_CONFIGURATION_CLOSE,
    QUIC_TRACE_API_CONFIGURATION_LOAD_CREDENTIAL,
    QUIC_TRACE_API_LISTENER_OPEN,
    QUIC_TRACE_API_LISTENER_CLOSE,
    QUIC_TRACE_API_LISTENER_START,
    QUIC_TRACE_API_LISTENER_STOP,
    QUIC_TRACE_API_CONNECTION_OPEN,
    QUIC_TRACE_API_CONNECTION_CLOSE,
    QUIC_TRACE_API_CONNECTION_SHUTDOWN,
    QUIC_TRACE_API_CONNECTION_START,
    QUIC_TRACE_API_CONNECTION_SET_CONFIGURATION,
    QUIC_TRACE_API_CONNECTION_SEND_RESUMPTION_TICKET,
    QUIC_TRACE_API_STREAM_OPEN,
    QUIC_TRACE_API_STREAM_CLOSE,
    QUIC_TRACE_API_STREAM_START,
    QUIC_TRACE_API_STREAM_SHUTDOWN,
    QUIC_TRACE_API_STREAM_SEND,
    QUIC_TRACE_API_STREAM_RECEIVE_COMPLETE,
    QUIC_TRACE_API_STREAM_RECEIVE_SET_ENABLED,
    QUIC_TRACE_API_DATAGRAM_SEND,
    QUIC_TRACE_API_CONNECTION_COMPLETE_RESUMPTION_TICKET_VALIDATION,
    QUIC_TRACE_API_CONNECTION_COMPLETE_CERTIFICATE_VALIDATION,
    QUIC_TRACE_API_STREAM_PROVIDE_RECEIVE_BUFFERS,
    QUIC_TRACE_API_CONNECTION_POOL_CREATE,
    QUIC_TRACE_API_EXECUTION_CREATE,
    QUIC_TRACE_API_EXECUTION_DELETE,
    QUIC_TRACE_API_EXECUTION_POLL,
    QUIC_TRACE_API_REGISTRATION_CLOSE2,
    QUIC_TRACE_API_COUNT
} QUIC_TRACE_API_TYPE;

//
// Tracing rundown callback type.
//
#ifdef __cplusplus
extern "C"
#endif
typedef
_Function_class_(QUIC_TRACE_RUNDOWN_CALLBACK)
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_TRACE_RUNDOWN_CALLBACK)(
    void
    );

extern QUIC_TRACE_RUNDOWN_CALLBACK* QuicTraceRundownCallback;

//
// Stub all events and logs — no-op everything.
//

#define QuicTraceEventEnabled(Name) FALSE

#define QuicTraceEvent(Name, Fmt, ...) \
    do { } while (0)

#define QuicTraceLogErrorEnabled()   FALSE
#define QuicTraceLogWarningEnabled() FALSE
#define QuicTraceLogInfoEnabled()    FALSE
#define QuicTraceLogVerboseEnabled() FALSE
#define QuicTraceLogStreamVerboseEnabled() FALSE

#define QuicTraceLogError(Name, Fmt, ...)              do { } while (0)
#define QuicTraceLogWarning(Name, Fmt, ...)            do { } while (0)
#define QuicTraceLogInfo(Name, Fmt, ...)               do { } while (0)
#define QuicTraceLogVerbose(Name, Fmt, ...)            do { } while (0)

#define QuicTraceLogConnError(Name, X, Fmt, ...)       do { UNREFERENCED_PARAMETER(X); } while (0)
#define QuicTraceLogConnWarning(Name, X, Fmt, ...)     do { UNREFERENCED_PARAMETER(X); } while (0)
#define QuicTraceLogConnInfo(Name, X, Fmt, ...)        do { UNREFERENCED_PARAMETER(X); } while (0)
#define QuicTraceLogConnVerbose(Name, X, Fmt, ...)     do { UNREFERENCED_PARAMETER(X); } while (0)

#define QuicTraceLogStreamError(Name, X, Fmt, ...)     do { UNREFERENCED_PARAMETER(X); } while (0)
#define QuicTraceLogStreamWarning(Name, X, Fmt, ...)   do { UNREFERENCED_PARAMETER(X); } while (0)
#define QuicTraceLogStreamInfo(Name, X, Fmt, ...)      do { UNREFERENCED_PARAMETER(X); } while (0)
#define QuicTraceLogStreamVerbose(Name, X, Fmt, ...)   do { UNREFERENCED_PARAMETER(X); } while (0)

#define CASTED_CLOG_BYTEARRAY(Len, Data)   (void)(Len), (void*)(Data)
#define CASTED_CLOG_BYTEARRAY16(Len, Data) (void)(Len), (void*)(Data)
