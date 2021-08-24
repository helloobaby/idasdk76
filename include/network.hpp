#ifndef NETWORK_HPP
#define NETWORK_HPP

#include <pro.h>

#ifdef __NT__
#  if !defined(AF_MAX)
#    include <ws2tcpip.h>
#  endif
#  define SYSTEM "Windows"
#  define socklen_t int
#  define SHUT_RD SD_RECEIVE
#  define SHUT_WR SD_SEND
#  define SHUT_RDWR SD_BOTH
#else   // not NT, i.e. UNIX
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  define closesocket(s)           close(s)
#  define SOCKET size_t
#  define INVALID_SOCKET size_t(-1)
#  define SOCKET_ERROR   (-1)
#  if defined(__LINUX__)
#    if defined(__ARM__)
#      if defined(__ANDROID__)
#        define SYSTEM "Android"
#      else
#        define SYSTEM "ARM Linux"
#      endif
#    else
#      if defined(__ANDROID__)
#        define SYSTEM "Android x86"
#      else
#        define SYSTEM "Linux"
#      endif
#    endif
     // linux debugger cannot be multithreaded because it uses thread_db.
     // i doubt that this library is meant to be used with multiple
     // applications simultaneously.
#    define __SINGLE_THREADED_SERVER__
#  elif defined(__MAC__)
#    define SYSTEM "Mac OS X"
#  else
#    error "Unknown platform"
#  endif
#  include <sys/socket.h>
#  include <netinet/in.h>
#endif

#ifndef __X86__
#  define _SYSBITS " 64-bit"
#else
#  define _SYSBITS " 32-bit"
#endif

#ifdef TESTABLE_BUILD
#  ifdef __EA64__
#    define SYSBITS _SYSBITS " (sizeof ea=64)"
#  else
#    define SYSBITS _SYSBITS " (sizeof ea=32)"
#  endif
#else
#    define SYSBITS _SYSBITS
#endif

#ifdef __SINGLE_THREADED_SERVER__
#  define __SERVER_TYPE__ "ST"
#else
#  define __SERVER_TYPE__ "MT"
#endif

#define TIMEOUT         (1000/25)       // timeout for polling (ms)
#define TIMEOUT_INFINITY -1
#define RECV_HELLO_TIMEOUT   1000       // timeout for the first packet (ms)
#define RECV_TIMEOUT_PERIOD  10000      // timeout for recv (ms)

// bidirectional codes (client <-> server)
enum base_packet_id_t
{
  RPC_OK = 0,  // response: function call succeeded
  RPC_UNK,     // response: unknown function code
  RPC_MEM,     // response: no memory
  base_packet_id_last
};

#define RPC_OPEN      3 // server->client: i'm ready, the very first packet

#define RPC_EVENT     4 // server->client: debug event ready, followed by debug_event
#define RPC_EVOK      5 // client->server: event processed (in response to RPC_EVENT)
#define RPC_CANCELLED 6 // client->server: operation was cancelled by the user
// we need EVOK to handle the situation when the debug
// event was detected by the server during polling and
// was sent to the client using RPC_EVENT but client has not received it yet
// and requested GET_DEBUG_EVENT. In this case we should not
// call remote_get_debug_event() but instead force the client
// to use the event sent by RPC_EVENT.
// In other words, if the server has sent RPC_EVENT but has not
// received RPC_EVOK, it should fail all GET_DEBUG_EVENTS.

// client->server codes
#define RPC_INIT                      10
#define RPC_TERM                      11
#define RPC_GET_PROCESSES             12
#define RPC_START_PROCESS             13
#define RPC_EXIT_PROCESS              14
#define RPC_ATTACH_PROCESS            15
#define RPC_DETACH_PROCESS            16
#define RPC_GET_DEBUG_EVENT           17
#define RPC_PREPARE_TO_PAUSE_PROCESS  18
#define RPC_STOPPED_AT_DEBUG_EVENT    19
#define RPC_CONTINUE_AFTER_EVENT      20
#define RPC_TH_SUSPEND                21
#define RPC_TH_CONTINUE               22
#define RPC_SET_RESUME_MODE           23
#define RPC_GET_MEMORY_INFO           24
#define RPC_READ_MEMORY               25
#define RPC_WRITE_MEMORY              26
#define RPC_UPDATE_BPTS               27
#define RPC_UPDATE_LOWCNDS            28
#define RPC_EVAL_LOWCND               29
#define RPC_ISOK_BPT                  30
#define RPC_READ_REGS                 31
#define RPC_WRITE_REG                 32
#define RPC_GET_SREG_BASE             33
#define RPC_SET_EXCEPTION_INFO        34

#define RPC_OPEN_FILE                 35
#define RPC_CLOSE_FILE                36
#define RPC_READ_FILE                 37
#define RPC_WRITE_FILE                38
#define RPC_IOCTL                     39 // both client and the server may send this packet
#define RPC_UPDATE_CALL_STACK         40
#define RPC_APPCALL                   41
#define RPC_CLEANUP_APPCALL           42
#define RPC_REXEC                     43
#define RPC_GET_SCATTERED_IMAGE       44
#define RPC_GET_IMAGE_UUID            45
#define RPC_GET_SEGM_START            46
#define RPC_BIN_SEARCH                47

// server->client codes
#define RPC_SET_DEBUG_NAMES           50
#define RPC_SYNC_STUB                 51
#define RPC_ERROR                     52
#define RPC_MSG                       53
#define RPC_WARNING                   54
#define RPC_HANDLE_DEBUG_EVENT        55
#define RPC_REPORT_IDC_ERROR          56
#define RPC_IMPORT_DLL                57

#pragma pack(push, 1)

struct PACKED rpc_packet_t
{                        // fields are always sent in the network order
  uint32 length;         // length of the packet (do not count length & code)
  uchar code;            // function code
};
CASSERT(sizeof(rpc_packet_t) == 5);
#pragma pack(pop)

enum rpc_notification_type_t
{
  rnt_unknown = 0,
  rnt_msg,
  rnt_warning,
  rnt_error,
};

#define DEFINE_ONE_NOTIFICATION_FUNCTION(FuncName, NotifCode, RpcEngineInst) \
  AS_PRINTF(2, 3) void FuncName(const char *format, ...)                \
  {                                                                     \
    va_list va;                                                         \
    va_start(va, format);                                               \
    dvnotif(NotifCode, RpcEngineInst, format, va);                    \
    va_end(va);                                                         \
  }

#define DEFINE_ALL_NOTIFICATION_FUNCTIONS(RpcEngineInst)        \
  DEFINE_ONE_NOTIFICATION_FUNCTION(dmsg,     0, RpcEngineInst)  \
  DEFINE_ONE_NOTIFICATION_FUNCTION(dwarning, 1, RpcEngineInst)  \
  DEFINE_ONE_NOTIFICATION_FUNCTION(derror,  -1, RpcEngineInst)

class rpc_engine_t;

//-------------------------------------------------------------------------
AS_PRINTF(2, 0) ssize_t dvnotif_client(
        int code,
        const char *format,
        va_list va);

#ifdef __NT__
#  define IRSERR_TIMEOUT WAIT_TIMEOUT
#else
#  define IRSERR_TIMEOUT ETIME
#endif
#define IRSERR_CANCELLED -0xE5CA7E // escape
#define IRSERR_SKIP_ITER -0x5217   // skip recv() in rpc_engine_t's recv_data loop

//-------------------------------------------------------------------------
//                           idarpc_stream_t
//-------------------------------------------------------------------------
// the idarpc_stream_t structure is not defined.
// it is used as an opaque type provided by the transport level.
// the transport level defines its own local type for it.
struct idarpc_stream_t;

idarpc_stream_t *irs_new(bool use_tls=false);
bool irs_init_client(idarpc_stream_t *irs, const char *hostname, int port_number);
bool irs_init_server(
        idarpc_stream_t *irs,
        const char *hostname,
        int port_number,
        const char *certchain=nullptr,
        const char *privkey=nullptr);
bool irs_accept(idarpc_stream_t *irs, idarpc_stream_t *listener);
bool irs_handshake(idarpc_stream_t *irs, int timeout_ms = -1);
int irs_ready(idarpc_stream_t *irs, int timeout_ms = -1);
ssize_t irs_recv(idarpc_stream_t *irs, void *buf, size_t n);
ssize_t irs_send(idarpc_stream_t *irs, const void *buf, size_t n);
void irs_term(idarpc_stream_t **pirs, int shutdown_flags = -1);
int irs_get_error(idarpc_stream_t *irs);
const char *irs_strerror(idarpc_stream_t *irs);
bool irs_peername(idarpc_stream_t *irs, qstring *out, bool lookupname = true);
bool irs_sockname(idarpc_stream_t *irs, qstring *out, bool lookupname = true);

enum progress_loop_ctrl_t
{
  plc_proceed,
  plc_skip_iter,
  plc_cancel,
};
typedef progress_loop_ctrl_t irs_progress_cb_t(bool receiving, size_t processed, size_t total, void *);
void irs_set_progress_cb(idarpc_stream_t *irs, int ms, irs_progress_cb_t cb, void *ud=NULL);
struct irs_cancellable_op_t
{
  idarpc_stream_t *irs;
  irs_cancellable_op_t(idarpc_stream_t *_irs, bool receiving, size_t goal=0);
  ~irs_cancellable_op_t();
  void inc_progress(size_t progress);
};

//-------------------------------------------------------------------------
typedef qtime64_t utc_timestamp_t;
typedef uint64 lofi_timestamp_t; // low-fidelity timestamp. Only encodes up to 1/10th seconds

//-------------------------------------------------------------------------
THREAD_SAFE inline lofi_timestamp_t to_lofi_timestamp(qtime64_t ts)
{
  const uint64 s = get_secs(ts);
  const uint64 us = get_usecs(ts);
  return s * 10 + us / (100 * 1000);
}

//-------------------------------------------------------------------------
THREAD_SAFE inline qtime64_t from_lofi_timestamp(lofi_timestamp_t lts)
{
  return make_qtime64(lts / 10, (lts % 10) * (100 * 1000));
}


//-------------------------------------------------------------------------
//               base_dispatcher_t + client_handler_t
//-------------------------------------------------------------------------
struct client_handler_t
{
  FILE *channels[16];
  idarpc_stream_t *irs;
  qstring peer_name;
  uint32 session_id;
  utc_timestamp_t session_start;
  bool verbose;

  void close_all_channels();
  void clear_channels();
  int find_free_channel() const;

  client_handler_t(idarpc_stream_t *_irs, bool _verbose);
  virtual ~client_handler_t();

  virtual bool handle() = 0; // true - delete this
  virtual void shutdown_gracefully(int signum) = 0;

  //lint -sem(client_handler_t::term_irs,cleanup)
  void term_irs();

  AS_PRINTF(2, 3) int lprintf(const char *format, ...) const;

private:
  DECLARE_UNCOPYABLE(client_handler_t);
};

//-------------------------------------------------------------------------
struct client_handlers_list_t
{
  typedef std::map<client_handler_t *, qthread_t> storage_t;
  storage_t storage;

  virtual ~client_handlers_list_t() {}
  virtual void lock() {}
  virtual void unlock() {}
  virtual bool is_multi_threaded() const { return false; }
};

//-------------------------------------------------------------------------
struct mt_client_handlers_list_t : public client_handlers_list_t
{
  qmutex_t mutex;

  mt_client_handlers_list_t() { mutex = qmutex_create(); QASSERT(1540, mutex != NULL); }
  virtual ~mt_client_handlers_list_t() { qmutex_free(mutex); }
  virtual void lock() override { qmutex_lock(mutex); }
  virtual void unlock() override { qmutex_unlock(mutex);  }
  virtual bool is_multi_threaded() const override { return true; }
};

//-------------------------------------------------------------------------
struct base_dispatcher_t
{
  qstring ipv4_address;
  qstring certchain;
  qstring privkey;
  idarpc_stream_t *irs = nullptr;
  client_handlers_list_t *clients_list = nullptr;
  ushort port_number = -1;
  bool use_tls = false;
  bool verbose = false;

  base_dispatcher_t(bool multi_threaded);
  virtual ~base_dispatcher_t();
  NORETURN void dispatch();

  virtual void collect_cliopts(cliopts_t *out);

  //
  void install_signal_handlers();

  //
  virtual client_handler_t *new_client_handler(idarpc_stream_t *_irs) = 0;
  void delete_client_handler(client_handler_t *inst);

  virtual void shutdown_gracefully(int signum);


private:
  void handle_session(client_handler_t *handler);
  void add_to_clients_list(client_handler_t *handler, qthread_t t);
  DECLARE_UNCOPYABLE(base_dispatcher_t);
};

//-------------------------------------------------------------------------
//                   packing/unpacking utils
//-------------------------------------------------------------------------
bytevec_t prepare_rpc_packet(uchar code);
void finalize_packet(bytevec_t &pkt);
//const char *get_rpc_name(int code);

//-------------------------------------------------------------------------
struct rpc_connection_params_t
{
  size_t cb;
  qstring host;
  ushort port;
  bool tls;

  rpc_connection_params_t(
        const char *_host=nullptr,
        ushort _port=0,
        bool _tls=true)
    : cb(sizeof(*this)), host(_host), port(_port), tls(_tls) {}
};

//-------------------------------------------------------------------------
//                           rpc_engine_t
//-------------------------------------------------------------------------
#define VERBOSE_ENABLED
#ifdef VERBOSE_ENABLED
#define verb(x)  do { if ( verbose ) msg x; } while(0)
#define verb_eng(engine, x) do { if ( (engine)->verbose ) msg x; } while(0)
#else
#define verb(x)  //msg x
#define verb_eng(engine, x)
#endif
#define verbev(x)  //msg x

//-------------------------------------------------------------------------
struct rpc_packet_data_t
{
  uchar code;

  rpc_packet_data_t(uchar _code) : code(_code) {}
  virtual ~rpc_packet_data_t() {}
  virtual void serialize(bytevec_t *out, int version) const = 0;
  virtual bool deserialize(const uchar **ptr, size_t len, int version) = 0;
};

//-------------------------------------------------------------------------
typedef int ioctl_handler_t(
        class rpc_engine_t *rpc,
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize);

//-------------------------------------------------------------------------
typedef rpc_packet_data_t *rpc_packet_instantiator_t(const uchar *ptr, size_t len, int version);

//-------------------------------------------------------------------------
struct rpc_packet_type_desc_t
{
  uchar code;
  const char *name;
  rpc_packet_instantiator_t *instantiate;
};
DECLARE_TYPE_AS_MOVABLE(rpc_packet_type_desc_t);
typedef qvector<rpc_packet_type_desc_t> rpc_packet_type_desc_vec_t;

//---------------------------------------------------------------------------
class rpc_engine_t
{
public:
  bool network_error;

  // pointer to the ioctl request handler, in case you
  // need to handle ioctl requests from the server.
  ioctl_handler_t *ioctl_handler;
  int recv_timeout;
  bool is_client;
  bool logged_in;

protected:
  void register_packet_type_descs(const rpc_packet_type_desc_t *ptypes, size_t cnt);
  const rpc_packet_type_desc_t *find_packet_type_desc(int code) const;
  const rpc_packet_type_desc_t *find_packet_type_desc(const char *name) const;

public:
  rpc_engine_t(bool is_client);
  virtual ~rpc_engine_t() {}

  int handle_ioctl_packet(bytevec_t &pkt, const uchar *ptr, const uchar *end);

  // low-level: deal with bytes, and don't handle "conversations".
  int send_data(bytevec_t &data);
  rpc_packet_t *recv_packet();

  virtual rpc_packet_t *send_request_and_receive_reply(bytevec_t &pkt) = 0;

  virtual idarpc_stream_t *get_irs() const = 0;
  AS_PRINTF(3, 0) virtual ssize_t send_notif(int code, const char *format, va_list va);

  virtual bool get_broken_connection(void) { return false; }
  virtual void set_broken_connection(void) {}

  int send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize);
  void set_ioctl_handler(ioctl_handler_t *h) { ioctl_handler = h; }

  DEFINE_ALL_NOTIFICATION_FUNCTIONS(this);

private:
  rpc_packet_type_desc_vec_t ptypes;

  int recv_data(void *out, size_t len);

  AS_PRINTF(3,0) static ssize_t dvnotif(int code, rpc_engine_t *rpc, const char *format, va_list va);
};

//-------------------------------------------------------------------------
AS_PRINTF(3, 0) ssize_t dvnotif_rpc(
        int code,
        rpc_engine_t *rpc,
        const char *format,
        va_list va);

//---------------------------------------------------------------------------
AS_PRINTF(1, 0) int vlprintf(const char *format, va_list va);
AS_PRINTF(1, 2) int lprintf(const char *format, ...);
void set_lprintf_output(FILE *out);

//---------------------------------------------------------------------------
THREAD_SAFE inline size_t format_timestamp(char *buf, size_t bufsize, qtime64_t ts)
{
  return qstrftime64(buf, bufsize, "%Y-%m-%d %H:%M:%S", ts);
}

#endif // NETWORK_HPP
