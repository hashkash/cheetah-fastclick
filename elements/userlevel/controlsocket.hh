#ifndef CLICK_CONTROLSOCKET_HH
#define CLICK_CONTROLSOCKET_HH
#include "elements/userlevel/handlerproxy.hh"
CLICK_DECLS
class ControlSocketErrorHandler;
class Timer;
class Handler;

/*
=c

ControlSocket("TCP", PORTNUMBER [, I<KEYWORDS>])
ControlSocket("UNIX", FILENAME [, I<KEYWORDS>])

=s debugging

opens control sockets for other programs

=io

None

=d

Opens a control socket that allows other user-level programs to call read or
write handlers on the router. Depending on its configuration string,
ControlSocket will listen on TCP port PORTNUMBER, or on a UNIX-domain socket
named FILENAME. With the PROXY keyword argument, you can make ControlSocket speak to
a kernel driver; see below.

The "server" (that is, the ControlSocket element) speaks a relatively
simple line-based protocol. Commands sent to the server are single lines of
text; they consist of words separated by spaces. The server responds to
every command with at least one message line followed optionally by some
data. Message lines start with a three-digit response code, as in FTP. When
multiple message lines are sent in response to a single command, all but
the last begin with the response code and a hyphen (as in "200-Hello!");
the last line begins with the response code and a space (as in "200
Hello!").

The server will accept lines terminated by CR, LF, or CRLF. Its response
lines are always terminated by CRLF.

When a connection is opened, the server responds by stating its protocol
version number with a line like "Click::ControlSocket/1.1". The current
version number is 1.1. Changes in minor version number will only add commands
and functionality to this specification, not change existing functionality.

ControlSocket supports hot-swapping, meaning you can change configurations
without interrupting existing clients. The hot-swap will succeed only if the
old ControlSocket and the new ControlSocket have the same element name, and
the same socket type and port/filename parameters. Additionally, the new
ControlSocket must have RETRIES set to 1 or more, since the old ControlSocket
has already bound the relevant socket.

Keyword arguments are:

=over 8

=item READONLY

Boolean.  Disallows write handlers if true (it is false by
default). 

=item PROXY

String. Specifies an element proxy. When a user requests the value of handler
E.H, ControlSocket will actually return the value of `PROXY.E.H'. This is
useful with elements like KernelHandlerProxy. Default is empty (no proxy).

=item VERBOSE

Boolean. When true, ControlSocket will print messages whenever it accepts a
new connection or drops an old one. Default is false.

=item RETRIES

Integer. If greater than 0, ControlSocket won't immediately fail when it can't
open its socket. Instead, it will attempt to open the socket once a second
until it succeeds, or until RETRIES unsuccessful attempts (after which it will
stop the router). Default is 0.

=item RETRY_WARNINGS

Boolean. If true, ControlSocket will print warning messages every time it
fails to open a socket. If false, it will print messages only on the final
failure. Default is true.

=back

=head1 SERVER COMMANDS

The server currently supports the following six commands. Many of the commands
take a I<handler> argument. These arguments name handlers, and take one of
three forms: C<I<elementname>.I<handlername>> names a particular element's
handler; C<I<elementnumber>.I<handlername>> also names an element handler, but
the element is identified by index, starting from 1; and C<I<handlername>>
names a global handler. (There are seven global read handlers, named
C<version>, C<list>, C<classes>, C<config>, C<flatconfig>, C<packages>, and
C<requirements>. See click.o(8) for more information.)

=over 5

=item READ I<handler> [I<params...>]

Call a read I<handler>, passing the I<params>, if any,
as arguments, and return the results.
On success, responds with a "success" message (response
code 2xy) followed by a line like "DATA I<n>". Here, I<n> is a
decimal integer indicating the length of the read handler data. The I<n>
bytes immediately following (the CRLF that terminates) the DATA line are
the handler's results.

=item WRITE I<handler> I<params...>

Call a write I<handler>, passing the I<params>, if any, as arguments.

=item WRITEDATA I<handler> I<n>

Call a write I<handler>. The arguments to pass are the I<n> bytes immediately
following (the CRLF that terminates) the WRITEDATA line.

=item CHECKREAD I<handler>

Checks whether a I<handler> exists and is readable. The return status is 200
for readable handlers, and an appropriate error status for non-readable
handlers or nonexistent handlers.

=item CHECKWRITE I<handler>

Checks whether a I<handler> exists and is writable.

=item LLRPC I<llrpc> [I<n>]

Call an LLRPC I<llrpc> and return the results. I<Llrpc> should have the form
C<I<element>#I<hexnumber>>. The C<I<hexnumber>> is the LLRPC number, from
C<E<lt>click/llrpc.hE<gt>>, in hexadecimal network format. Translate C<CLICK_LLRPC>
constants to network format by calling
C<CLICK_LLRPC_HTON(CLICK_LLRPC_...)>. If I<n> is given, then the I<n> bytes
immediately following (the CRLF that terminates) the LLRPC line are passed in
as an argument. The results are returned after a "DATA I<nn>" line, as in
READ.

ControlSocket will not call an LLRPC unless it can determine (from the command
number) how much data the LLRPC expects and returns. (Only "flat" LLRPCs may
be called; they are declared using the _CLICK_IOC_[RWS]F macros.)

=item QUIT

Close the connection.

=back

The server's response codes follow this pattern.

=over 5

=item 2xy
The command succeeded.

=item 5xy
The command failed.

=back

Here are some of the particular error messages:

  200 OK.
  220 OK, but the handler reported some warnings.
  500 Syntax error.
  501 Unimplemented command.
  510 No such element.
  511 No such handler.
  520 Handler error.
  530 Permission denied.
  540 No router installed.

ControlSocket is only available in user-level processes.

=e

  ControlSocket(unix, /tmp/clicksocket);

=a ChatterSocket, KernelHandlerProxy */

class ControlSocket : public Element { public:

  ControlSocket();
  ~ControlSocket();

  const char *class_name() const	{ return "ControlSocket"; }
  
  int configure(Vector<String> &conf, ErrorHandler *);
  int initialize(ErrorHandler *);
  void cleanup(CleanupStage);
  void take_state(Element *, ErrorHandler *);

  void selected(int);

  enum {
    CSERR_OK			= HandlerProxy::CSERR_OK,	       // 200
    CSERR_OK_HANDLER_WARNING	= 220,
    CSERR_SYNTAX		= HandlerProxy::CSERR_SYNTAX,          // 500
    CSERR_UNIMPLEMENTED		= 501,
    CSERR_NO_SUCH_ELEMENT	= HandlerProxy::CSERR_NO_SUCH_ELEMENT, // 510
    CSERR_NO_SUCH_HANDLER	= HandlerProxy::CSERR_NO_SUCH_HANDLER, // 511
    CSERR_HANDLER_ERROR		= HandlerProxy::CSERR_HANDLER_ERROR,   // 520
    CSERR_DATA_TOO_BIG		= 521,
    CSERR_LLRPC_ERROR		= 522,
    CSERR_PERMISSION		= HandlerProxy::CSERR_PERMISSION,      // 530
    CSERR_NO_ROUTER		= HandlerProxy::CSERR_NO_ROUTER,       // 540
    CSERR_UNSPECIFIED		= HandlerProxy::CSERR_UNSPECIFIED      // 590
  };
  
 private:

  String _unix_pathname;
  int _socket_fd;
  bool _read_only : 1;
  bool _verbose : 1;
  bool _retry_warnings : 1;
  bool _tcp_socket : 1;
  Element *_proxy;
  HandlerProxy *_full_proxy;
  
  Vector<String> _in_texts;
  Vector<String> _out_texts;
  Vector<int> _flags;
  
  String _proxied_handler;
  ErrorHandler *_proxied_errh;

  int _retries;
  Timer *_retry_timer;

  enum { READ_CLOSED = 1, WRITE_CLOSED = 2, ANY_ERR = -1 };

  static const char protocol_version[];

  int initialize_socket_error(ErrorHandler *, const char *);
  int initialize_socket(ErrorHandler *);
  static void retry_hook(Timer *, void *);
  
  int message(int fd, int code, const String &, bool continuation = false);
  int transfer_messages(int fd, int default_code, const String &first_message,
			ControlSocketErrorHandler *);
  
    String proxied_handler_name(const String &) const;
    const Handler* parse_handler(int fd, const String &, Element **);
    int read_command(int fd, const String &, const String &);
    int write_command(int fd, const String &, const String &);
    int check_command(int fd, const String &, bool write);
    int llrpc_command(int fd, const String &, String);
    int parse_command(int fd, const String &);
    void flush_write(int fd, bool read_needs_processing);

  int report_proxy_errors(int fd, const String &);
  static ErrorHandler *proxy_error_function(const String &, void *);

};

CLICK_ENDDECLS
#endif
