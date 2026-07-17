%% @doc Ranch transport adapter for the Noise Protocol Framework.
%%
%% This module implements the `ranch_transport' behaviour, allowing any
%% Ranch-based protocol to run transparently over a Noise encrypted channel.
%%
%% Usage (server side):
%%
%%   {ok, _} = ranch:start_listener(my_listener, ranch_noise,
%%       #{socket_opts => [{port, 8765}]},
%%       my_protocol, #{}).
%%
%%   %% Inside the protocol handler:
%%   NoiseOpts = [{noise, "Noise_XX_25519_ChaChaPoly_BLAKE2b"},
%%                {s, ServerKeypair}, {role, responder}],
%%   {ok, Socket} = ranch:handshake(Ref, NoiseOpts),
%%   %% use Transport:recv/send/setopts as normal
%%
%% Usage (client side):
%%
%%   {ok, Socket} = ranch_noise:connect("host", 8765,
%%       [{noise, "Noise_XX_25519_ChaChaPoly_BLAKE2b"}, {s, ClientKP}]).
%%
%% Socket type transitions:
%%   Before handshake : inet:socket()  (raw TCP, managed by Ranch internals)
%%   After  handshake : pid()          (ranch_noise_socket gen_server)
%%
%% The socket option {packet, 2} is forced on all TCP sockets so the TCP
%% stack handles the 2-byte length framing that Noise messages require.
-module(ranch_noise).
-behaviour(ranch_transport).

-export([name/0]).
-export([secure/0]).
-export([messages/0]).
-export([listen/1]).
-export([accept/2]).
-export([handshake/2]).
-export([handshake/3]).
-export([handshake_continue/2]).
-export([handshake_continue/3]).
-export([handshake_cancel/1]).
-export([connect/3]).
-export([connect/4]).
-export([recv/3]).
-export([recv_proxy_header/2]).
-export([send/2]).
-export([sendfile/2]).
-export([sendfile/4]).
-export([sendfile/5]).
-export([setopts/2]).
-export([getopts/2]).
-export([getstat/1]).
-export([getstat/2]).
-export([controlling_process/2]).
-export([peername/1]).
-export([sockname/1]).
-export([shutdown/2]).
-export([close/1]).
-export([cleanup/1]).
-export([format_error/1]).

%% Socket options forwarded to gen_tcp (subset of ranch_tcp opts).
-type opt() ::
      {backlog,              non_neg_integer()}
    | {buffer,               non_neg_integer()}
    | {delay_send,           boolean()}
    | {dontroute,            boolean()}
    | {exit_on_close,        boolean()}
    | {fd,                   non_neg_integer()}
    | {high_msgq_watermark,  non_neg_integer()}
    | {high_watermark,       non_neg_integer()}
    | inet | inet6
    | {ip,                   inet:ip_address() | inet:local_address()}
    | {ipv6_v6only,          boolean()}
    | {keepalive,            boolean()}
    | {linger,               {boolean(), non_neg_integer()}}
    | {low_msgq_watermark,   non_neg_integer()}
    | {low_watermark,        non_neg_integer()}
    | {nodelay,              boolean()}
    | {port,                 inet:port_number()}
    | {priority,             integer()}
    | {raw,                  non_neg_integer(), non_neg_integer(), binary()}
    | {recbuf,               non_neg_integer()}
    | {send_timeout,         timeout()}
    | {send_timeout_close,   boolean()}
    | {sndbuf,               non_neg_integer()}
    | {tos,                  integer()}.

%% Options passed to ranch:handshake(Ref, NoiseOpts) by the protocol handler.
-type noise_opt() ::
      {noise,    string() | binary() | enoise_protocol:protocol()}
    | {s,        enoise_keypair:keypair()}
    | {e,        enoise_keypair:keypair()}
    | {rs,       binary()}
    | {re,       binary()}
    | {prologue, binary()}
    | {role,     initiator | responder}.

-export_type([opt/0, noise_opt/0]).

%% Options we strip from socket_opts before passing to gen_tcp:listen/2.
%% We force our own values for these.
-define(DISALLOWED, [active, header, mode, packet, packet_size,
                     line_delimiter, reuseaddr]).

%%====================================================================
%% Transport identification
%%====================================================================

-spec name() -> noise.
name() -> noise.

-spec secure() -> true.
secure() -> true.

%% Messages emitted in active mode: {noise, Socket, Data},
%% {noise_closed, Socket}, {noise_error, Socket, Reason},
%% {noise_passive, Socket}.
-spec messages() -> {noise, noise_closed, noise_error, noise_passive}.
messages() -> {noise, noise_closed, noise_error, noise_passive}.

%%====================================================================
%% Listen / Accept
%%====================================================================

-spec listen(ranch:transport_opts(any())) -> {ok, inet:socket()} | {error, atom()}.
listen(TransOpts) ->
    Logger     = maps:get(logger, TransOpts, logger),
    SocketOpts = maps:get(socket_opts, TransOpts, []),
    Opts0 = ranch:set_option_default(SocketOpts, backlog, 1024),
    Opts1 = ranch:set_option_default(Opts0, nodelay, true),
    Opts2 = ranch:set_option_default(Opts1, send_timeout, 30000),
    Opts3 = ranch:set_option_default(Opts2, send_timeout_close, true),
    %% Force: {packet,2} for Noise framing, binary mode, passive, reuse addr.
    Forced   = [binary, {active, false}, {reuseaddr, true}, {packet, 2}],
    Filtered = ranch:filter_options(Opts3, ?DISALLOWED, Forced, Logger),
    gen_tcp:listen(0, Filtered).

-spec accept(inet:socket(), timeout())
    -> {ok, inet:socket()} | {error, closed | timeout | atom()}.
accept(ListenSock, Timeout) ->
    gen_tcp:accept(ListenSock, Timeout).

%%====================================================================
%% Noise Handshake
%%====================================================================

%% Called by Ranch when no options are passed to ranch:handshake/1.
%% Noise is impossible without at least {noise, Protocol} and {s, Keypair}.
-spec handshake(inet:socket(), timeout())
    -> {error, {missing_noise_opts, use_ranch_handshake_with_opts}}.
handshake(_Socket, _Timeout) ->
    {error, {missing_noise_opts, use_ranch_handshake_with_opts}}.

%% Called by Ranch when the protocol calls ranch:handshake(Ref, NoiseOpts).
%% Performs the Noise handshake over the raw TCP socket and returns a
%% ranch_noise_socket pid as the upgraded socket handle.
-spec handshake(inet:socket(), [noise_opt()], timeout())
    -> {ok, pid()} | {error, any()}.
handshake(TcpSock, NoiseOpts, Timeout) ->
    %% Ensure passive + 2-byte framing before the handshake exchange.
    ok = inet:setopts(TcpSock, [{active, false}, {packet, 2}]),
    Role       = proplists:get_value(role, NoiseOpts, responder),
    EnoiseOpts = proplists:delete(role, NoiseOpts),
    %% Inject the handshake timeout so enoise respects the Ranch deadline.
    Opts = [{timeout, Timeout} | proplists:delete(timeout, EnoiseOpts)],
    ComState   = make_com_state(TcpSock),
    case enoise:handshake(Opts, Role, ComState) of
        {ok, #{rx := Rx, tx := Tx}, _} ->
            ranch_noise_socket:start_link(TcpSock, Rx, Tx, self());
        {error, _} = Err ->
            Err
    end.

-spec handshake_continue(pid(), timeout()) -> {ok, pid()}.
handshake_continue(Socket, _Timeout) -> {ok, Socket}.

-spec handshake_continue(pid(), [noise_opt()], timeout()) -> {ok, pid()}.
handshake_continue(Socket, _Opts, _Timeout) -> {ok, Socket}.

-spec handshake_cancel(pid()) -> ok.
handshake_cancel(_Socket) -> ok.

%%====================================================================
%% Client-side connect
%%====================================================================

-spec connect(inet:hostname() | inet:ip_address(), inet:port_number(),
              [noise_opt()])
    -> {ok, pid()} | {error, any()}.
connect(Host, Port, NoiseOpts) ->
    connect(Host, Port, NoiseOpts, infinity).

-spec connect(inet:hostname() | inet:ip_address(), inet:port_number(),
              [noise_opt()], timeout())
    -> {ok, pid()} | {error, any()}.
connect(Host, Port, NoiseOpts, Timeout) ->
    TcpOpts = [binary, {packet, 2}, {active, false}],
    case gen_tcp:connect(Host, Port, TcpOpts, Timeout) of
        {ok, TcpSock} ->
            Opts = case proplists:is_defined(role, NoiseOpts) of
                true  -> NoiseOpts;
                false -> [{role, initiator} | NoiseOpts]
            end,
            case handshake(TcpSock, Opts, Timeout) of
                {ok, _} = Ok ->
                    Ok;
                {error, _} = Err ->
                    gen_tcp:close(TcpSock),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%%====================================================================
%% Data I/O  (post-handshake, socket is a ranch_noise_socket pid)
%%====================================================================

-spec recv(pid(), non_neg_integer(), timeout())
    -> {ok, binary()} | {error, closed | timeout | atom()}.
recv(Sock, Len, Timeout) ->
    ranch_noise_socket:recv(Sock, Len, Timeout).

-spec send(pid(), iodata()) -> ok | {error, atom()}.
send(Sock, Data) ->
    ranch_noise_socket:send(Sock, Data).

-spec sendfile(pid(), file:name_all() | file:fd())
    -> {ok, non_neg_integer()} | {error, atom()}.
sendfile(Sock, File) ->
    sendfile(Sock, File, 0, 0, []).

-spec sendfile(pid(), file:name_all() | file:fd(),
               non_neg_integer(), non_neg_integer())
    -> {ok, non_neg_integer()} | {error, atom()}.
sendfile(Sock, File, Offset, Bytes) ->
    sendfile(Sock, File, Offset, Bytes, []).

%% Noise messages must be individually encrypted, so sendfile falls back to
%% the generic chunk-based implementation from ranch_transport.
-spec sendfile(pid(), file:name_all() | file:fd(),
               non_neg_integer(), non_neg_integer(),
               ranch_transport:sendfile_opts())
    -> {ok, non_neg_integer()} | {error, atom()}.
sendfile(Sock, File, Offset, Bytes, Opts) ->
    ranch_transport:sendfile(?MODULE, Sock, File, Offset, Bytes, Opts).

-spec recv_proxy_header(any(), timeout())
    -> {ok, ranch_proxy_header:proxy_info()}
     | {error, closed | atom()}
     | {error, protocol_error, atom()}.
recv_proxy_header(_Sock, _Timeout) ->
    {error, not_supported}.

%%====================================================================
%% Socket options / info
%%====================================================================

%% All socket-option / info callbacks handle both socket types:
%%   pid()        → post-handshake noise socket (delegate to gen_server)
%%   inet:socket()→ pre-handshake / listen socket (delegate to inet/gen_tcp)

-spec setopts(inet:socket() | pid(), list()) -> ok | {error, atom()}.
setopts(Sock, Opts) when is_pid(Sock) ->
    ranch_noise_socket:setopts(Sock, Opts);
setopts(Sock, Opts) ->
    inet:setopts(Sock, Opts).

-spec getopts(inet:socket() | pid(), [atom()]) -> {ok, list()} | {error, atom()}.
getopts(Sock, Names) when is_pid(Sock) ->
    ranch_noise_socket:getopts(Sock, Names);
getopts(Sock, Names) ->
    inet:getopts(Sock, Names).

-spec getstat(inet:socket() | pid()) -> {ok, list()} | {error, atom()}.
getstat(Sock) when is_pid(Sock) ->
    ranch_noise_socket:getstat(Sock);
getstat(Sock) ->
    inet:getstat(Sock).

-spec getstat(inet:socket() | pid(), [atom()]) -> {ok, list()} | {error, atom()}.
getstat(Sock, Stats) when is_pid(Sock) ->
    ranch_noise_socket:getstat(Sock, Stats);
getstat(Sock, Stats) ->
    inet:getstat(Sock, Stats).

-spec controlling_process(inet:socket() | pid(), pid())
    -> ok | {error, closed | not_owner | atom()}.
controlling_process(Sock, Pid) when is_pid(Sock) ->
    ranch_noise_socket:controlling_process(Sock, Pid);
controlling_process(Sock, Pid) ->
    gen_tcp:controlling_process(Sock, Pid).

-spec peername(inet:socket() | pid())
    -> {ok, {inet:ip_address(), inet:port_number()} | {local, binary()}}
     | {error, atom()}.
peername(Sock) when is_pid(Sock) ->
    ranch_noise_socket:peername(Sock);
peername(Sock) ->
    inet:peername(Sock).

-spec sockname(inet:socket() | pid())
    -> {ok, {inet:ip_address(), inet:port_number()} | {local, binary()}}
     | {error, atom()}.
sockname(Sock) when is_pid(Sock) ->
    ranch_noise_socket:sockname(Sock);
sockname(Sock) ->
    inet:sockname(Sock).

-spec shutdown(inet:socket() | pid(), read | write | read_write)
    -> ok | {error, atom()}.
shutdown(Sock, How) when is_pid(Sock) ->
    ranch_noise_socket:shutdown(Sock, How);
shutdown(Sock, How) ->
    gen_tcp:shutdown(Sock, How).

%% Close works on both raw TCP sockets (pre-handshake) and noise sockets.
-spec close(inet:socket() | pid()) -> ok.
close(Sock) when is_pid(Sock) ->
    ranch_noise_socket:close(Sock);
close(Sock) ->
    gen_tcp:close(Sock).

-spec cleanup(ranch:transport_opts(any())) -> ok.
cleanup(_TransOpts) -> ok.

-spec format_error(term()) -> string().
format_error(Reason) ->
    lists:flatten(io_lib:format("~p", [Reason])).

%%====================================================================
%% Internal helpers
%%====================================================================

%% Build the enoise communication state backed by a passive TCP socket
%% with {packet, 2}, so each call to recv_msg/send_msg transfers exactly
%% one complete Noise message frame.
make_com_state(TcpSock) ->
    #{
        recv_msg => fun(Sock, T) ->
            case gen_tcp:recv(Sock, 0, T) of
                {ok, Data}       -> {ok, Data, Sock};
                {error, _} = Err -> Err
            end
        end,
        send_msg => fun(Sock, Data) ->
            case gen_tcp:send(Sock, Data) of
                ok               -> {ok, Sock};
                {error, _} = Err -> Err
            end
        end,
        state => TcpSock
    }.
