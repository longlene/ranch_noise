%% @doc Per-connection gen_server that holds Noise CipherState.
%%
%% After the Noise handshake completes, ranch_noise:handshake/3 starts one
%% of these processes and returns its pid as the "socket" handle.  All
%% subsequent Transport:recv/send/setopts/... calls are routed here.
%%
%% The underlying TCP socket is kept with {packet, 2} so the kernel
%% automatically handles the 2-byte length framing of Noise messages.
%%
%% Active-mode delivery:
%%   active=true       - every decrypted message is sent to owner immediately
%%   active={once,_}   - one message is delivered, then reverts to passive
%%   active=false      - data is buffered; only delivered via recv/3 calls
%%
%% Passive recv/3:
%%   If msg_buf is non-empty the call returns immediately.
%%   Otherwise the call stores the caller and a timeout timer; the reply is
%%   sent asynchronously when the next TCP frame arrives.
-module(ranch_noise_socket).
-behaviour(gen_server).

%% Public API
-export([start_link/4]).
-export([recv/3]).
-export([send/2]).
-export([close/1]).
-export([shutdown/2]).
-export([setopts/2]).
-export([getopts/2]).
-export([getstat/1]).
-export([getstat/2]).
-export([controlling_process/2]).
-export([peername/1]).
-export([sockname/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

-record(state, {
    tcp_sock  :: inet:socket() | closed,
    rx        :: enoise_cipher_state:state(),
    tx        :: enoise_cipher_state:state(),
    owner     :: pid(),
    owner_ref :: reference(),
    %% false | true | {once, Delivered::boolean()}
    active = false :: false | true | {once, boolean()},
    %% Decrypted messages waiting to be delivered.
    msg_buf = [] :: [binary()],
    %% Set while a recv/3 call is blocking: {From, TimerRef | undefined}.
    recv_from = undefined :: undefined | {gen_server:from(), reference() | undefined}
}).

%%====================================================================
%% Public API
%%====================================================================

%% Start the gen_server and transfer TCP socket ownership to it.
%% Must be called from the process that currently owns TcpSock.
-spec start_link(inet:socket(),
                 enoise_cipher_state:state(),
                 enoise_cipher_state:state(),
                 pid()) -> {ok, pid()} | {error, any()}.
start_link(TcpSock, Rx, Tx, Owner) ->
    case gen_server:start_link(?MODULE, [TcpSock, Rx, Tx, Owner], []) of
        {ok, Pid} ->
            case gen_tcp:controlling_process(TcpSock, Pid) of
                ok ->
                    %% Forward any TCP messages that arrived in the caller's
                    %% mailbox between gen_server start and ownership transfer.
                    flush_tcp(Pid, TcpSock),
                    %% Signal gen_server to activate the socket now that it
                    %% owns it.
                    Pid ! activate,
                    {ok, Pid};
                {error, _} = Err ->
                    gen_server:stop(Pid),
                    Err
            end;
        Err ->
            Err
    end.

-spec recv(pid(), non_neg_integer(), timeout())
    -> {ok, binary()} | {error, closed | timeout | atom()}.
recv(Pid, _Len, Timeout) ->
    CallTimeout = case Timeout of
        infinity -> infinity;
        T        -> T + 1000
    end,
    gen_server:call(Pid, {recv, Timeout}, CallTimeout).

-spec send(pid(), iodata()) -> ok | {error, atom()}.
send(Pid, Data) ->
    gen_server:call(Pid, {send, iolist_to_binary(Data)}).

-spec close(pid()) -> ok.
close(Pid) ->
    try gen_server:call(Pid, close, 5000)
    catch exit:_ -> ok
    end.

-spec shutdown(pid(), read | write | read_write) -> ok | {error, atom()}.
shutdown(Pid, How) ->
    gen_server:call(Pid, {shutdown, How}).

-spec setopts(pid(), list()) -> ok | {error, atom()}.
setopts(Pid, Opts) ->
    gen_server:call(Pid, {setopts, Opts}).

-spec getopts(pid(), [atom()]) -> {ok, list()} | {error, atom()}.
getopts(Pid, Names) ->
    gen_server:call(Pid, {getopts, Names}).

-spec getstat(pid()) -> {ok, list()} | {error, atom()}.
getstat(Pid) ->
    gen_server:call(Pid, getstat).

-spec getstat(pid(), [atom()]) -> {ok, list()} | {error, atom()}.
getstat(Pid, Stats) ->
    gen_server:call(Pid, {getstat, Stats}).

-spec controlling_process(pid(), pid()) -> ok | {error, not_owner | atom()}.
controlling_process(Pid, NewOwner) ->
    gen_server:call(Pid, {controlling_process, self(), NewOwner}).

-spec peername(pid())
    -> {ok, {inet:ip_address(), inet:port_number()} | {local, binary()}}
     | {error, atom()}.
peername(Pid) ->
    gen_server:call(Pid, peername).

-spec sockname(pid())
    -> {ok, {inet:ip_address(), inet:port_number()} | {local, binary()}}
     | {error, atom()}.
sockname(Pid) ->
    gen_server:call(Pid, sockname).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([TcpSock, Rx, Tx, Owner]) ->
    %% Monitor the owner so we clean up when it exits normally.
    %% The start_link also creates a link for abnormal exits.
    OwnerRef = erlang:monitor(process, Owner),
    {ok, #state{
        tcp_sock  = TcpSock,
        rx        = Rx,
        tx        = Tx,
        owner     = Owner,
        owner_ref = OwnerRef
    }}.

%% ---- close -----------------------------------------------------------

handle_call(close, _From, S) ->
    {stop, normal, ok, S};

%% ---- recv ------------------------------------------------------------

handle_call({recv, _Timeout}, _From,
            S = #state{tcp_sock = closed, msg_buf = []}) ->
    {reply, {error, closed}, S};

handle_call({recv, _Timeout}, _From,
            S = #state{msg_buf = [Msg | Rest]}) ->
    {reply, {ok, Msg}, S#state{msg_buf = Rest}};

handle_call({recv, Timeout}, From,
            S = #state{msg_buf = [], tcp_sock = TcpSock}) ->
    TRef = start_recv_timer(Timeout, From),
    %% Arm the socket so we get the next frame.
    inet:setopts(TcpSock, [{active, once}]),
    {noreply, S#state{recv_from = {From, TRef}}};

%% ---- send ------------------------------------------------------------

handle_call({send, _Data}, _From, S = #state{tcp_sock = closed}) ->
    {reply, {error, closed}, S};

handle_call({send, Data}, _From,
            S = #state{tcp_sock = TcpSock, tx = Tx}) ->
    {ok, Tx1, CipherText} = enoise_cipher_state:encrypt_with_ad(Tx, <<>>, Data),
    %% gen_tcp with {packet,2} automatically prepends <<byte_size(CipherText):16>>.
    Res = gen_tcp:send(TcpSock, CipherText),
    {reply, Res, S#state{tx = Tx1}};

%% ---- setopts ---------------------------------------------------------

handle_call({setopts, Opts}, _From, S) ->
    S1 = do_setopts(S, Opts),
    {reply, ok, S1};

%% ---- controlling_process ---------------------------------------------

handle_call({controlling_process, OldPid, NewPid}, _From,
            S = #state{owner = OldPid, owner_ref = ORef}) ->
    erlang:demonitor(ORef, [flush]),
    NewRef = erlang:monitor(process, NewPid),
    {reply, ok, S#state{owner = NewPid, owner_ref = NewRef}};

handle_call({controlling_process, _Wrong, _NewPid}, _From, S) ->
    {reply, {error, not_owner}, S};

%% ---- misc ------------------------------------------------------------

handle_call({shutdown, How}, _From, S = #state{tcp_sock = TcpSock}) ->
    {reply, gen_tcp:shutdown(TcpSock, How), S};

handle_call({getopts, Names}, _From, S = #state{tcp_sock = TcpSock}) ->
    {reply, inet:getopts(TcpSock, Names), S};

handle_call(getstat, _From, S = #state{tcp_sock = TcpSock}) ->
    {reply, inet:getstat(TcpSock), S};

handle_call({getstat, Stats}, _From, S = #state{tcp_sock = TcpSock}) ->
    {reply, inet:getstat(TcpSock, Stats), S};

handle_call(peername, _From, S = #state{tcp_sock = TcpSock}) ->
    {reply, inet:peername(TcpSock), S};

handle_call(sockname, _From, S = #state{tcp_sock = TcpSock}) ->
    {reply, inet:sockname(TcpSock), S};

handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast(_Msg, S) ->
    {noreply, S}.

%% ---- TCP data --------------------------------------------------------

handle_info({tcp, TcpSock, CipherText},
            S = #state{tcp_sock = TcpSock, rx = Rx}) ->
    case enoise_cipher_state:decrypt_with_ad(Rx, <<>>, CipherText) of
        {ok, Rx1, PlainText} ->
            S1 = S#state{rx = Rx1,
                         msg_buf = S#state.msg_buf ++ [PlainText]},
            S2 = try_deliver(S1),
            S3 = maybe_reactivate(S2),
            {noreply, S3};
        {error, Reason} ->
            %% Decryption failure – notify owner and stop.
            reply_recv({error, {decrypt_failed, Reason}}, S),
            notify_error(S, {decrypt_failed, Reason}),
            {stop, normal, S#state{tcp_sock = closed}}
    end;

handle_info({tcp_closed, TcpSock}, S = #state{tcp_sock = TcpSock}) ->
    reply_recv({error, closed}, S),
    notify_closed(S),
    {noreply, S#state{tcp_sock = closed}};

handle_info({tcp_error, TcpSock, Reason}, S = #state{tcp_sock = TcpSock}) ->
    reply_recv({error, Reason}, S),
    notify_error(S, Reason),
    {noreply, S#state{tcp_sock = closed}};

%% ---- activate --------------------------------------------------------

%% Sent by start_link/4 after ownership transfer.
handle_info(activate, S = #state{tcp_sock = TcpSock}) ->
    inet:setopts(TcpSock, [{active, once}]),
    {noreply, S};

%% ---- recv timeout ----------------------------------------------------

handle_info({recv_timeout, From}, S = #state{recv_from = {From, _}}) ->
    gen_server:reply(From, {error, timeout}),
    {noreply, S#state{recv_from = undefined}};

handle_info({recv_timeout, _}, S) ->
    {noreply, S};

%% ---- owner down ------------------------------------------------------

handle_info({'DOWN', ORef, process, _, _},
            S = #state{owner_ref = ORef}) ->
    {stop, normal, S};

handle_info(_Msg, S) ->
    {noreply, S}.

terminate(_Reason, #state{tcp_sock = TcpSock, owner_ref = ORef}) ->
    case TcpSock of
        closed -> ok;
        Sock   -> catch gen_tcp:close(Sock)
    end,
    case ORef of
        undefined -> ok;
        Ref       -> erlang:demonitor(Ref, [flush])
    end,
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal helpers
%%====================================================================

%% Attempt to deliver buffered messages to whoever is waiting.
try_deliver(S = #state{recv_from = {From, TRef},
                       msg_buf   = [Msg | Rest]}) ->
    cancel_timer(TRef),
    gen_server:reply(From, {ok, Msg}),
    S#state{recv_from = undefined, msg_buf = Rest};

try_deliver(S = #state{active = true, msg_buf = Msgs})
        when Msgs =/= [] ->
    Sock = self(),
    Owner = S#state.owner,
    [Owner ! {noise, Sock, Msg} || Msg <- Msgs],
    S#state{msg_buf = []};

try_deliver(S = #state{active   = {once, false},
                       msg_buf  = [Msg | Rest]}) ->
    S#state.owner ! {noise, self(), Msg},
    S#state{active = {once, true}, msg_buf = Rest};

try_deliver(S) ->
    S.

%% Re-arm {active, once} on the underlying TCP socket when more data
%% is expected (a blocking recv is pending, or active mode wants it).
maybe_reactivate(S = #state{tcp_sock = closed}) ->
    S;
maybe_reactivate(S = #state{tcp_sock    = TcpSock,
                             recv_from   = RF,
                             active      = Active,
                             msg_buf     = Buf}) ->
    NeedMore = (RF =/= undefined andalso Buf =:= [])
        orelse Active =:= true
        orelse Active =:= {once, false},
    NeedMore andalso inet:setopts(TcpSock, [{active, once}]),
    S.

%% Apply a list of socket options, handling {active, _} specially.
do_setopts(S, []) ->
    S;
do_setopts(S, [{active, true} | Rest]) ->
    S1 = S#state{active = true},
    S2 = try_deliver(S1),
    S3 = maybe_reactivate(S2),
    do_setopts(S3, Rest);
do_setopts(S, [{active, once} | Rest]) ->
    S1 = S#state{active = {once, false}},
    S2 = try_deliver(S1),
    S3 = maybe_reactivate(S2),
    do_setopts(S3, Rest);
do_setopts(S, [{active, false} | Rest]) ->
    do_setopts(S#state{active = false}, Rest);
do_setopts(S, [_ | Rest]) ->
    %% Silently ignore unrecognised options (e.g. TCP-level opts that
    %% callers may pass generically).
    do_setopts(S, Rest).

%% Reply to a blocked recv/3 call, if any.
reply_recv(Reply, #state{recv_from = {From, TRef}}) ->
    cancel_timer(TRef),
    gen_server:reply(From, Reply);
reply_recv(_Reply, _S) ->
    ok.

%% Deliver a closed/error notification to the owner in active mode.
notify_closed(#state{owner = Owner, active = A}) when A =/= false ->
    Owner ! {noise_closed, self()};
notify_closed(_) ->
    ok.

notify_error(#state{owner = Owner, active = A}, Reason) when A =/= false ->
    Owner ! {noise_error, self(), Reason};
notify_error(_, _) ->
    ok.

start_recv_timer(infinity, _From) ->
    undefined;
start_recv_timer(Timeout, From) ->
    erlang:send_after(Timeout, self(), {recv_timeout, From}).

cancel_timer(undefined) -> ok;
cancel_timer(TRef)      -> erlang:cancel_timer(TRef).

%% Drain any {tcp, Sock, Data} messages that landed in the caller's
%% mailbox between gen_server:start_link and gen_tcp:controlling_process.
flush_tcp(Pid, TcpSock) ->
    receive
        {tcp, TcpSock, Data} ->
            Pid ! {tcp, TcpSock, Data},
            flush_tcp(Pid, TcpSock)
    after 0 ->
        ok
    end.
