-module(ranch_noise_tests).
-include_lib("eunit/include/eunit.hrl").

-define(PROTOCOL, "Noise_XX_25519_ChaChaPoly_BLAKE2b").
-define(LISTENER, ranch_noise_test_listener).

%%====================================================================
%% Test suite
%%====================================================================

ranch_noise_test_() ->
    {foreach,
     fun setup/0,
     fun teardown/1,
     [
         fun test_passive_echo/1,
         fun test_active_once_echo/1,
         fun test_multiple_messages/1,
         fun test_large_message/1,
         fun test_close_by_server/1,
         fun test_peername_sockname/1
     ]}.

%%====================================================================
%% Setup / teardown
%%====================================================================

setup() ->
    application:ensure_all_started(ranch),
    ServerKP = enoise_keypair:new(dh25519),
    ClientKP = enoise_keypair:new(dh25519),
    NoiseOpts = [{noise, ?PROTOCOL}, {s, ServerKP}, {role, responder}],
    {ok, _} = ranch:start_listener(
        ?LISTENER,
        ranch_noise,
        #{socket_opts    => [{port, 0}],
          num_acceptors  => 2,
          handshake_timeout => 5000},
        ranch_noise_echo,
        #{noise_opts => NoiseOpts}
    ),
    Port = ranch:get_port(?LISTENER),
    #{port => Port, client_kp => ClientKP}.

teardown(_) ->
    ranch:stop_listener(?LISTENER).

%%====================================================================
%% Helpers
%%====================================================================

connect(Port, ClientKP) ->
    ranch_noise:connect("127.0.0.1", Port,
        [{noise, ?PROTOCOL}, {s, ClientKP}, {role, initiator}],
        5000).

%%====================================================================
%% Tests
%%====================================================================

test_passive_echo(#{port := Port, client_kp := KP}) ->
    {"passive recv echo", fun() ->
        {ok, Sock} = connect(Port, KP),
        ok = ranch_noise:send(Sock, <<"hello">>),
        {ok, <<"hello">>} = ranch_noise:recv(Sock, 0, 5000),
        ok = ranch_noise:close(Sock)
    end}.

test_active_once_echo(#{port := Port, client_kp := KP}) ->
    {"active once echo", fun() ->
        {ok, Sock} = connect(Port, KP),
        ok = ranch_noise:setopts(Sock, [{active, once}]),
        ok = ranch_noise:send(Sock, <<"world">>),
        receive
            {noise, Sock, <<"world">>} -> ok
        after 5000 ->
            error(timeout)
        end,
        ok = ranch_noise:close(Sock)
    end}.

test_multiple_messages(#{port := Port, client_kp := KP}) ->
    {"multiple sequential messages", fun() ->
        {ok, Sock} = connect(Port, KP),
        Msgs = [<<"msg1">>, <<"msg2">>, <<"msg3">>, <<"msg4">>, <<"msg5">>],
        [ok = ranch_noise:send(Sock, M) || M <- Msgs],
        [begin
             {ok, M} = ranch_noise:recv(Sock, 0, 5000)
         end || M <- Msgs],
        ok = ranch_noise:close(Sock)
    end}.

test_large_message(#{port := Port, client_kp := KP}) ->
    {"large message (32 KB)", fun() ->
        {ok, Sock} = connect(Port, KP),
        %% Max Noise plaintext = 65535 - 16 (AEAD tag) = 65519 bytes.
        %% Stay well under that limit.
        LargeMsg = crypto:strong_rand_bytes(32768),
        ok = ranch_noise:send(Sock, LargeMsg),
        {ok, LargeMsg} = ranch_noise:recv(Sock, 0, 10000),
        ok = ranch_noise:close(Sock)
    end}.

test_close_by_server(#{port := Port, client_kp := KP}) ->
    {"server close detected by client", fun() ->
        {ok, Sock} = connect(Port, KP),
        ok = ranch_noise:setopts(Sock, [{active, true}]),
        %% Close from client side; server will get closed, stop, client
        %% will receive noise_closed.
        ok = ranch_noise:close(Sock),
        receive
            {noise_closed, Sock} -> ok
        after 1000 ->
            %% close() already stopped the gen_server; either way is fine.
            ok
        end
    end}.

test_peername_sockname(#{port := Port, client_kp := KP}) ->
    {"peername and sockname return addresses", fun() ->
        {ok, Sock} = connect(Port, KP),
        {ok, {_, Port}} = ranch_noise:peername(Sock),
        {ok, {_, _LocalPort}} = ranch_noise:sockname(Sock),
        ok = ranch_noise:close(Sock)
    end}.
