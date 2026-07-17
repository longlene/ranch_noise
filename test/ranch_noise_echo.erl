%% Simple echo protocol used in tests.
%% Accepts a Noise handshake, then echoes every received message back.
-module(ranch_noise_echo).
-behaviour(ranch_protocol).

-export([start_link/3]).

start_link(Ref, Transport, Opts) ->
    Pid = spawn_link(fun() -> init(Ref, Transport, Opts) end),
    {ok, Pid}.

init(Ref, Transport, #{noise_opts := NoiseOpts}) ->
    {ok, Socket} = ranch:handshake(Ref, NoiseOpts),
    loop(Socket, Transport).

loop(Socket, Transport) ->
    case Transport:recv(Socket, 0, 10000) of
        {ok, Data} ->
            ok = Transport:send(Socket, Data),
            loop(Socket, Transport);
        {error, closed} ->
            ok;
        {error, _Reason} ->
            Transport:close(Socket)
    end.
