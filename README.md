# ranch_noise

[Noise Protocol Framework](https://noiseprotocol.org/) transport adapter for [Ranch](https://github.com/ninenines/ranch).

Allows any Ranch-based protocol (e.g., Cowboy, MochiWeb) to run transparently over an encrypted Noise channel.

## Features

- Full integration with Ranch's transport API — drop-in replacement for `ranch_tcp` / `ranch_ssl`
- Supports all [Noise protocol patterns](https://noiseprotocol.org/noise.html) (e.g. `Noise_XX_25519_ChaChaPoly_BLAKE2b`)
- Passive, active, and active-once delivery modes
- Post-handshake socket API mirrors `gen_tcp` (`recv`/`send`/`setopts`/`peername`/etc.)
- Client convenience function `ranch_noise:connect/3,4`

## Requirements

- Erlang/OTP
- [ranch](https://github.com/ninenines/ranch) (transmission-layer dispatcher)
- [enoise](https://github.com/aeternity/enoise) (Noise Protocol reference implementation in Erlang)

## Installation

Add `ranch_noise` to your project dependencies in `rebar.config`:

```erlang
{deps, [
    ranch_noise
]}.
```

Or clone and compile:

```bash
$ rebar3 compile
```

## Usage

### Server

Start a Ranch listener using `ranch_noise` as the transport:

```erlang
%% Create keypairs for server and client.
ServerKP = enoise_keypair:new(dh25519),
ClientKP = enoise_keypair:new(dh25519),

%% Start listener — note the transport is `ranch_noise`.
NoiseOpts = [{noise, "Noise_XX_25519_ChaChaPoly_BLAKE2b"},
             {s, ServerKP}, {role, responder}],
{ok, _} = ranch:start_listener(my_listener, ranch_noise,
    #{socket_opts => [{port, 8765}],
      num_acceptors => 2,
      handshake_timeout => 5000},
    my_protocol, #{noise_opts => NoiseOpts}).
```

Inside the Ranch protocol handler, perform the Noise handshake:

```erlang
start_link(Ref, Transport, #{noise_opts := NoiseOpts}) ->
    Pid = spawn_link(fun() -> init(Ref, Transport, NoiseOpts) end),
    {ok, Pid}.

init(Ref, Transport, NoiseOpts) ->
    {ok, Socket} = ranch:handshake(Ref, NoiseOpts),
    %% Socket is now a noise-encrypted handle — use Transport:recv/3
    %% and Transport:send/2 as normal.
    loop(Socket, Transport).
```

### Client

```erlang
{ok, Sock} = ranch_noise:connect("127.0.0.1", 8765,
    [{noise, "Noise_XX_25519_ChaChaPoly_BLAKE2b"},
     {s, ClientKP}, {role, initiator}],
    5000).

%% Send / recv work exactly like gen_tcp after the handshake.
ok = ranch_noise:send(Sock, <<"hello">>),
{ok, <<"hello">>} = ranch_noise:recv(Sock, 0, 5000).
```

### Socket type transitions

| Phase | Socket type |
|-------|------------|
| Before handshake | `inet:socket()` — raw TCP managed by Ranch |
| After handshake | `pid()` — `ranch_noise_socket` gen_server holding Noise CipherState |

### Active mode

Set `active` options post-handshake to receive encrypted messages as messages:

```erlang
%% Passive (default) — call recv/3 to pull data.
%% Active once — one {noise, Socket, Data} message, then reverts to passive.
ok = ranch_noise:setopts(Sock, [{active, once}]),

%% Active — every decrypted message delivered immediately.
ok = ranch_noise:setopts(Sock, [{active, true}]),

%% Messages arrive as:
%%   {noise, Socket, Data}
%%   {noise_closed, Socket}
%%   {noise_error, Socket, Reason}
```

## Running tests

```bash
$ rebar3 eunit
```

## License

Apache-2.0
