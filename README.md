# nikau

[![builds.sr.ht status](https://builds.sr.ht/~nickbp/nikau/commits/main/.build.yml.svg)](https://builds.sr.ht/~nickbp/nikau/commits/main/.build.yml)

```
\\ //
 \V/
  U
  |
  | nikau
```

TLS-encrypted server-client KVM software for sharing input devices across Linux machines.

## How it works

Nikau relies on the Linux uinput API, and supports Wayland, X11, and plain Linux consoles. OSX and Windows are not supported.

It is packaged as a single executable which supports both server and client modes.

The server is where the input devices are plugged in. The clients receive input events from the server, and emit them using virtual uinput devices.

When a key is pressed or mouse is moved on the server, Nikau will encode and send the event over the network to the currently enabled client (if any). That client will then write the event to a virtual device, to be picked up by the host OS.

Key combinations are used to rotate between machines. The default is `LeftAlt+N` to go to the next machine, or `LeftAlt+P` to go to the previous machine. This is customized using commandline arguments on the server.

## Getting started

1. Install nikau to each of your systems using one of these methods:.

    a. Stable release: `cargo install nikau`, and then use `~/.cargo/bin/nikau` to run the binary.

    b. Latest `main`: `git clone https://git.sr.ht/~nickbp/nikau && cd nikau && cargo build`, and then use `./target/debug/nikau` to run the binary.

    c. Docker image: `docker-server.sh` and `docker-client.sh` provide example `docker run` commands. Note that `--privileged` is required and this has security implications. Get a list of available tags (based on commit SHAs) from [here](https://github.com/users/nickbp/packages/container/package/nikau).

2. Run `nikau server` on your server machine
3. Run `nikau client <serverIP>` on your client machine(s)

When a client connects to a server for the first time, you will need to approve the certificate handshake on _both_ the server _and_ the client. Check the displayed `Server fingerprint` and `Client fingerprint` and confirm they look the same across the server and client machines. Similar to SSH, this manual approval process is only required for the first connection, after that the certificates are "known". You can check a server or client's cert fingerprint directly by running `sudo openssl x509 -noout -sha256 -fingerprint -in /root/.config/nikau/private.pem`.

Once things have connected, the server should log that it's added the client to its rotation, and the client should log that it's waiting to be activated. This is the default state, where input on the server is staying local to the server. The KVM isn't doing anything yet.

To send input from the server to the connected client(s), try pressing `LeftAlt+N` and `LeftAlt+P` to rotate forward and backward between clients and the server. For now, clients are simply ordered alphabetically by their IP/port. These shortcuts are configurable at the server. Another option is sending `SIGUSR1` and `SIGUSR2` signals to the server process, which will also trigger forward and backward rotation.

## Status

I'm using this on a regular basis. As such it should "just work". Email me if you're having problems.

The wire protocol is still unstable and may change between releases. For now, you should ensure that all servers and clients are running the same version.

Known shortcomings:
- Clipboards are not synced across devices. I would like support for this. Currently, Nikau doesn't have access to clipboard contents as it only interfaces with uinput, but if e.g. Wayland offers an interface for this then I don't think there's a problem supporting it.
- Nikau does not work on OSX or Windows, and I don't have any plans to add support for them.

## Security

**This software has NOT undergone any security review or audit. Use is at your own risk.** See also terms and conditions of the [licence](LICENCE.md).

Keep in mind that the purpose of this software is to essentially collect keystrokes and send them over the network to another machine. Whether this is acceptable is something that you must decide based on your context and use case.

_Assuming_ there aren't flagrant security flaws in either Nikau or the many underlying libraries that it depends upon, the communication containing user input data should be TLS-encrypted. Authentication follows a "prompt-once" model using self-signed server and client certificates. On the first connection, manual bidirectional approval is required on both the server and the client.

In order to have access to uinput devices, the client and server must both be run as root (e.g. via `sudo`).

## License

This project is [licensed](LICENCE.md) under the AGPLv3 and is copyright Nicholas Parker.
