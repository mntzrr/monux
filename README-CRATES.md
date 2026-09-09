# monux

```
\\ //
 \V/
  U
  |
  | monux
```

TLS-encrypted server-client KVM software for sharing input devices and clipboards across machines.

The server (the machine with the physical input devices) runs on Linux, relying on the uinput/evdev APIs: keyboards, mice, and touchpads across Wayland, X11, and even bare Linux consoles. Clients (the controlled machines) run on Linux with the same device coverage, or on macOS (Apple Silicon) with keyboard and mouse input via CGEvent injection. Clipboards can be seamlessly copied between Linux machines, and screen-edge switching is supported on Hyprland. Windows is not currently supported.

For more information and setup instructions, visit the [project repository](https://github.com/mntzrr/monux).
