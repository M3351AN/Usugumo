# Usugumo

A Windows kernel-mode driver that proxies RPM/WPM/mouse_event/keybd_event .etc operations, handling user-mode process requests via ioctl

> [!WARNING]
> This project IS NOT designed to combat AC/AV/EDR or sth like that.
> 
> And no matter what purpose you use it for, I DO NOT guarantee anything about it and assume ALL RISKS at your own risk
> 
> Unless strictly tested and appropriately modified, in principle, DO NOT directly use any code from this project for production environments

---

## Features

- Handling user-mode process requests via ioctl
- Kernel-mode RPM/WPM
- Kernel-mode fetch module info(base, size)
- Kernel-mode get PID via name
- Kernel-mode mouse input
- Kernel-mode keyboard input
- Kernel-mode anti capture
  
## KnownIssues

- Currently only works on x64 windows
- Current implementation does not take into account CR3 encryption, kernel-mode memory protection, etc., and is only used as a PoC

## License

This project is licensed under [**TOSSUCU License 2025.9**](LICENSE).

## Usage

See [Examples](./Examples)

There‘s also an alternative example that utilizes Native API, which is not a best practice, but better than most user-mode pasta.

## Credits

- [ekknod/MouseClassServiceCallbackMeme](https://github.com/ekknod/MouseClassServiceCallbackMeme/)
- [reactos](https://github.com/reactos/reactos/) BSD Licensed part
- [danielkrupinski/Osiris](https://github.com/danielkrupinski/Osiris/)
- [oakboat/GsDriver-ring3](https://github.com/oakboat/GsDriver-ring3/)
