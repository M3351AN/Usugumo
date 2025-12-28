# Usugumo

A Windows kernel-mode driver that proxies RPM/WPM/mouse_event operations, handling user-mode process requests via ioctl

---

## Features

- Handling user-mode process requests via ioctl
- Kernel-mode RPM/WPM
- Kernel-mode mouse input
  
## KnownIssues

- Currently only works on x64 windows
- Current implementation does not take into account CR3 encryption, kernel-mode memory protection, etc., and is only used as a PoC

## License

This project is licensed under [**TOSSUCU License 2025.9**](LICENSE).

## Credits

- [ekknod/MouseClassServiceCallbackMeme](https://github.com/ekknod/MouseClassServiceCallbackMeme/)
- [reactos](https://github.com/reactos/reactos/) BSD Licenced part
- [danielkrupinski/Osiris](https://github.com/danielkrupinski/Osiris/)
