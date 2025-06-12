# Usugumo
A Windows kernel-mode driver that proxies RPM/WPM operations, handling user-mode process requests via ioctl
---

## Features

- Handling user-mode process requests via ioctl
- Implement RPM/WPM without OpenProcess in kernel-mode 

## KnownIssues

- Currently only works on x64 processes(?)
- Current implementation does not take into account CR3 encryption, kernel-mode memory protection, etc., and is only used as a PoC
- Kernel-mode mouse input method is not yet implemented
  
## License

This project is licensed under [**TOSSRCU**](LICENSE).
```diff
+ You are free to:
	• Use: Utilize the software for any purpose not explicitly restricted
	• Copy: Reproduce the software without limitation
	• Modify: Create derivative works through remixing/transforming
	• Merge: Combine with other materials
	• Publish: Display/communicate the software publicly
	• Distribute: Share copies of the software

+ Under the following terms:
	• Attribution: Must include copyright notice and this license in all copies
	• Waifu Clause: Don't consider the author as your waifu

- You are not allowed to:
	• Sublicense: Cannot grant sublicenses for original/modified material

```

## Credits

- [ekknod/MouseClassServiceCallbackMeme](https://github.com/ekknod/MouseClassServiceCallbackMeme/)