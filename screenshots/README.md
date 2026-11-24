# Screenshots

Add your proof-of-work screenshots here to strengthen the write-up. Recommended captures:

- `01-nmap.png` — service scan showing ports 80 / 3306 / rpcbind
- `02-lfi-config.png` — decoded `config.php` (credential disclosure)
- `03-upload.png` — successful polyglot upload
- `04-rce-wwwdata.png` — `id` returning `uid=33(www-data)`
- `05-privesc-mike.png` — `uid=1002(mike)` after the PATH hijack
- `06-root.png` — `euid=0(root)` from the `msg2root` injection
- `07-flag.png` — contents of `/root/flag.txt`

Then reference them from the main `README.md`, e.g. `![root](screenshots/06-root.png)`.
