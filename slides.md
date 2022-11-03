---
marp: true
theme: acceis
class: invert
paginate: true
header: '![height:20px](themes/logo_acceis_white.svg)'
footer: '**Cracking hashed known_hosts** - 17/10/2022 - Auteur'
---
# Cracking hashed known_hosts

![height:200px](themes/logo_acceis_white.svg)

---

## Default known_hosts

![bg right](assets/acceis_neutral_background.jpg)

---

`~/.ssh/known_hosts`

```
[vagrant@archlinux ~]$ ssh -V
OpenSSH_9.1p1, OpenSSL 1.1.1q  5 Jul 202
```

---

```
[vagrant@archlinux ~]$ ssh -TN new@sdf.org
The authenticity of host 'sdf.org (205.166.94.16)' can't be established.
ED25519 key fingerprint is SHA256:ZjwbO7AU8rHJExYrmZS2LqGZ7WfdoELfMrF54W92PYA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'sdf.org' (ED25519) to the list of known hosts.
```

---

```
[vagrant@archlinux ~]$ cat ~/.ssh/known_hosts
205.166.94.16 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJJk3a190w/1TZkzVKORvz/kwyKmFY144lVeDFm80p17
195.144.107.198 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOdXzF+Jx/wvEBun5fxi8FQK30miLZFND0rxkYwNcYlE
128.252.17.87 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPH6DuyTSE4wZ4CPLB2FCfdaieiioRpkViEj+We1BZ3e
104.149.73.196 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICz0N0440w+2iREw/tl2n+kTg9tgs38RpzqXwryU5wwz
```

---

```

sdf.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJJk3a190w/1TZkzVKORvz/kwyKmFY144lVeDFm80p17
test.rebex.net ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOdXzF+Jx/wvEBun5fxi8FQK30miLZFND0rxkYwNcYlE
itcsubmit.wustl.edu ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPH6DuyTSE4wZ4CPLB2FCfdaieiioRpkViEj+We1BZ3e
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf
```

```
[demo.wftpserver.com]:2222 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBALrVMyBtERl1mbdOoWZeR1v3fMl2uj6C43D5D9g8w/gbPL5DmGAY3UnVHj7SEcBdPAXkqLUgQ4UTNIJKMBC7aI=
```

---

```sh
grep -v '#' /etc/ssh/ssh_config
```

---

## known_hosts + `HashKnownHosts`

![bg left:33%](assets/acceis_neutral_background.jpg)

---

`/etc/ssh/ssh_config`

```
HashKnownHosts yes
```

---

`~/.ssh/known_hosts`

```
|1|MCKLsiMqXVKQlR1GWLJpqUoBcvk=|SDo6nxIA6+jiNvsMkqR8xxtqIR0= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJJk3a190w/1TZkzVKORvz/kwyKmFY144lVeDFm80p17
|1|b08QaZXugZ42Kx2lmu7krSkrbSA=|DK9KjVOSW3/9J+yfHk+cb6z6FMs= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJJk3a190w/1TZkzVKORvz/kwyKmFY144lVeDFm80p17
|1|EWVUGTJTEkI3LpQQa9wTZg3S/P0=|Osi69nNyEPHswWxBqyIIrfN6AM0= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOdXzF+Jx/wvEBun5fxi8FQK30miLZFND0rxkYwNcYlE
|1|N5eGXqQYXcAmrsSzu5wHmtwDEvU=|kHLRLHMlwt+J2rjx7stjiGdIqBk= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPH6DuyTSE4wZ4CPLB2FCfdaieiioRpkViEj+We1BZ3e
|1|mtEB/sRYid9BQp29PlY/gnHsg8U=|Bu27uiplueFG7JjVc0r4Z9a5I/I= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICz0N0440w+2iREw/tl2n+kTg9tgs38RpzqXwryU5wwz
|1|LszTPhLnWS4GZ/Xka0StLur1XiA=|U/i/iaHUBbvReAOJt1NaSyafQH0= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOdXzF+Jx/wvEBun5fxi8FQK30miLZFND0rxkYwNcYlE
|1|DGCl76T1/CtOKAF9Jv5sAmKzjy0=|nT+hrQYiA4S009a1TJLNQYLwB6w= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
|1|MHIGUkcMYn9rcW0ugE+tfUPgQss=|5bBnuOv3qE3Udvxj/7m1D+yDajY= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf
```

```
|1|73nfOpZXvt078aFDxJvipqrcZ/0=|QDtmgCPbhR2EzsTkiuN734l6kDw= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBALrVMyBtERl1mbdOoWZeR1v3fMl2uj6C43D5D9g8w/gbPL5DmGAY3UnVHj7SEcBdPAXkqLUgQ4UTNIJKMBC7aI=
```

---

# Format

```
|<Magic string>|<salt>|<hash> <key algorithm> <public key sig.>
```

- `<salt>`: 160 bits random salt base64 encoded
- `<hash>`: 160 bits SHA1 hashed host base64 encoded
- `<public key>`: public host key signature base64 encoded

---

SHA1 hash from base64 to hexadecimal

```
key=$(ctf-party 'N5eGXqQYXcAmrsSzu5wHmtwDEvU=' from_b64 to_hex)
3797865ea4185dc026aec4b3bb9c079adc0312f5

key=$(printf 'N5eGXqQYXcAmrsSzu5wHmtwDEvU=' | base64 -d | xxd -p)
3797865ea4185dc026aec4b3bb9c079adc0312f5
```

Text to base64 salted SHA1 hash

```
printf 128.252.17.87 | openssl sha1 -mac HMAC -macopt hexkey:$key | awk '{print $2}' | ctf-party - from_hex to_b64
kHLRLHMlwt+J2rjx7stjiGdIqBk=

printf 128.252.17.87 | openssl sha1 -mac HMAC -macopt hexkey:$key | awk '{print $2}' | xxd -r -p | base64
kHLRLHMlwt+J2rjx7stjiGdIqBk=
```

---

## Why cracking host hashes?

![bg right](assets/acceis_neutral_background.jpg)


---

- For pivoting once you compromised a machine (SSH based worm have been reported in the past)
- It's not uncommon that private key are not encrypted on enterprise servers (so you don't need a password to use them)
- Password re-use between system user and encrypted private key is not uncommon either
- Once an SSH private is owned, the only question left is: **Where can I use this key?**

---

### Where can I use this key? 🔍🔑

- `~/.zsh_history` / `~/.bash_history` looking for `ssh` commands
- `/etc/hosts` (less reliable)
- application logs
- `~/.ssh/known_hosts` 😏

---

😃 `HashKnownHosts` is an old feature from openSSH 4.0 but is rarely used since it's disabled by default and few knows about it.

**BUT**

😒 Ubuntu and Debian servers seems to enable it by default.

---

`HashKnownHosts` was a worm / attacker killer feature in 2005 but with nowadays GPU we can crack this right? 😏

---

## Cracking strategy

![bg left](assets/acceis_neutral_background.jpg)

---

- IPv4 + default port
- IPv4 + custom port
- IPv6 + default port
- IPv6 + custom port
- domain + default port
- domain + custom port

---

Range | Number of addresses
----- | -------------------
10.0.0.0/8      | ~16.7M
172.16.0.0/12   | ~1M
192.168.0.0/24  | ~65K
0.0.0.0/0       | ~4B
::0/0           | 3.4×10^38
fe80::/10       | 3.3×10^35
fdXX:XXXX:XXXX:XXXX::/64  | 1.8×10^19

---

### Attack method

- 🥶 brute-force
- 🤒 pre-computed dictionary
- 🥵 mask

---

### What's reasonable?

- all IPv4 + default port
- all IPv4 + common custom ports
- checking a few targeted IPv6
- targeted (sub-)domains

---

## Cracking time! 🕥

#### Let's go! 🤩

![bg right:40%](assets/acceis_neutral_background.jpg)

---

### Mask 🎭 attack on all IPv4 addresses

```
$ git clone https://github.com/chris408/known_hosts-hashcat && cd known_hosts-hashcat
$ python kh-converter.py .known_hosts > hashes.txt
$ hashcat -m 160 --quiet --hex-salt hashes.txt -a 3 ipv4_hcmask.txt
```

---

From previously shown examples:

```
$ python kh-converter.py .known_hosts
483a3a9f1200ebe8e236fb0c92a47cc71b6a211d:30228bb2232a5d5290951d4658b269a94a0172f9
0caf4a8d53925b7ffd27ec9f1e4f9c6facfa14cb:6f4f106995ee819e362b1da59aeee4ad292b6d20
3ac8baf6737210f1ecc16c41ab2208adf37a00cd:1165541932531242372e94106bdc13660dd2fcfd
9072d12c7325c2df89dab8f1eecb63886748a819:3797865ea4185dc026aec4b3bb9c079adc0312f5
06edbbba2a65b9e146ec98d5734af867d6b923f2:9ad101fec45889df41429dbd3e563f8271ec83c5
53f8bf89a1d405bbd1780389b7535a4b269f407d:2eccd33e12e7592e0667f5e46b44ad2eeaf55e20
9d3fa1ad06220384b4d3d6b54c92cd4182f007ac:0c60a5efa4f5fc2b4e28017d26fe6c0262b38f2d
e5b067b8ebf7a84dd476fc63ffb9b50fec836a36:30720652470c627f6b716d2e804fad7d43e042cb
403b668023db851d84cec4e48ae37bdf897a903c:ef79df3a9657bedd3bf1a143c49be2a6aadc67fd
```

---

Cracked ones:

```
$ hashcat -m 160 --quiet --hex-salt hashes.txt -a 3 ipv4_hcmask.txt
3ac8baf6737210f1ecc16c41ab2208adf37a00cd:1165541932531242372e94106bdc13660dd2fcfd:195.144.107.198
06edbbba2a65b9e146ec98d5734af867d6b923f2:9ad101fec45889df41429dbd3e563f8271ec83c5:104.149.73.196
9072d12c7325c2df89dab8f1eecb63886748a819:3797865ea4185dc026aec4b3bb9c079adc0312f5:128.252.17.87
0caf4a8d53925b7ffd27ec9f1e4f9c6facfa14cb:6f4f106995ee819e362b1da59aeee4ad292b6d20:205.166.94.16
```

---

Ref.

- [chris408/known_hosts-hashcat](https://github.com/chris408/known_hosts-hashcat)
- [SSH: benefits of using hashed known_hosts](https://security.stackexchange.com/questions/56268/ssh-benefits-of-using-hashed-known-hosts)
- [man sshd(8)](https://man.archlinux.org/man/core/openssh/sshd.8.en#SSH_KNOWN_HOSTS_FILE_FORMAT)
- [OpenSSH/Client Configuration Files](https://en.wikibooks.org/wiki/OpenSSH/Client_Configuration_Files#About_the_Contents_of_the_known_hosts_Files)
- [IPv6 Subnet Calculator](https://www.coderstool.com/ipv6-subnet-calculator)
- [IPv4 Hashcat Mask](https://pastebin.com/4HQ6C8gG)