# SSH

```console
$ sslknife ssh generate -o ~/.ssh/id_ed25519 -C alice@laptop
$ sslknife ssh inspect ~/.ssh/id_ed25519.pub
Kind:               public
Format:             authorized_keys
Type:               ssh-ed25519
Bits:               256
Fingerprint SHA256: SHA256:5p9n...
Comment:            alice@laptop
$ sslknife ssh inspect ~/.ssh/authorized_keys          # every line, with options
$ sslknife ssh import ~/.ssh/id_ed25519                # stored as-is, still passphrase-protected
$ sslknife ssh convert id_rsa --to pkcs8 -o id_rsa.pem
$ sslknife ssh cert sign --ca ssh_ca --key id_ed25519.pub --principal alice --id alice@corp --validity 8h
$ sslknife ssh cert inspect id_ed25519-cert.pub
```

Encrypted private keys are inspected and fingerprinted without the passphrase
when the format allows it. Imported private keys are stored exactly as the
file, so a passphrase-protected key stays protected inside the vault. RSA SSH
CAs sign with `rsa-sha2-512`, never SHA-1.

## Using stored keys with ssh

`ssh agent` puts keys from the vault into an SSH agent, so `ssh`, `git`,
`scp` or Ansible can use them without the private key ever being written to
disk:

```console
$ sslknife ssh agent add deploy-key --lifetime 8h     # into the running ssh-agent ($SSH_AUTH_SOCK)
$ sslknife ssh agent add --tag servers --confirm      # ask (ssh-askpass) before each use
$ sslknife ssh agent list
$ sslknife ssh agent remove deploy-key                # or --all

$ sslknife ssh agent serve deploy-key -- ssh deploy@web01   # built-in agent for one command
$ sslknife ssh agent serve --tag prod -- ansible-playbook site.yml
```

Without a command, `serve` runs until interrupted. With a fixed socket, ssh
can use it for chosen hosts through `~/.ssh/config`:

```console
$ sslknife ssh agent serve --all --socket ~/.ssh/sslknife-agent.sock --lifetime 8h
```

```
Host *.example.com
    IdentityAgent ~/.ssh/sslknife-agent.sock
```

Passphrase-protected keys are decrypted with `--passphrase-file`,
`$SSLKNIFE_SSH_PASSPHRASE` or a prompt, and a passphrase that opened one key
is tried on the next. A `<key>-cert.pub` next to a key file is loaded with it,
as `ssh-add` does; `--cert` attaches certificates to stored keys. The agent
socket is created with mode 0600.
