# Password secrets modes

The `[logging].secrets_mode` key controls how captured passwords are stored
in the CSV log. Choose based on your threat model and whether you need to
recover plaintext later.

When you use one of the encrypted modes, the logger reads the X25519
recipient public key from `[logging].secrets_pubkey` before privileges are
dropped.

## Modes

### `plain`

The password is written as-is (truncated to 100 bytes if longer).

 
> [!WARNING]
> These are not necessarily invented passwords. Credential stuffing campaigns
> reuse real leaked credentials, so the log may contain passwords that are
> valid elsewhere. Treat it accordingly.
 

### `hash`

```
password_field = base64( sha256(password_bytes) )
```

Lets you detect reuse and frequency without retaining plaintext.
Cannot be reversed if not by brute-force guessing, which is infeasible for strong passwords but may be possible for weak ones. Still better than plaintext for protecting against accidental leaks of the log data.

### `none`

The password field is written as an empty string. Only IP, username,
timestamp, and SSH client version are retained.

### `enc_x25519_aes256gcm`

Hybrid encryption: X25519 key agreement, HKDF key derivation, AES-256-GCM
authenticated encryption. Passwords are recoverable offline with the
corresponding private key.

**Key agreement**

```
ephemeral_priv  = random(32 bytes)            # from CSPRNG, per-entry
ephemeral_pub   = X25519(ephemeral_priv, G)   # 32 bytes, G = basepoint

shared_secret   = X25519(ephemeral_priv, recipient_pub)   # 32 bytes
```

**Key and IV derivation**

```
material = HKDF-SHA256(
    IKM  = shared_secret,
    salt = 0x00 * 32,
    info = "sshpot password encryption v1",   # UTF-8
    L    = 44 bytes
)

key = material[0:32]    # 32-byte AES-256 key
iv  = material[32:44]   # 12-byte GCM nonce
```

The zero salt is safe here because the IKM (the X25519 output) is already
uniformly random for each entry. The (key, IV) pair is never reused because
a fresh ephemeral keypair is generated per entry.

**Plaintext preparation (length hiding)**

Passwords are truncated to 100 bytes before encryption. The plaintext is
padded to a fixed 101 bytes so the ciphertext length does not reveal
password length:

```
trunc     = truncate(password, 100 bytes)
pad_len   = 100 - len(trunc)              # 0..100
plaintext = len(trunc) || trunc || 0x00 * pad_len
           # total: 1 + len(trunc) + pad_len = 101 bytes
```

**Encryption**

```
ciphertext_with_tag = AES-256-GCM-Encrypt(key, iv, plaintext)
# 101 bytes plaintext + 16-byte tag = 117 bytes ciphertext
```

**Storage format**

```
password_field = base64( ephemeral_pub || ciphertext_with_tag )
# 32 + 117 = 149 bytes binary → 200 characters base64
```

### `enc_x25519_chacha20poly1305`

Same key agreement and HKDF derivation as `enc_x25519_aes256gcm`.
Differs in the cipher used and does not apply length-hiding padding.

**Encryption**

```
ciphertext_with_tag = ChaCha20-Poly1305-Encrypt(key, iv, password)
```

**Storage format**

```
password_field = base64( ephemeral_pub || ciphertext_with_tag )
```

Prefer AES-256-GCM on hardware with AES-NI; prefer ChaCha20-Poly1305
on hardware without it (most ARM, older x86).

---

## Generating a recipient keypair

The recipient keypair is a standard X25519 keypair. You can generate one
with OpenSSL:

```bash
# private key (keep offline or in a secrets manager)
openssl genpkey -algorithm x25519 -out recipient.key

# public key (place in config as recipient_pub)
openssl pkey -in recipient.key -pubout -out recipient.pub
```

Store the private key offline. The honeypot host needs only the public key.

---

## Notation used in this document

| Symbol | Meaning |
|--------|---------|
| `a \|\| b` | byte-level concatenation of `a` and `b` |
| `base64(x)` | standard base64 encoding (RFC 4648) |
| `random(n)` | `n` bytes from a CSPRNG |
| `truncate(s, n)` | take at most the first `n` bytes of `s` |