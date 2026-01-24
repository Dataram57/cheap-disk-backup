

# Backup Structure

### General

Every generated file is encrypted as such:

```
ENCRYPTED_FILE_CONTENT, SALT_BYTES
```

To decrypt the file one must cut the last `SALT_BYTES`, generate a decryption key through `password` and `SALT_BYTES`, and use decryption key to decrypt the remaining `ENCRYPTED_FILE_CONTENT`.
