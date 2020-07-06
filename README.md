# StreamEncryptor
StreamEncryptor aims to make the encryption and authentication of streams as easy as possible. Encrypted streams are prepended with an authentication packet, allowing them to be verified when decrypting.

Please note that I am no expert in encryption! Hence, there may be issues that I am not aware of.

### Installation
You can download StreamEncryptor from [nuget](https://www.nuget.org/packages/StreamEncryptor/)

### Documentation

Using StreamEncryptor is as simple as the following:


```c#
using (var encryptor = new AesHmacEncryptor("your password here"))
{
    MemoryStream encrypted = await encryptor.EncryptAsync(streamToEncrypt);
    MemoryStream decrypted = await encryptor.DecryptAsync(encrypted);
}
```

The above demonstrates encrypting and authenticating a stream using the AES algorithm, and then verifying and decrypting it.

See the [wiki](https://github.com/carlst99/StreamEncryptor/wiki) for more detailed info.
