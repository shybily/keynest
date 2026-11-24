# Cross-platform Test Vectors

移动端实现必须通过一组由服务端生成、双端共享的向量。

每个向量包含：

- RSA 私钥和公钥测试材料
- 地址：`project/prod/api`
- 密钥 ID
- 配置版本
- 明文 JSON
- 加密信封

向量只允许使用测试密钥，不得包含生产凭据。

## Mandatory Cases

- valid envelope
- wrong project AAD
- wrong environment AAD
- wrong service AAD
- wrong version
- wrong key ID
- tampered AES ciphertext
- tampered encrypted content key
- unsupported algorithm
- malformed Base64
- malformed nonce
- invalid 304 cache
- network fallback cache
- cache must never contain plaintext
