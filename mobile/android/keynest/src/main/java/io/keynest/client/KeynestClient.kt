package io.keynest.client

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import okhttp3.OkHttpClient
import okhttp3.Request
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.io.pem.PemReader
import java.io.File
import java.io.StringReader
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateKeySpec
import java.time.Duration
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@Serializable
data class KeynestAddress(
    val project: String,
    val environment: String,
    val service: String,
)

@Serializable
data class KeynestField(
    val path: String,
    val label: String,
    val type: String,
    val description: String? = null,
    val required: Boolean = false,
    val sensitive: Boolean = false,
    val environment: String? = null,
    val yaml: String? = null,
    val options: List<String>? = null,
    val default: JsonElement? = null,
)

@Serializable
data class KeynestDocument(
    val address: KeynestAddress,
    val schema: List<KeynestField>,
    val values: Map<String, JsonElement>,
    val version: Int,
    val updatedAt: String,
)

@Serializable
data class KeynestEnvelope(
    val algorithm: String,
    val keyId: String,
    val version: Int,
    val encryptedKey: String,
    val nonce: String,
    val ciphertext: String,
)

enum class KeynestRefreshSource {
    CACHE,
    NETWORK,
}

data class KeynestRefreshResult(
    val document: KeynestDocument,
    val version: Int,
    val source: KeynestRefreshSource,
)

data class KeynestRenderedResult(
    val data: ByteArray,
    val version: Int,
    val source: KeynestRefreshSource,
)

enum class KeynestRenderFormat(val wireName: String) {
    ENV("env"),
    YAML("yaml"),
}

sealed class KeynestException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class InvalidConfiguration(message: String) : KeynestException(message)
    class Unauthorized : KeynestException("bearer token is unauthorized")
    class Forbidden : KeynestException("bearer token is forbidden")
    class CenterUnavailable : KeynestException("configuration center unavailable")
    class NotModifiedWithoutCache : KeynestException("304 returned without cached envelope")
    class UnsupportedAlgorithm(algorithm: String) : KeynestException("unsupported algorithm: $algorithm")
    class PrivateKeyInvalid : KeynestException("private key is invalid")
    class DecryptionFailed(cause: Throwable? = null) : KeynestException("decryption failed", cause)
    class CacheReadFailed(cause: Throwable? = null) : KeynestException("cache read failed", cause)
    class CacheWriteFailed(cause: Throwable? = null) : KeynestException("cache write failed", cause)
    class HttpStatus(val status: Int) : KeynestException("configuration center returned HTTP $status")
    class Canceled : KeynestException("refresh canceled")
    class VersionConflict : KeynestException("cached configuration version is newer")
}

data class KeynestOptions(
    val refreshOnLaunch: Boolean = true,
    val refreshOnAppActive: Boolean = true,
    val foregroundOnly: Boolean = true,
    val minimumForegroundInterval: Duration = Duration.ofSeconds(30),
    val requestTimeout: Duration = Duration.ofSeconds(10),
    val serveCacheImmediately: Boolean = true,
    val fallbackToCacheOnUnavailable: Boolean = true,
    val cacheEnabled: Boolean = true,
    val deduplicateRefreshRequests: Boolean = true,
    val retryCount: Int = 1,
    val retryInterval: Duration = Duration.ofSeconds(1),
)

class KeynestClient(
    private val context: Context,
    private val baseURL: String,
    private val accessToken: String,
    private val privateKeyPEM: ByteArray,
    val options: KeynestOptions = KeynestOptions(),
) {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    private val httpClient = OkHttpClient.Builder()
        .callTimeout(options.requestTimeout.seconds, java.util.concurrent.TimeUnit.SECONDS)
        .build()
    private val normalizedBaseURL = baseURL.trimEnd('/')
    private val mutex = Mutex()
    private val inFlight = mutableMapOf<String, kotlinx.coroutines.Deferred<KeynestRefreshResult>>()
    private val lastRefresh = mutableMapOf<String, Long>()

    init {
        require(normalizedBaseURL.matches(Regex("^https?://.+"))) {
            "invalid configuration center URL"
        }
        require(accessToken.isNotBlank()) { "configuration access token is required" }
        require(privateKeyPEM.isNotEmpty()) { "configuration decryption private key is required" }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    suspend fun get(address: KeynestAddress): KeynestDocument =
        refresh(address).document

    suspend fun refresh(address: KeynestAddress): KeynestRefreshResult {
        validate(address)
        val key = cacheKey(address)
        val now = System.currentTimeMillis()
        val existing = mutex.withLock {
            if (options.deduplicateRefreshRequests) inFlight[key] else null
        }
        if (existing != null) return existing.await()

        val last = mutex.withLock { lastRefresh[key] }
        if (last != null &&
            now - last < options.minimumForegroundInterval.toMillis() &&
            options.serveCacheImmediately
        ) {
            val envelope = readEnvelope(address)
            if (envelope != null) {
                return KeynestRefreshResult(
                    document = decryptDocument(envelope, address),
                    version = envelope.version,
                    source = KeynestRefreshSource.CACHE,
                )
            }
        }

        val deferred = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).async {
            performRefresh(address)
        }
        mutex.withLock { inFlight[key] = deferred }
        return try {
            val result = deferred.await()
            mutex.withLock {
                inFlight.remove(key)
                lastRefresh[key] = System.currentTimeMillis()
            }
            result
        } catch (failure: Throwable) {
            mutex.withLock { inFlight.remove(key) }
            if (failure is KeynestException) throw failure
            throw KeynestException.CenterUnavailable()
        }
    }

    suspend fun getRendered(
        address: KeynestAddress,
        format: KeynestRenderFormat,
    ): KeynestRenderedResult = withContext(Dispatchers.IO) {
        validate(address)
        val key = "${cacheKey(address)}:/render/${format.wireName}"

        val requestBuilder = Request.Builder()
            .url("$normalizedBaseURL/api/v1/configs/${escape(address.project)}/${escape(address.environment)}/${escape(address.service)}/render/${format.wireName}")
            .header("Authorization", "Bearer $accessToken")
        readEnvelopeAtKey(key)?.let { envelope ->
            requestBuilder.header("If-None-Match", "\"${envelope.version}\"")
        }

        val response = try {
            httpClient.newCall(requestBuilder.build()).execute()
        } catch (failure: Throwable) {
            val cached = readEnvelopeAtKey(key)
            if (cached != null && options.fallbackToCacheOnUnavailable) {
                return@withContext KeynestRenderedResult(
                    data = decryptBytes(cached, address),
                    version = cached.version,
                    source = KeynestRefreshSource.CACHE,
                )
            }
            throw KeynestException.CenterUnavailable()
        }

        response.use {
            when (it.code) {
                304 -> {
                    val cached = readEnvelopeAtKey(key)
                        ?: throw KeynestException.NotModifiedWithoutCache()
                    KeynestRenderedResult(
                        data = decryptBytes(cached, address),
                        version = cached.version,
                        source = KeynestRefreshSource.CACHE,
                    )
                }
                200 -> {
                    val envelope = json.decodeFromString<KeynestEnvelope>(
                        it.body?.string() ?: throw KeynestException.CenterUnavailable(),
                    )
                    val plain = decryptBytes(envelope, address)
                    writeEnvelopeAtKey(key, envelope)
                    KeynestRenderedResult(
                        data = plain,
                        version = envelope.version,
                        source = KeynestRefreshSource.NETWORK,
                    )
                }
                401 -> throw KeynestException.Unauthorized()
                403 -> throw KeynestException.Forbidden()
                408, 429 -> throwUnavailableOrCached(address, key)
                in 500..599 -> throwUnavailableOrCached(address, key)
                else -> throw KeynestException.HttpStatus(it.code)
            }
        }
    }

    private suspend fun performRefresh(address: KeynestAddress): KeynestRefreshResult =
        withContext(Dispatchers.IO) {
            val requestBuilder = Request.Builder()
                .url("$normalizedBaseURL/api/v1/configs/${escape(address.project)}/${escape(address.environment)}/${escape(address.service)}")
                .header("Authorization", "Bearer $accessToken")
            readEnvelope(address)?.let { envelope ->
                requestBuilder.header("If-None-Match", "\"${envelope.version}\"")
            }

            val response = try {
                httpClient.newCall(requestBuilder.build()).execute()
            } catch (failure: Throwable) {
                val cached = readEnvelope(address)
                if (cached != null && options.fallbackToCacheOnUnavailable) {
                    return@withContext KeynestRefreshResult(
                        document = decryptDocument(cached, address),
                        version = cached.version,
                        source = KeynestRefreshSource.CACHE,
                    )
                }
                throw KeynestException.CenterUnavailable()
            }

            response.use {
                when (it.code) {
                    304 -> {
                        val cached = readEnvelope(address)
                            ?: throw KeynestException.NotModifiedWithoutCache()
                        KeynestRefreshResult(
                            document = decryptDocument(cached, address),
                            version = cached.version,
                            source = KeynestRefreshSource.CACHE,
                        )
                    }
                    200 -> {
                        val envelope = json.decodeFromString<KeynestEnvelope>(
                            it.body?.string() ?: throw KeynestException.CenterUnavailable(),
                        )
                        val document = decryptDocument(envelope, address)
                        writeEnvelope(address, envelope)
                        KeynestRefreshResult(
                            document = document,
                            version = envelope.version,
                            source = KeynestRefreshSource.NETWORK,
                        )
                    }
                    401 -> throw KeynestException.Unauthorized()
                    403 -> throw KeynestException.Forbidden()
                    408, 429 -> fallbackFromRefresh(address)
                    in 500..599 -> fallbackFromRefresh(address)
                    else -> throw KeynestException.HttpStatus(it.code)
                }
            }
        }

    private fun fallbackFromRefresh(address: KeynestAddress): KeynestRefreshResult {
        val cached = readEnvelope(address)
        if (cached != null && options.fallbackToCacheOnUnavailable) {
            return KeynestRefreshResult(
                document = decryptDocument(cached, address),
                version = cached.version,
                source = KeynestRefreshSource.CACHE,
            )
        }
        throw KeynestException.CenterUnavailable()
    }

    private fun throwUnavailableOrCached(address: KeynestAddress, key: String): KeynestRenderedResult {
        val cached = readEnvelopeAtKey(key)
        if (cached != null && options.fallbackToCacheOnUnavailable) {
            return KeynestRenderedResult(
                data = decryptBytes(cached, address),
                version = cached.version,
                source = KeynestRefreshSource.CACHE,
            )
        }
        throw KeynestException.CenterUnavailable()
    }

    private fun validate(address: KeynestAddress) {
        val pattern = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
        if (!pattern.matches(address.project) ||
            !pattern.matches(address.environment) ||
            !pattern.matches(address.service)
        ) {
            throw KeynestException.InvalidConfiguration("invalid Keynest address")
        }
    }

    private fun escape(value: String): String =
        URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20")

    private fun cacheKey(address: KeynestAddress): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val identity = "$normalizedBaseURL|${address.project}|${address.environment}|${address.service}"
        return digest.digest(identity.toByteArray(StandardCharsets.UTF_8)).joinToString("") {
            "%02x".format(it)
        }
    }

    private fun cacheDirectory(): File =
        File(context.cacheDir, "Keynest").apply { mkdirs() }

    private fun cacheFile(key: String): File =
        File(cacheDirectory(), "$key.json")

    private fun readEnvelope(address: KeynestAddress): KeynestEnvelope? =
        readEnvelopeAtKey(cacheKey(address))

    private fun readEnvelopeAtKey(key: String): KeynestEnvelope? {
        if (!options.cacheEnabled) return null
        val file = cacheFile(key)
        if (!file.exists()) return null
        return try {
            json.decodeFromString<KeynestEnvelope>(file.readText(StandardCharsets.UTF_8))
        } catch (failure: Throwable) {
            throw KeynestException.CacheReadFailed(failure)
        }
    }

    private fun writeEnvelope(address: KeynestAddress, envelope: KeynestEnvelope) {
        writeEnvelopeAtKey(cacheKey(address), envelope)
    }

    private fun writeEnvelopeAtKey(key: String, envelope: KeynestEnvelope) {
        if (!options.cacheEnabled) return
        val file = cacheFile(key)
        val temp = File(file.parentFile, ".${file.name}.tmp")
        try {
            temp.writeText(json.encodeToString(KeynestEnvelope.serializer(), envelope), StandardCharsets.UTF_8)
            if (!temp.renameTo(file)) {
                temp.copyTo(file, overwrite = true)
                temp.delete()
            }
        } catch (failure: Throwable) {
            throw KeynestException.CacheWriteFailed(failure)
        }
    }

    private fun decryptDocument(envelope: KeynestEnvelope, address: KeynestAddress): KeynestDocument {
        val plain = decryptBytes(envelope, address)
        return try {
            json.decodeFromString<KeynestDocument>(plain.toString(StandardCharsets.UTF_8))
        } catch (failure: Throwable) {
            throw KeynestException.DecryptionFailed(failure)
        }
    }

    private fun decryptBytes(envelope: KeynestEnvelope, address: KeynestAddress): ByteArray {
        if (envelope.algorithm != "RSA-OAEP-256+A256GCM") {
            throw KeynestException.UnsupportedAlgorithm(envelope.algorithm)
        }
        val privateKey = try {
            val pem = PemReader(StringReader(privateKeyPEM.toString(StandardCharsets.UTF_8))).use { it.readPemObject() }
                ?: throw KeynestException.PrivateKeyInvalid()
            val factory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
            factory.generatePrivate(PKCS8EncodedKeySpec(pem.content))
        } catch (failure: Throwable) {
            if (failure is KeynestException) throw failure
            throw KeynestException.PrivateKeyInvalid()
        }

        val aad = "${envelope.keyId}\n${address.project}\n${address.environment}\n${address.service}\n${envelope.version}"
            .toByteArray(StandardCharsets.UTF_8)
        return try {
            val encryptedKey = Base64.getDecoder().decode(envelope.encryptedKey)
            val oaep = Cipher.getInstance("RSA/None/OAEPWithSHA256AndMGF1Padding", BouncyCastleProvider.PROVIDER_NAME)
            oaep.init(Cipher.DECRYPT_MODE, privateKey, javax.crypto.spec.OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256,
                javax.crypto.spec.PSource.PSpecified(aad),
            ))
            val contentKeyBytes = oaep.doFinal(encryptedKey)
            if (contentKeyBytes.size != 32) throw KeynestException.DecryptionFailed()

            val nonce = Base64.getDecoder().decode(envelope.nonce)
            val ciphertext = Base64.getDecoder().decode(envelope.ciphertext)
            val gcm = Cipher.getInstance("AES/GCM/NoPadding")
            gcm.init(Cipher.DECRYPT_MODE, SecretKeySpec(contentKeyBytes, "AES"), GCMParameterSpec(128, nonce))
            gcm.updateAAD(aad)
            gcm.doFinal(ciphertext)
        } catch (failure: Throwable) {
            if (failure is KeynestException) throw failure
            throw KeynestException.DecryptionFailed(failure)
        }
    }
}
