import Foundation
import CryptoKit
import Security
import BigInt

public struct KeynestAddress: Codable, Hashable, Sendable {
    public let project: String
    public let environment: String
    public let service: String

    public init(project: String, environment: String, service: String) {
        self.project = project
        self.environment = environment
        self.service = service
    }
}

public struct KeynestField: Codable, Sendable {
    public let path: String
    public let label: String
    public let type: String
    public let description: String?
    public let required: Bool?
    public let sensitive: Bool?
    public let environment: String?
    public let yaml: String?
    public let options: [String]?
    public let `default`: JSONValue?
}

public enum JSONValue: Codable, Sendable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([String: JSONValue].self) { self = .object(value) }
        else if let value = try? container.decode([JSONValue].self) { self = .array(value) }
        else { throw DecodingError.dataCorruptedError(in: container, debugDescription: "unsupported JSON value") }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
}

public struct KeynestDocument: Codable, Sendable {
    public let address: KeynestAddress
    public let schema: [KeynestField]
    public let values: [String: JSONValue]
    public let version: Int
    public let updatedAt: String

    enum CodingKeys: String, CodingKey {
        case address, schema, values, version
        case updatedAt
    }
}

public struct KeynestEnvelope: Codable, Sendable {
    public let algorithm: String
    public let keyId: String
    public let version: Int
    public let encryptedKey: String
    public let nonce: String
    public let ciphertext: String
}

public enum KeynestRefreshSource: Sendable {
    case cache
    case network
}

public struct KeynestRefreshResult: Sendable {
    public let document: KeynestDocument
    public let version: Int
    public let source: KeynestRefreshSource
}

public struct KeynestRenderedResult: Sendable {
    public let data: Data
    public let version: Int
    public let source: KeynestRefreshSource
}

public enum KeynestRenderFormat: String, Sendable {
    case env
    case yaml
}

public enum KeynestError: Error, Equatable {
    case invalidConfiguration(String)
    case unauthorized
    case forbidden
    case centerUnavailable
    case timeout
    case notModifiedWithoutCache
    case unsupportedAlgorithm(String)
    case privateKeyInvalid
    case decryptionFailed
    case cacheReadFailed
    case cacheWriteFailed
    case canceled
    case versionConflict
    case httpStatus(Int)
}

private struct DERItem {
    let tag: UInt8
    let content: Data
}

public struct KeynestOptions: Sendable {
    public var refreshOnLaunch: Bool
    public var refreshOnAppActive: Bool
    public var foregroundOnly: Bool
    public var minimumForegroundInterval: TimeInterval
    public var requestTimeout: TimeInterval
    public var serveCacheImmediately: Bool
    public var fallbackToCacheOnUnavailable: Bool
    public var cacheEnabled: Bool
    public var deduplicateRefreshRequests: Bool
    public var retryCount: Int
    public var retryInterval: TimeInterval

    public init(
        refreshOnLaunch: Bool = true,
        refreshOnAppActive: Bool = true,
        foregroundOnly: Bool = true,
        minimumForegroundInterval: TimeInterval = 30,
        requestTimeout: TimeInterval = 10,
        serveCacheImmediately: Bool = true,
        fallbackToCacheOnUnavailable: Bool = true,
        cacheEnabled: Bool = true,
        deduplicateRefreshRequests: Bool = true,
        retryCount: Int = 1,
        retryInterval: TimeInterval = 1
    ) {
        self.refreshOnLaunch = refreshOnLaunch
        self.refreshOnAppActive = refreshOnAppActive
        self.foregroundOnly = foregroundOnly
        self.minimumForegroundInterval = minimumForegroundInterval
        self.requestTimeout = requestTimeout
        self.serveCacheImmediately = serveCacheImmediately
        self.fallbackToCacheOnUnavailable = fallbackToCacheOnUnavailable
        self.cacheEnabled = cacheEnabled
        self.deduplicateRefreshRequests = deduplicateRefreshRequests
        self.retryCount = retryCount
        self.retryInterval = retryInterval
    }
}

private struct RSAOAEPPrivateKey {
    let modulus: BigUInt
    let privateExponent: BigUInt

    var modulusLength: Int {
        max(1, (modulus.serialize().count))
    }

    func decryptOAEP(_ ciphertext: Data, label: Data) throws -> Data {
        let c = BigUInt(ciphertext.map { String(format: "%02x", $0) }.joined(), radix: 16) ?? 0
        guard c < modulus else { throw KeynestError.decryptionFailed }
        let m = modPow(c, privateExponent, modulus)
        var em = m.serialize()
        if em.count > modulusLength {
            throw KeynestError.decryptionFailed
        }
        if em.count < modulusLength {
            em.insert(contentsOf: repeatElement(0, count: modulusLength - em.count), at: 0)
        }

        let hLen = 32
        guard em.count == modulusLength, em.count >= 66, em[0] == 0 else {
            throw KeynestError.decryptionFailed
        }

        let maskedSeed = Data(em[1..<(1 + hLen)])
        let maskedDB = Data(em[(1 + hLen)...])
        let seedMask = mgf1(maskedDB, length: hLen)
        let seed = xor(maskedSeed, seedMask)
        let dbMask = mgf1(seed, length: maskedDB.count)
        let db = xor(maskedDB, dbMask)

        let labelHash = SHA256.hash(data: label)
        let labelHashData = Data(labelHash)
        guard db.prefix(hLen) == labelHashData else {
            throw KeynestError.decryptionFailed
        }

        var offset = hLen
        while offset < db.count && db[offset] == 0 {
            offset += 1
        }
        guard offset < db.count, db[offset] == 1 else {
            throw KeynestError.decryptionFailed
        }
        return db[(offset + 1)...]
    }

    private func modPow(_ base: BigUInt, _ exponent: BigUInt, _ modulus: BigUInt) -> BigUInt {
        var result = BigUInt(1)
        var b = base % modulus
        var e = exponent
        while e > 0 {
            if e & 1 == 1 {
                result = (result * b) % modulus
            }
            e >>= 1
            b = (b * b) % modulus
        }
        return result
    }

    private func mgf1(_ seed: Data, length: Int) -> Data {
        var output = Data()
        for counter in 0..<(length + 31) / 32 {
            var counterBytes = UInt32(counter).bigEndian
            let input = seed + Data(bytes: &counterBytes, count: 4)
            output.append(Data(SHA256.hash(data: input)))
        }
        return output.prefix(length)
    }

    private func xor(_ lhs: Data, _ rhs: Data) -> Data {
        Data(zip(lhs, rhs).map { $0 ^ $1 })
    }
}

public final class KeynestClient: @unchecked Sendable {
    private let baseURL: URL
    private let accessToken: String
    private let privateKeyPEM: Data
    public let options: KeynestOptions
    private let session: URLSession
    private let cacheDirectory: URL
    private let lock = NSLock()
    private var inFlight: [String: Task<KeynestRefreshResult, Error>] = [:]
    private var lastRefresh: [String: Date] = [:]

    public init(baseURL: String, accessToken: String, privateKeyPEM: Data, options: KeynestOptions = .init()) throws {
        guard let url = URL(string: baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))),
              let scheme = url.scheme, ["http", "https"].contains(scheme),
              url.host != nil else {
            throw KeynestError.invalidConfiguration("invalid configuration center URL")
        }
        if accessToken.isEmpty {
            throw KeynestError.invalidConfiguration("configuration access token is required")
        }
        if privateKeyPEM.isEmpty {
            throw KeynestError.privateKeyInvalid
        }

        self.baseURL = url
        self.accessToken = accessToken
        self.privateKeyPEM = privateKeyPEM
        self.options = options

        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = options.requestTimeout
        configuration.timeoutIntervalForResource = options.requestTimeout
        self.session = URLSession(configuration: configuration)

        let cacheRoot = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        self.cacheDirectory = cacheRoot.appendingPathComponent("Keynest", isDirectory: true)
        try FileManager.default.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUnlessOpen], ofItemAtPath: cacheDirectory.path)
    }

    public func get(_ address: KeynestAddress) async throws -> KeynestDocument {
        let result = try await refresh(address)
        return result.document
    }

    public func refresh(_ address: KeynestAddress) async throws -> KeynestRefreshResult {
        try validate(address)
        let key = cacheKey(address)

        if let cachedTask = existingTask(key),
           options.deduplicateRefreshRequests {
            return try await cachedTask.value
        }

        if let last = lastRefreshTime(key),
           Date().timeIntervalSince(last) < options.minimumForegroundInterval,
           let cached = try readEnvelope(address) {
            let document = try decryptEnvelope(cached, address: address)
            return KeynestRefreshResult(document: document, version: cached.version, source: .cache)
        }

        let task = Task {
            try await self.performRefresh(address: address)
        }
        setTask(task, key: key)
        defer { removeTask(key) }

        do {
            let result = try await task.value
            setLastRefresh(key)
            return result
        } catch let error as KeynestError {
            throw error
        }
    }

    public func getRendered(_ address: KeynestAddress, format: KeynestRenderFormat) async throws -> KeynestRenderedResult {
        try validate(address)
        let path = "/api/v1/configs/\(escape(address.project))/\(escape(address.environment))/\(escape(address.service))/render/\(format.rawValue)"
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")

        let cacheKey = "\(cacheKey(address)):/render/\(format.rawValue)"
        if let cached = try readEnvelopeAtKey(cacheKey) {
            request.setValue("\"\(cached.version)\"", forHTTPHeaderField: "If-None-Match")
        }

        let (data, response) = try await fetchData(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw KeynestError.centerUnavailable
        }
        switch http.statusCode {
        case 304:
            guard let cached = try readEnvelopeAtKey(cacheKey) else {
                throw KeynestError.notModifiedWithoutCache
            }
            let plain = try decryptEnvelopeData(cached, address: address)
            return KeynestRenderedResult(data: plain, version: cached.version, source: .cache)
        case 200:
            let envelope = try JSONDecoder().decode(KeynestEnvelope.self, from: data)
            let plain = try decryptEnvelopeData(envelope, address: address)
            try writeEnvelopeAtKey(cacheKey, envelope)
            return KeynestRenderedResult(data: plain, version: envelope.version, source: .network)
        case 401:
            throw KeynestError.unauthorized
        case 403:
            throw KeynestError.forbidden
        case 408, 429, 500...599:
            if let cached = try readEnvelopeAtKey(cacheKey) {
                let plain = try decryptEnvelopeData(cached, address: address)
                return KeynestRenderedResult(data: plain, version: cached.version, source: .cache)
            }
            throw KeynestError.centerUnavailable
        default:
            throw KeynestError.httpStatus(http.statusCode)
        }
    }

    private func performRefresh(address: KeynestAddress) async throws -> KeynestRefreshResult {
        let path = "/api/v1/configs/\(escape(address.project))/\(escape(address.environment))/\(escape(address.service))"
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")

        if let cached = try readEnvelope(address) {
            request.setValue("\"\(cached.version)\"", forHTTPHeaderField: "If-None-Match")
        }

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await fetchData(for: request)
        } catch {
            if Task.isCancelled { throw KeynestError.canceled }
            if let cached = try readEnvelope(address),
               options.fallbackToCacheOnUnavailable {
                let document = try decryptEnvelope(cached, address: address)
                return KeynestRefreshResult(document: document, version: cached.version, source: .cache)
            }
            throw KeynestError.centerUnavailable
        }

        guard let http = response as? HTTPURLResponse else {
            throw KeynestError.centerUnavailable
        }
        switch http.statusCode {
        case 304:
            guard let cached = try readEnvelope(address) else {
                throw KeynestError.notModifiedWithoutCache
            }
            let document = try decryptEnvelope(cached, address: address)
            return KeynestRefreshResult(document: document, version: cached.version, source: .cache)
        case 200:
            let envelope = try JSONDecoder().decode(KeynestEnvelope.self, from: data)
            let document = try decryptEnvelope(envelope, address: address)
            try writeEnvelope(address, envelope)
            return KeynestRefreshResult(document: document, version: envelope.version, source: .network)
        case 401:
            throw KeynestError.unauthorized
        case 403:
            throw KeynestError.forbidden
        case 408, 429, 500...599:
            if let cached = try readEnvelope(address),
               options.fallbackToCacheOnUnavailable {
                let document = try decryptEnvelope(cached, address: address)
                return KeynestRefreshResult(document: document, version: cached.version, source: .cache)
            }
            throw KeynestError.centerUnavailable
        default:
            throw KeynestError.httpStatus(http.statusCode)
        }
    }

    private func fetchData(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await session.data(for: request)
    }

    private func validate(_ address: KeynestAddress) throws {
        let pattern = #"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"#
        for value in [address.project, address.environment, address.service] {
            if value.range(of: pattern, options: .regularExpression) == nil {
                throw KeynestError.invalidConfiguration("invalid Keynest address")
            }
        }
    }

    private func escape(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? value
    }

    private func cacheKey(_ address: KeynestAddress) -> String {
        let identity = "\(baseURL.absoluteString)|\(address.project)|\(address.environment)|\(address.service)"
        let digest = SHA256.hash(data: Data(identity.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func cacheURL(_ key: String) -> URL {
        cacheDirectory.appendingPathComponent("\(key).json")
    }

    private func readEnvelope(_ address: KeynestAddress) throws -> KeynestEnvelope? {
        try readEnvelopeAtKey(cacheKey(address))
    }

    private func readEnvelopeAtKey(_ key: String) throws -> KeynestEnvelope? {
        let url = cacheURL(key)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        do {
            return try JSONDecoder().decode(KeynestEnvelope.self, from: Data(contentsOf: url))
        } catch {
            throw KeynestError.cacheReadFailed
        }
    }

    private func writeEnvelope(_ address: KeynestAddress, _ envelope: KeynestEnvelope) throws {
        try writeEnvelopeAtKey(cacheKey(address), envelope)
    }

    private func writeEnvelopeAtKey(_ key: String, _ envelope: KeynestEnvelope) throws {
        guard options.cacheEnabled else { return }
        let url = cacheURL(key)
        do {
            let data = try JSONEncoder().encode(envelope)
            try data.write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUnlessOpen], ofItemAtPath: url.path)
        } catch {
            throw KeynestError.cacheWriteFailed
        }
    }

    private func decryptEnvelope(_ envelope: KeynestEnvelope, address: KeynestAddress) throws -> KeynestDocument {
        let plain = try decryptEnvelopeData(envelope, address: address)
        do {
            return try JSONDecoder().decode(KeynestDocument.self, from: plain)
        } catch {
            throw KeynestError.decryptionFailed
        }
    }

    private func decryptEnvelopeData(_ envelope: KeynestEnvelope, address: KeynestAddress) throws -> Data {
        guard envelope.algorithm == "RSA-OAEP-256+A256GCM" else {
            throw KeynestError.unsupportedAlgorithm(envelope.algorithm)
        }
        guard let encryptedKey = Data(base64Encoded: envelope.encryptedKey),
              let nonceData = Data(base64Encoded: envelope.nonce),
              let ciphertext = Data(base64Encoded: envelope.ciphertext) else {
            throw KeynestError.decryptionFailed
        }
        let privateKey: RSAOAEPPrivateKey
        do {
            privateKey = try parsePrivateKey()
        } catch {
            throw KeynestError.privateKeyInvalid
        }
        let aad = aad(keyId: envelope.keyId, address: address, version: envelope.version)
        let contentKey: Data
        do {
            contentKey = try privateKey.decryptOAEP(encryptedKey, label: aad)
        } catch {
            throw KeynestError.decryptionFailed
        }
        guard contentKey.count == 32,
              let nonce = try? AES.GCM.Nonce(data: nonceData),
              ciphertext.count >= 16 else {
            throw KeynestError.decryptionFailed
        }
        let tag = ciphertext.suffix(16)
        let body = ciphertext.prefix(ciphertext.count - 16)
        guard let sealed = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: body, tag: tag),
              let plaintext = try? AES.GCM.open(sealed, using: SymmetricKey(data: contentKey), authenticating: aad) else {
            throw KeynestError.decryptionFailed
        }
        return plaintext
    }

    private func aad(keyId: String, address: KeynestAddress, version: Int) -> Data {
        Data("\(keyId)\n\(address.project)\n\(address.environment)\n\(address.service)\n\(version)".utf8)
    }

    private func parsePrivateKey() throws -> RSAOAEPPrivateKey {
        guard var pem = String(data: privateKeyPEM, encoding: .utf8) else {
            throw KeynestError.privateKeyInvalid
        }
        pem = pem.replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
            .components(separatedBy: .whitespacesAndNewlines).joined()
        guard let der = Data(base64Encoded: pem),
              let outer = readDERValue(der, offset: 0),
              outer.item.tag == 0x30 else {
            throw KeynestError.privateKeyInvalid
        }

        let outerItems = readDERSequence(outer.item.content)
        if outerItems.count >= 3, outerItems[0].tag == 0x02, outerItems[1].tag == 0x30, outerItems[2].tag == 0x04 {
            let pkcs1 = outerItems[2].content
            return try parsePKCS1(pkcs1)
        }
        return try parsePKCS1(outer.item.content)
    }

    private func parsePKCS1(_ der: Data) throws -> RSAOAEPPrivateKey {
        guard let sequence = readDERValue(der, offset: 0),
              sequence.item.tag == 0x30 else {
            throw KeynestError.privateKeyInvalid
        }
        let items = readDERSequence(sequence.item.content)
        guard items.count >= 4,
              items[0].tag == 0x02,
              items[1].tag == 0x02,
              items[2].tag == 0x02,
              items[3].tag == 0x02 else {
            throw KeynestError.privateKeyInvalid
        }
        let modulus = bigUInt(items[1].content)
        let privateExponent = bigUInt(items[3].content)
        guard modulus > 0, privateExponent > 0 else {
            throw KeynestError.privateKeyInvalid
        }
        return RSAOAEPPrivateKey(modulus: modulus, privateExponent: privateExponent)
    }

    private func bigUInt(_ data: Data) -> BigUInt {
        let hex = data.map { String(format: "%02x", $0) }.joined()
        return BigUInt(hex, radix: 16) ?? 0
    }

    private func readDERSequence(_ data: Data) -> [DERItem] {
        var items: [DERItem] = []
        var offset = 0
        while offset < data.count {
            guard let result = readDERValue(data, offset: offset) else { break }
            items.append(result.item)
            offset = result.next
        }
        return items
    }

    private func readDERValue(_ data: Data, offset: Int) -> (item: DERItem, next: Int)? {
        guard offset + 2 <= data.count else { return nil }
        let tag = data[offset]
        var index = offset + 1
        var length: Int
        let firstLength = data[index]
        index += 1
        if firstLength & 0x80 == 0 {
            length = Int(firstLength)
        } else {
            let lengthBytes = Int(firstLength & 0x7f)
            guard lengthBytes > 0, lengthBytes <= 4, index + lengthBytes <= data.count else { return nil }
            length = 0
            for _ in 0..<lengthBytes {
                length = (length << 8) | Int(data[index])
                index += 1
            }
        }
        guard length >= 0, index + length <= data.count else { return nil }
        let content = data[index..<(index + length)]
        return (DERItem(tag: tag, content: Data(content)), index + length)
    }

    private func existingTask(_ key: String) -> Task<KeynestRefreshResult, Error>? {
        lock.lock(); defer { lock.unlock() }
        return inFlight[key]
    }

    private func setTask(_ task: Task<KeynestRefreshResult, Error>, key: String) {
        lock.lock(); defer { lock.unlock() }
        inFlight[key] = task
    }

    private func removeTask(_ key: String) {
        lock.lock(); defer { lock.unlock() }
        inFlight[key] = nil
    }

    private func lastRefreshTime(_ key: String) -> Date? {
        lock.lock(); defer { lock.unlock() }
        return lastRefresh[key]
    }

    private func setLastRefresh(_ key: String) {
        lock.lock(); defer { lock.unlock() }
        lastRefresh[key] = Date()
    }
}
