# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require_relative "secret"

module ConcertClient
  module Rm1
    TOKEN_WIRE_PREFIX = "rm1"
    HEADER_ROOM_PASS = "X-Room-Pass"
    HEADER_ROOM_LEASE = "X-Room-Lease"

    KIND_PASS = "pass"
    KIND_LEASE = "lease"
    VALID_KINDS = [KIND_PASS, KIND_LEASE].freeze

    MIN_TTL_SECONDS = 1
    DEFAULT_MAX_TTL_SECONDS = 900
    MAX_SIGNED_TTL_SECONDS = 3600
    DEFAULT_MAX_CLOCK_SKEW_SECONDS = 30
    MAX_KEY_ID_LEN = 64
    MAX_SCOPE_LEN = 256
    MAX_SIGNED_TOKEN_LEN = 4096

    ED25519_SEED_SIZE = 32
    ED25519_PRIVATE_KEY_SIZE = 64
    ED25519_PUBLIC_KEY_SIZE = 32
    ED25519_SIGNATURE_SIZE = 64

    REJECT_MISSING_SCOPE = "missing_scope"
    REJECT_NO_VERIFIER = "no_verifier"
    REJECT_MALFORMED = "malformed"
    REJECT_UNKNOWN_KEY = "unknown_key"
    REJECT_INVALID_SIGNATURE = "invalid_signature"
    REJECT_EXPIRED = "expired"
    REJECT_FUTURE_ISSUED = "future_issued"
    REJECT_WRONG_SCOPE = "wrong_scope"
    REJECT_WRONG_KIND = "wrong_kind"
    REJECT_KEY_MISMATCH = "key_mismatch"

    ALLOWED_CLAIM_KEYS = %w[kid kind scope key iat exp].freeze

    class Error < ArgumentError; end
    class UnsupportedCryptoError < RuntimeError; end

    class VerificationError < Error
      attr_reader :reason

      def initialize(reason, message = nil)
        @reason = reason
        super(message || "rm1 token verification failed: #{reason}")
      end
    end

    # Authenticated payload inside an `rm1` signed pass or lease envelope.
    class Claims
      attr_reader :kid, :kind, :scope, :key, :iat, :exp

      def initialize(kid:, kind:, scope:, iat:, exp:, key: "")
        @kid = kid
        @kind = kind
        @scope = scope
        @key = key.to_s
        @iat = iat
        @exp = exp
        freeze
      end

      def to_h
        h = { "kid" => @kid, "kind" => @kind, "scope" => @scope }
        h["key"] = @key unless @key.empty?
        h["iat"] = @iat
        h["exp"] = @exp
        h
      end

      def ==(other)
        other.is_a?(Claims) &&
          kid == other.kid &&
          kind == other.kind &&
          scope == other.scope &&
          key == other.key &&
          iat == other.iat &&
          exp == other.exp
      end
    end

    # Unverified parsed envelope components.
    class Envelope
      attr_reader :claims, :signing_input, :signature

      def initialize(claims:, signing_input:, signature:)
        @claims = claims
        @signing_input = signing_input.dup.force_encoding(Encoding::BINARY).freeze
        @signature = signature.dup.force_encoding(Encoding::BINARY).freeze
        freeze
      end
    end

    module_function

    def ed25519_supported?
      return false unless OpenSSL::PKey.respond_to?(:new_raw_private_key) && OpenSSL::PKey.respond_to?(:new_raw_public_key)

      key = OpenSSL::PKey.new_raw_private_key("ED25519", "\x01".b * ED25519_SEED_SIZE)
      sig = key.sign(nil, "probe")
      sig.bytesize == ED25519_SIGNATURE_SIZE
    rescue StandardError
      false
    end

    def b64url_encode(bytes)
      Base64.urlsafe_encode64(bytes, padding: false)
    end

    def b64url_decode_strict(segment)
      if !segment.is_a?(String) || segment.empty? || segment.include?("=") || !/\A[A-Za-z0-9_-]+\z/.match?(segment)
        raise VerificationError.new(REJECT_MALFORMED, "invalid base64url segment")
      end

      rem = segment.bytesize % 4
      raise VerificationError.new(REJECT_MALFORMED, "invalid base64url length") if rem == 1

      padded = rem.zero? ? segment : segment + ("=" * (4 - rem))
      raw = Base64.urlsafe_decode64(padded)
      raise VerificationError.new(REJECT_MALFORMED, "non-canonical base64url encoding") unless b64url_encode(raw) == segment

      raw.force_encoding(Encoding::BINARY)
    rescue ArgumentError
      raise VerificationError.new(REJECT_MALFORMED, "failed to decode base64url")
    end

    def validate_key_id!(kid)
      raise Error, "key ID must not be empty" unless kid.is_a?(String) && !kid.empty?
      raise Error, "key ID exceeds #{MAX_KEY_ID_LEN} bytes" if kid.bytesize > MAX_KEY_ID_LEN
      raise Error, "key ID contains control characters" if kid.include?("\r") || kid.include?("\n") || kid.include?("\0")
    end

    def validate_scope!(scope)
      raise Error, "scope must not be empty" unless scope.is_a?(String) && !scope.empty?
      raise Error, "scope exceeds #{MAX_SCOPE_LEN} bytes" if scope.bytesize > MAX_SCOPE_LEN
      raise Error, "scope contains control characters" if scope.include?("\r") || scope.include?("\n") || scope.include?("\0")
    end

    def validate_key_binding!(key, required:)
      raise Error, "key must be a String" unless key.is_a?(String)
      raise Error, "lease tokens require a non-empty key binding" if required && key.empty?
      if !key.empty? && (key.include?("\r") || key.include?("\n") || key.include?("\0") || key.bytesize > 256)
        raise Error, "invalid token key binding"
      end
    end

    def encode_claims(claims)
      raise Error, "claims must be a ConcertClient::Rm1::Claims" unless claims.is_a?(Claims)

      validate_key_id!(claims.kid)
      validate_scope!(claims.scope)
      raise Error, "unknown token kind #{claims.kind.inspect}" unless VALID_KINDS.include?(claims.kind)

      validate_key_binding!(claims.key, required: claims.kind == KIND_LEASE)
      raise Error, "iat must be a positive Integer" unless claims.iat.is_a?(Integer) && claims.iat > 0
      raise Error, "exp must be an Integer strictly greater than iat" unless claims.exp.is_a?(Integer) && claims.exp > claims.iat

      raw_json = JSON.generate(claims.to_h)
      b64url_encode(raw_json.encode(Encoding::UTF_8))
    end

    def encode_signing_input(claims)
      "#{TOKEN_WIRE_PREFIX}.#{encode_claims(claims)}".b
    end

    def assemble_envelope(claims, signature)
      raise Error, "signature must be non-empty String bytes" unless signature.is_a?(String) && !signature.empty?

      signing_input = encode_signing_input(claims)
      "#{signing_input}.#{b64url_encode(signature.b)}"
    end

    def parse_envelope(token)
      if !token.is_a?(String) || token.empty? || token.bytesize > MAX_SIGNED_TOKEN_LEN
        raise VerificationError.new(REJECT_MALFORMED, "token empty or exceeds maximum length")
      end

      parts = token.split(".", -1)
      if parts.length != 3 || parts[0] != TOKEN_WIRE_PREFIX || parts[1].empty? || parts[2].empty?
        raise VerificationError.new(REJECT_MALFORMED, "invalid rm1 envelope framing")
      end

      payload_bytes = b64url_decode_strict(parts[1])
      sig_bytes = b64url_decode_strict(parts[2])
      raise VerificationError.new(REJECT_MALFORMED, "empty signature") if sig_bytes.empty?

      parsed = JSON.parse(payload_bytes.force_encoding(Encoding::UTF_8))
      raise VerificationError.new(REJECT_MALFORMED, "claims payload must be a JSON object") unless parsed.is_a?(Hash)

      unknown = parsed.keys - ALLOWED_CLAIM_KEYS
      raise VerificationError.new(REJECT_MALFORMED, "claims contain unknown fields") unless unknown.empty?

      kid = parsed["kid"]
      kind = parsed["kind"]
      scope = parsed["scope"]
      key = parsed.key?("key") ? parsed["key"] : ""
      iat = parsed["iat"]
      exp = parsed["exp"]

      if !kid.is_a?(String) || kid.empty? || kid.bytesize > MAX_KEY_ID_LEN
        raise VerificationError.new(REJECT_MALFORMED, "invalid kid claim")
      end
      if !scope.is_a?(String) || scope.empty? || scope.bytesize > MAX_SCOPE_LEN
        raise VerificationError.new(REJECT_MALFORMED, "invalid scope claim")
      end
      raise VerificationError.new(REJECT_MALFORMED, "invalid kind claim") unless VALID_KINDS.include?(kind)
      raise VerificationError.new(REJECT_MALFORMED, "invalid key claim") unless key.is_a?(String)
      raise VerificationError.new(REJECT_MALFORMED, "invalid iat claim") unless iat.is_a?(Integer) && iat > 0
      raise VerificationError.new(REJECT_MALFORMED, "invalid exp claim") unless exp.is_a?(Integer) && exp > iat

      claims = Claims.new(kid: kid, kind: kind, scope: scope, key: key, iat: iat, exp: exp)
      Envelope.new(claims: claims, signing_input: "#{TOKEN_WIRE_PREFIX}.#{parts[1]}".b, signature: sig_bytes)
    rescue JSON::ParserError, Encoding::UndefinedConversionError
      raise VerificationError.new(REJECT_MALFORMED, "invalid JSON payload")
    end

    def decode_key_material(raw, expected_lengths:)
      str = raw.is_a?(Secret) ? raw.reveal : raw
      raise Error, "key material must be a String" unless str.is_a?(String)

      bin = str.b
      return bin if expected_lengths.include?(bin.bytesize)

      text = str.strip
      raise Error, "key material must not be empty" if text.empty?

      if /\A[0-9a-fA-F]+\z/.match?(text) && text.bytesize.even? && expected_lengths.include?(text.bytesize / 2)
        return [text].pack("H*")
      end

      pad = (4 - (text.bytesize % 4)) % 4
      padded = text + ("=" * pad)
      [Base64.method(:urlsafe_decode64), Base64.method(:strict_decode64)].each do |dec|
        begin
          decoded = dec.call(padded).b
          return decoded if expected_lengths.include?(decoded.bytesize)
        rescue ArgumentError
          next
        end
      end

      raise Error, "key material is not a valid raw, hex, or base64url Ed25519 key"
    end

    # Signs `rm1` envelopes using OpenSSL Ed25519 (when supported by the runtime)
    # or an optional custom `sign_proc`. Never reveals key material in `inspect`/`to_s`.
    class Ed25519Signer
      attr_reader :key_id

      def initialize(key_id, private_key, sign_proc: nil)
        Rm1.validate_key_id!(key_id)
        @key_id = key_id.dup.freeze
        @sign_proc = sign_proc
        raw = Rm1.decode_key_material(
          private_key,
          expected_lengths: [ED25519_SEED_SIZE, ED25519_PRIVATE_KEY_SIZE]
        )
        @seed = Secret.new(raw.byteslice(0, ED25519_SEED_SIZE), name: "ed25519 private seed", binary: true)
      end

      def sign(signing_input)
        data = signing_input.to_s.b
        if @sign_proc
          sig = @sign_proc.call(data).to_s.b
          raise Error, "custom sign_proc must return 64 bytes" unless sig.bytesize == ED25519_SIGNATURE_SIZE

          return sig
        end

        unless Rm1.ed25519_supported?
          raise UnsupportedCryptoError,
                "OpenSSL in this Ruby runtime (#{OpenSSL::OPENSSL_VERSION}) does not support Ed25519; " \
                "upgrade to Ruby 3.0+ linked against OpenSSL 1.1.1+/3.x or supply a custom sign_proc"
        end

        pkey = OpenSSL::PKey.new_raw_private_key("ED25519", @seed.reveal)
        pkey.sign(nil, data).b
      end

      def public_key_bytes
        unless Rm1.ed25519_supported?
          raise UnsupportedCryptoError,
                "OpenSSL in this Ruby runtime (#{OpenSSL::OPENSSL_VERSION}) does not support Ed25519"
        end

        pkey = OpenSSL::PKey.new_raw_private_key("ED25519", @seed.reveal)
        pkey.raw_public_key.b
      end

      def to_s
        "#<ConcertClient::Rm1::Ed25519Signer key_id=#{@key_id.inspect} private_key=#{REDACTED}>"
      end
      alias inspect to_s
    end

    # Verifies `rm1` envelopes against a key ring `{ kid => pubkey_bytes_or_hex_or_b64url }`.
    class Ed25519Verifier
      def initialize(keys, verify_proc: nil)
        raise Error, "at least one verification public key is required" unless keys.is_a?(Hash) && !keys.empty?

        @keys = {}
        keys.each do |kid, pub|
          kid_s = kid.to_s
          Rm1.validate_key_id!(kid_s)
          @keys[kid_s] = Rm1.decode_key_material(pub, expected_lengths: [ED25519_PUBLIC_KEY_SIZE]).freeze
        end
        @keys.freeze
        @verify_proc = verify_proc
      end

      def verify_signature(key_id, signing_input, signature)
        pub = @keys[key_id]
        raise VerificationError.new(REJECT_UNKNOWN_KEY, "unknown key ID #{key_id.inspect}") if pub.nil?
        unless signature.bytesize == ED25519_SIGNATURE_SIZE
          raise VerificationError.new(REJECT_INVALID_SIGNATURE, "invalid Ed25519 signature length")
        end

        if @verify_proc
          ok = @verify_proc.call(pub, signing_input, signature)
          raise VerificationError.new(REJECT_INVALID_SIGNATURE, "invalid signature") unless ok

          return true
        end

        unless Rm1.ed25519_supported?
          raise UnsupportedCryptoError,
                "OpenSSL in this Ruby runtime (#{OpenSSL::OPENSSL_VERSION}) does not support Ed25519; " \
                "upgrade to Ruby 3.0+ linked against OpenSSL 1.1.1+/3.x or supply a custom verify_proc"
        end

        pkey = OpenSSL::PKey.new_raw_public_key("ED25519", pub)
        ok = pkey.verify(nil, signature, signing_input)
        raise VerificationError.new(REJECT_INVALID_SIGNATURE, "invalid Ed25519 signature") unless ok

        true
      rescue OpenSSL::PKey::PKeyError
        raise VerificationError.new(REJECT_INVALID_SIGNATURE, "invalid Ed25519 signature")
      end

      def verify(token, expected_scope:, expected_kind: KIND_PASS, expected_key: "", now: nil, max_skew_seconds: DEFAULT_MAX_CLOCK_SKEW_SECONDS)
        raise VerificationError.new(REJECT_MISSING_SCOPE, "expected_scope must not be empty") if expected_scope.to_s.empty?
        raise Error, "unknown expected_kind #{expected_kind.inspect}" unless VALID_KINDS.include?(expected_kind)

        env = Rm1.parse_envelope(token)
        claims = env.claims

        # 3. Cryptographic check before scope/expiry.
        verify_signature(claims.kid, env.signing_input, env.signature)

        # 4. Scope, kind, and key binding.
        raise VerificationError.new(REJECT_WRONG_SCOPE, "token scope mismatch") unless claims.scope == expected_scope
        raise VerificationError.new(REJECT_WRONG_KIND, "token kind mismatch") unless claims.kind == expected_kind

        if expected_kind == KIND_LEASE
          raise VerificationError.new(REJECT_MALFORMED, "lease token missing key binding") if claims.key.empty?
          raise VerificationError.new(REJECT_KEY_MISMATCH, "lease token key mismatch") unless claims.key == expected_key
        elsif !claims.key.empty? && claims.key != expected_key
          raise VerificationError.new(REJECT_KEY_MISMATCH, "pass token key mismatch")
        end

        # 5. Clock skew and expiry.
        now_ts = now.nil? ? Time.now.to_i : now.to_i
        skew = [0, max_skew_seconds.to_i].max
        raise VerificationError.new(REJECT_FUTURE_ISSUED, "token issued in the future") if claims.iat > now_ts + skew
        raise VerificationError.new(REJECT_EXPIRED, "token expired") if now_ts >= claims.exp

        claims
      end
    end

    # Standalone `rm1` pass and lease issuer bound to a scope and signer.
    class TokenIssuer
      attr_reader :scope, :max_ttl_seconds

      def initialize(scope, signer, max_ttl_seconds: DEFAULT_MAX_TTL_SECONDS, clock: nil)
        Rm1.validate_scope!(scope)
        raise Error, "signer must respond to #key_id and #sign" unless signer.respond_to?(:key_id) && signer.respond_to?(:sign)
        unless max_ttl_seconds.is_a?(Integer) && max_ttl_seconds >= MIN_TTL_SECONDS && max_ttl_seconds <= MAX_SIGNED_TTL_SECONDS
          raise Error, "max_ttl_seconds must be between #{MIN_TTL_SECONDS} and #{MAX_SIGNED_TTL_SECONDS}"
        end

        @scope = scope.dup.freeze
        @signer = signer
        @max_ttl_seconds = max_ttl_seconds
        @clock = clock || -> { Time.now.to_i }
      end

      def mint_pass(key: "", ttl_seconds: 300)
        mint(KIND_PASS, key: key, ttl_seconds: ttl_seconds)
      end

      def mint_lease(key, ttl_seconds: 300)
        mint(KIND_LEASE, key: key, ttl_seconds: ttl_seconds)
      end

      private

      def mint(kind, key:, ttl_seconds:)
        unless ttl_seconds.is_a?(Integer) && ttl_seconds >= MIN_TTL_SECONDS && ttl_seconds <= @max_ttl_seconds
          raise Error, "ttl_seconds must be between #{MIN_TTL_SECONDS} and #{@max_ttl_seconds}"
        end

        Rm1.validate_key_binding!(key, required: kind == KIND_LEASE)
        iat = @clock.call.to_i
        claims = Claims.new(
          kid: @signer.key_id,
          kind: kind,
          scope: @scope,
          key: key,
          iat: iat,
          exp: iat + ttl_seconds
        )
        sig = @signer.sign(Rm1.encode_signing_input(claims))
        Rm1.assemble_envelope(claims, sig)
      end
    end
  end
end
