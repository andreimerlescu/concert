# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"
require "uri"
require_relative "secret"

module ConcertClient
  class CachePurgeError < RuntimeError
    attr_reader :status_code

    def initialize(message, status_code: nil)
      @status_code = status_code
      super(message)
    end
  end

  PurgeResult = Struct.new(:purged, :mode, keyword_init: true)

  # Authenticated client for Concert's `POST /_room/cache/purge` endpoint.
  # Pure Ruby stdlib (`net/http`, `json`, `openssl`) with strict timeouts,
  # TLS verification, bounded response reads, and secret redaction.
  class CachePurgeClient
    PURGE_PATH = "/_room/cache/purge"
    VALID_MODES = %w[url prefix tag all].freeze
    ENV_BASE_URL = "CONCERT_URL"
    ENV_ADMIN_AUTH = "CONCERT_ADMIN_TOKEN"
    ENV_ADMIN_AUTH_FILE = "CONCERT_ADMIN_TOKEN_FILE"
    DEFAULT_TIMEOUT = 10.0
    MAX_TIMEOUT = 120.0
    DEFAULT_MAX_RESPONSE_BYTES = 65_536
    LOOPBACK_HOSTS = %w[localhost 127.0.0.1 ::1].freeze

    attr_reader :base_url

    def initialize(
      base_url,
      token,
      timeout: DEFAULT_TIMEOUT,
      max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
      allow_insecure_http: false
    )
      @base_uri = validate_base_url(base_url, allow_insecure_http: allow_insecure_http)
      @base_url = @base_uri.to_s.chomp("/").freeze
      @token = token.is_a?(Secret) ? token : Secret.new(token, name: "admin token")

      unless timeout.is_a?(Numeric) && timeout > 0 && timeout <= MAX_TIMEOUT
        raise ArgumentError, "timeout must be between 0 and #{MAX_TIMEOUT} seconds"
      end
      unless max_response_bytes.is_a?(Integer) && max_response_bytes >= 256
        raise ArgumentError, "max_response_bytes must be an Integer >= 256"
      end

      @timeout = timeout.to_f
      @max_response_bytes = max_response_bytes
    end

    def self.from_env(
      url_env: ENV_BASE_URL,
      token_env: nil,
      token_file_env: nil,
      env: ENV,
      timeout: DEFAULT_TIMEOUT,
      allow_insecure_http: false
    )
      base_url = env[url_env].to_s.strip
      raise ArgumentError, "missing required environment variable: #{url_env}" if base_url.empty?

      auth_var = token_env || ENV_ADMIN_AUTH
      auth_file_var = token_file_env || ENV_ADMIN_AUTH_FILE
      secret = Secret.from_env_or_file(auth_var, auth_file_var, env: env)
      new(base_url, secret, timeout: timeout, allow_insecure_http: allow_insecure_http)
    end

    def purge(mode, target: "", host: "")
      raise ArgumentError, "mode must be a String or Symbol" unless mode.is_a?(String) || mode.is_a?(Symbol)

      norm_mode = mode.to_s.strip.downcase
      unless VALID_MODES.include?(norm_mode)
        raise ArgumentError, "mode must be one of: #{VALID_MODES.join(', ')}"
      end

      norm_target = target.to_s.strip
      norm_host = host.to_s.strip
      if %w[url prefix tag].include?(norm_mode) && norm_target.empty?
        raise ArgumentError, "target is required for purge mode #{norm_mode.inspect}"
      end

      uri = URI.parse("#{@base_url}#{PURGE_PATH}")
      req = Net::HTTP::Post.new(uri.request_uri)
      req["Authorization"] = "Bearer #{@token.reveal}"
      req["Content-Type"] = "application/json"
      req["Accept"] = "application/json"
      req.body = JSON.generate("mode" => norm_mode, "host" => norm_host, "target" => norm_target)

      status, raw_body = execute_bounded(uri, req)
      unless status >= 200 && status < 300
        detail = extract_error_detail(raw_body)
        raise CachePurgeError.new("cache purge failed with HTTP #{status}: #{detail}", status_code: status)
      end

      parsed = JSON.parse(raw_body)
      unless parsed.is_a?(Hash) && parsed["purged"].is_a?(Integer)
        raise CachePurgeError, "cache purge response missing integer 'purged' field"
      end

      PurgeResult.new(purged: parsed["purged"], mode: (parsed["mode"] || norm_mode).to_s)
    rescue JSON::ParserError
      raise CachePurgeError, "cache purge returned invalid JSON"
    end

    def purge_url(url, host: "")
      purge("url", target: url, host: host)
    end

    def purge_prefix(prefix, host: "")
      purge("prefix", target: prefix, host: host)
    end

    def purge_tag(tag, host: "")
      purge("tag", target: tag, host: host)
    end

    def purge_all(host: "")
      purge("all", host: host)
    end

    def to_s
      "#<ConcertClient::CachePurgeClient base_url=#{@base_url.inspect} token=#{REDACTED} timeout=#{@timeout}>"
    end
    alias inspect to_s

    private

    def validate_base_url(raw, allow_insecure_http:)
      raise ArgumentError, "base_url must not be empty" unless raw.is_a?(String) && !raw.strip.empty?

      uri = URI.parse(raw.strip)
      scheme = uri.scheme.to_s.downcase
      raise ArgumentError, "base_url must use https:// (or http:// for loopback)" unless %w[http https].include?(scheme)
      raise ArgumentError, "base_url must include a host" if uri.host.to_s.empty?
      raise ArgumentError, "base_url must not embed credentials (S4)" if uri.user || uri.password

      host = uri.host.downcase.delete("[]")
      if scheme == "http" && !allow_insecure_http && !LOOPBACK_HOSTS.include?(host)
        raise ArgumentError, "insecure http:// base_url is restricted to localhost/loopback"
      end

      uri
    rescue URI::InvalidURIError => e
      raise ArgumentError, "invalid base_url: #{e.message}"
    end

    def execute_bounded(uri, req)
      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = @timeout
      http.read_timeout = @timeout
      http.write_timeout = @timeout if http.respond_to?(:write_timeout=)
      if uri.scheme == "https"
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      end

      status = nil
      body = +"".b
      http.start do |conn|
        conn.request(req) do |resp|
          status = resp.code.to_i
          resp.read_body do |chunk|
            if body.bytesize + chunk.bytesize > @max_response_bytes
              raise CachePurgeError, "response body exceeded maximum allowed size (#{@max_response_bytes} bytes)"
            end

            body << chunk.b
          end
        end
      end
      [status, body.force_encoding(Encoding::UTF_8)]
    rescue Timeout::Error, Errno::ECONNREFUSED, Errno::ECONNRESET, SocketError, OpenSSL::SSL::SSLError => e
      raise CachePurgeError, "cache purge transport error: #{e.class}: #{e.message}"
    end

    def extract_error_detail(body)
      return "no error body" if body.nil? || body.empty?

      obj = JSON.parse(body)
      return obj["error"].to_s[0, 256] if obj.is_a?(Hash) && obj["error"].is_a?(String)

      "unexpected error response"
    rescue JSON::ParserError
      "unexpected error response"
    end
  end
end
