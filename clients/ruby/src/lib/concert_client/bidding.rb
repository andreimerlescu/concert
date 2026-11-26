# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"
require "uri"
require_relative "secret"

module ConcertClient
  class BiddingError < RuntimeError
    attr_reader :status_code

    def initialize(message, status_code: nil)
      @status_code = status_code
      super(message)
    end
  end

  class UnsupportedChainError < ArgumentError; end
  class BidCapExceededError < ArgumentError; end
  class CrossOriginError < ArgumentError; end

  # 100% Crypto-Only AI Agent Pass Bidding client for Concert.
  # Supported chains ONLY: xrpl, stellar, hedera, solana (ZERO fiat).
  class AgentBidClient
    SUPPORTED_CHAINS = %w[xrpl stellar hedera solana].freeze
    DEFAULT_BID_PATH = "/_concert/bids"
    DEFAULT_STATUS_PATH = "/_concert/bids/status"
    MODE_INSTANT = "instant"
    MODE_AUCTION = "auction"
    TERMINAL_STATUSES = %w[won lost rejected settled settlement_failed].freeze
    DEFAULT_TIMEOUT = 10.0
    MAX_TIMEOUT = 120.0
    DEFAULT_MAX_RESPONSE_BYTES = 1_048_576
    MAX_MICRO_USD = (1 << 63) - 1
    LOOPBACK_HOSTS = %w[localhost 127.0.0.1 ::1].freeze

    AuctionOffer = Struct.new(
      :mode,
      :auction_id,
      :scope,
      :floor_micro_usd,
      :closes_at,
      :slots,
      :min_wait_seconds,
      :bid_url,
      :status_url,
      :supported_chains,
      keyword_init: true
    )

    # Normalized response from POST /_concert/bids or GET /_concert/bids/status.
    class BidStatusResponse
      attr_reader :bid_id, :status, :pass_token, :priority_pass, :pass_cookie,
                  :session, :transaction, :reason, :status_url, :set_cookies

      def initialize(
        bid_id:,
        status:,
        pass_issued: false,
        pass_token: "",
        priority_pass: "",
        pass_cookie: "",
        session: "",
        transaction: "",
        reason: "",
        status_url: "",
        set_cookies: []
      )
        @bid_id = bid_id.to_s
        @status = status.to_s
        @pass_issued = !!pass_issued
        @pass_token = pass_token.to_s
        @priority_pass = priority_pass.to_s
        @pass_cookie = pass_cookie.to_s
        @session = session.to_s
        @transaction = transaction.to_s
        @reason = reason.to_s
        @status_url = status_url.to_s
        @set_cookies = Array(set_cookies).map(&:to_s).freeze
        freeze
      end

      def pass_issued?
        @pass_issued
      end

      def terminal?
        TERMINAL_STATUSES.include?(@status)
      end

      def settled?
        @status == "settled"
      end

      def to_s
        tok = @pass_token.empty? ? "" : REDACTED
        "#<ConcertClient::AgentBidClient::BidStatusResponse bid_id=#{@bid_id.inspect} " \
          "status=#{@status.inspect} pass_issued=#{@pass_issued} transaction=#{@transaction.inspect} " \
          "pass_token=#{tok.inspect}>"
      end
      alias inspect to_s
    end

    attr_reader :base_url, :max_bid_micro_usd, :chain, :asset

    def self.normalize_chain(chain)
      raise UnsupportedChainError, "chain must be a String or Symbol" unless chain.is_a?(String) || chain.is_a?(Symbol)

      norm = chain.to_s.strip.downcase
      unless SUPPORTED_CHAINS.include?(norm)
        raise UnsupportedChainError,
              "unsupported chain #{chain.inspect}; Concert is 100% crypto-only and accepts only: #{SUPPORTED_CHAINS.join(', ')}"
      end

      norm
    end

    def self.parse_usd_to_micro_usd(raw)
      raise ArgumentError, "USD amount must be a String" unless raw.is_a?(String)

      s = raw.strip
      raise ArgumentError, "USD amount must be strictly positive" if s.empty? || s.start_with?("+", "-")
      raise ArgumentError, "USD amount contains multiple decimal points" if s.count(".") > 1

      int_part, frac_part = s.split(".", 2)
      frac_part ||= ""
      raise ArgumentError, "USD amount must not be empty" if int_part.to_s.empty? && frac_part.empty?

      int_part = "0" if int_part.to_s.empty?
      if frac_part.bytesize > 6
        extra = frac_part[6..].sub(/0+\z/, "")
        raise ArgumentError, "USD amount supports at most 6 fractional digits" unless extra.empty?

        frac_part = frac_part[0, 6]
      end
      frac_part = frac_part.ljust(6, "0")
      digits = int_part + frac_part
      raise ArgumentError, "USD amount contains non-digit characters" unless /\A\d+\z/.match?(digits)

      value = digits.to_i
      raise ArgumentError, "USD amount must be positive and within int64 micro-USD bounds" if value <= 0 || value > MAX_MICRO_USD

      value
    end

    def self.format_micro_usd(micro_usd)
      return "$0.00" unless micro_usd.is_a?(Integer) && micro_usd > 0

      dollars = micro_usd / 1_000_000
      frac = format("%06d", micro_usd % 1_000_000)
      trimmed = frac.sub(/0+\z/, "")
      trimmed = frac[0, 2] if trimmed.bytesize < 2
      "$#{dollars}.#{trimmed}"
    end

    def self.resolve_same_origin_url(base_url, candidate)
      raise CrossOriginError, "URL must not be empty" unless candidate.is_a?(String) && !candidate.strip.empty?

      cand = candidate.strip
      if cand.include?("\r") || cand.include?("\n") || cand.include?("\0")
        raise CrossOriginError, "URL contains control characters"
      end

      base = URI.parse(base_url)
      resolved = URI.join("#{base_url.chomp('/')}/", cand)
      if resolved.scheme.to_s.downcase != base.scheme.to_s.downcase ||
         resolved.host.to_s.downcase != base.host.to_s.downcase ||
         resolved.port != base.port
        raise CrossOriginError, "auction URL origin does not match Concert origin"
      end
      raise CrossOriginError, "auction URL must not embed credentials" if resolved.user || resolved.password

      resolved
    rescue URI::InvalidURIError => e
      raise CrossOriginError, "invalid auction URL: #{e.message}"
    end

    def self.parse_auction_offer(payload, status_code: 429)
      return nil unless status_code == 429

      obj = payload.is_a?(Hash) ? payload : JSON.parse(payload.to_s)
      return nil unless obj.is_a?(Hash)

      raw_offer = if obj.key?("auction")
                    obj["auction"]
                  elsif obj.key?(:auction)
                    obj[:auction]
                  elsif obj.key?("floor_micro_usd") || obj.key?(:floor_micro_usd)
                    obj
                  end
      return nil unless raw_offer.is_a?(Hash)

      mode = (raw_offer["mode"] || raw_offer[:mode]).to_s.strip.downcase
      raise BiddingError, "unsupported auction offer mode #{mode.inspect}" unless [MODE_INSTANT, MODE_AUCTION].include?(mode)

      floor = raw_offer["floor_micro_usd"] || raw_offer[:floor_micro_usd]
      raise BiddingError, "auction offer missing positive integer floor_micro_usd" unless floor.is_a?(Integer) && floor > 0

      raw_chains = raw_offer["supported_chains"] || raw_offer[:supported_chains] || []
      raise BiddingError, "auction offer supported_chains must be an Array" unless raw_chains.is_a?(Array)

      chains = []
      raw_chains.each do |item|
        low = item.to_s.strip.downcase
        chains << low if SUPPORTED_CHAINS.include?(low) && !chains.include?(low)
      end

      slots = raw_offer["slots"] || raw_offer[:slots]
      slots = 1 unless slots.is_a?(Integer) && slots >= 0
      min_wait = raw_offer["min_wait_seconds"] || raw_offer[:min_wait_seconds]
      min_wait = 0 unless min_wait.is_a?(Integer) && min_wait >= 0

      bid_url = (raw_offer["bid_url"] || raw_offer[:bid_url]).to_s
      bid_url = DEFAULT_BID_PATH if bid_url.empty?
      status_url = (raw_offer["status_url"] || raw_offer[:status_url]).to_s
      status_url = DEFAULT_STATUS_PATH if status_url.empty?

      AuctionOffer.new(
        mode: mode,
        auction_id: (raw_offer["auction_id"] || raw_offer[:auction_id]).to_s,
        scope: (raw_offer["scope"] || raw_offer[:scope]).to_s,
        floor_micro_usd: floor,
        closes_at: (raw_offer["closes_at"] || raw_offer[:closes_at]).to_s,
        slots: slots,
        min_wait_seconds: min_wait,
        bid_url: bid_url,
        status_url: status_url,
        supported_chains: chains.freeze
      )
    rescue JSON::ParserError
      raise BiddingError, "invalid JSON in 429 auction response"
    end

    def initialize(
      base_url,
      max_bid_micro_usd:,
      chain:,
      asset: "",
      session_id: nil,
      timeout: DEFAULT_TIMEOUT,
      max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
      allow_insecure_http: false
    )
      @base_uri = validate_base_url(base_url, allow_insecure_http: allow_insecure_http)
      @base_url = @base_uri.to_s.chomp("/").freeze
      unless max_bid_micro_usd.is_a?(Integer) && max_bid_micro_usd > 0 && max_bid_micro_usd <= MAX_MICRO_USD
        raise ArgumentError, "max_bid_micro_usd must be a positive Integer within int64 bounds"
      end

      @max_bid_micro_usd = max_bid_micro_usd
      @chain = self.class.normalize_chain(chain)
      @asset = asset.to_s.strip.freeze
      @session_id = if session_id.nil?
                      nil
                    elsif session_id.is_a?(Secret)
                      session_id
                    else
                      Secret.new(session_id, name: "session_id")
                    end

      unless timeout.is_a?(Numeric) && timeout > 0 && timeout <= MAX_TIMEOUT
        raise ArgumentError, "timeout must be between 0 and #{MAX_TIMEOUT} seconds"
      end
      unless max_response_bytes.is_a?(Integer) && max_response_bytes >= 256
        raise ArgumentError, "max_response_bytes must be an Integer >= 256"
      end

      @timeout = timeout.to_f
      @max_response_bytes = max_response_bytes
    end

    def evaluate_offer(offer)
      return nil unless offer.supported_chains.include?(@chain)
      return nil if offer.floor_micro_usd > @max_bid_micro_usd
      return offer.floor_micro_usd if offer.mode == MODE_INSTANT

      @max_bid_micro_usd
    end

    def submit_bid(
      bid_micro_usd:,
      amount_atomic:,
      payment_payload:,
      chain: nil,
      asset: nil,
      scope: "",
      auction_id: "",
      bid_id: "",
      agent_key: "",
      bid_url: DEFAULT_BID_PATH
    )
      raise ArgumentError, "bid_micro_usd must be a positive Integer" unless bid_micro_usd.is_a?(Integer) && bid_micro_usd > 0

      if bid_micro_usd > @max_bid_micro_usd
        raise BidCapExceededError,
              "bid #{self.class.format_micro_usd(bid_micro_usd)} exceeds configured max_bid_micro_usd " \
              "(#{self.class.format_micro_usd(@max_bid_micro_usd)})"
      end

      active_chain = self.class.normalize_chain(chain.nil? ? @chain : chain)
      active_asset = (asset.nil? ? @asset : asset).to_s.strip
      atomic_s = amount_atomic.to_s.strip
      unless /\A\d+\z/.match?(atomic_s) && atomic_s.to_i > 0
        raise ArgumentError, "amount_atomic must be a positive integer string"
      end

      coerced_payload = coerce_payment_payload(payment_payload)
      target_uri = self.class.resolve_same_origin_url(@base_url, bid_url)

      body = {
        "chain" => active_chain,
        "asset" => active_asset,
        "amount_atomic" => atomic_s,
        "bid_micro_usd" => bid_micro_usd,
        "payment_payload" => coerced_payload
      }
      body["bid_id"] = bid_id.to_s.strip unless bid_id.to_s.strip.empty?
      body["auction_id"] = auction_id.to_s.strip unless auction_id.to_s.strip.empty?
      body["scope"] = scope.to_s.strip unless scope.to_s.strip.empty?
      body["agent_key"] = agent_key.to_s.strip unless agent_key.to_s.strip.empty?

      req = Net::HTTP::Post.new(target_uri.request_uri)
      req["Content-Type"] = "application/json"
      req["Accept"] = "application/json"
      req["Concert-Session"] = @session_id.reveal unless @session_id.nil?
      req.body = JSON.generate(body)

      execute_bid_request(target_uri, req)
    end

    def bid_status(bid_id, status_url: DEFAULT_STATUS_PATH)
      clean_id = bid_id.to_s.strip
      raise ArgumentError, "bid_id must not be empty" if clean_id.empty?

      target_uri = self.class.resolve_same_origin_url(@base_url, status_url)
      existing = URI.decode_www_form(target_uri.query || "")
      existing << ["bid_id", clean_id]
      target_uri.query = URI.encode_www_form(existing)

      req = Net::HTTP::Get.new(target_uri.request_uri)
      req["Accept"] = "application/json"
      req["Concert-Session"] = @session_id.reveal unless @session_id.nil?

      execute_bid_request(target_uri, req)
    end

    def poll_bid_status(bid_id, status_url: DEFAULT_STATUS_PATH, poll_interval: 1.0, max_attempts: 30, sleep_proc: nil)
      unless max_attempts.is_a?(Integer) && max_attempts >= 1 && max_attempts <= 300
        raise ArgumentError, "max_attempts must be between 1 and 300"
      end

      interval = [[poll_interval.to_f, 0.05].max, 30.0].min
      sleeper = sleep_proc || ->(s) { Kernel.sleep(s) }

      last = bid_status(bid_id, status_url: status_url)
      (max_attempts - 1).times do
        return last if last.terminal?

        sleeper.call(interval)
        last = bid_status(bid_id, status_url: status_url)
      end
      last
    end

    def to_s
      sess = @session_id.nil? ? nil : REDACTED
      "#<ConcertClient::AgentBidClient base_url=#{@base_url.inspect} chain=#{@chain.inspect} " \
        "max_bid_micro_usd=#{@max_bid_micro_usd} session_id=#{sess.inspect}>"
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

    def coerce_payment_payload(payload)
      if payload.is_a?(Hash)
        raise ArgumentError, "payment_payload must not be empty" if payload.empty?

        return payload
      end
      if payload.is_a?(String)
        raise ArgumentError, "payment_payload must not be empty" if payload.strip.empty?

        return JSON.parse(payload)
      end

      raise ArgumentError, "payment_payload must be a Hash or JSON String"
    rescue JSON::ParserError
      raise ArgumentError, "payment_payload String must be valid JSON"
    end

    def execute_bid_request(uri, req)
      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = @timeout
      http.read_timeout = @timeout
      http.write_timeout = @timeout if http.respond_to?(:write_timeout=)
      if uri.scheme == "https"
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      end

      status = nil
      cookies = []
      body = +"".b
      http.start do |conn|
        conn.request(req) do |resp|
          status = resp.code.to_i
          cookies = Array(resp.get_fields("set-cookie"))
          resp.read_body do |chunk|
            if body.bytesize + chunk.bytesize > @max_response_bytes
              raise BiddingError, "bidding response exceeded maximum size (#{@max_response_bytes} bytes)"
            end

            body << chunk.b
          end
        end
      end
      text = body.force_encoding(Encoding::UTF_8)

      unless status == 200 || status == 202
        detail = extract_safe_error(text)
        raise BiddingError.new("bidding request failed with HTTP #{status}: #{detail}", status_code: status)
      end

      data = JSON.parse(text)
      raise BiddingError, "bidding endpoint returned non-object JSON" unless data.is_a?(Hash)

      bid_obj = data["bid"].is_a?(Hash) ? data["bid"] : {}
      BidStatusResponse.new(
        bid_id: data["bid_id"] || bid_obj["bid_id"] || "",
        status: data["status"] || bid_obj["status"] || "",
        pass_issued: !!data["pass_issued"],
        pass_token: data["pass_token"] || "",
        priority_pass: data["priority_pass"] || "",
        pass_cookie: data["pass_cookie"] || "",
        session: data["session"] || "",
        transaction: data["transaction"] || bid_obj["transaction"] || "",
        reason: data["reason"] || bid_obj["reason"] || "",
        status_url: data["status_url"] || "",
        set_cookies: cookies
      )
    rescue JSON::ParserError
      raise BiddingError, "bidding endpoint returned invalid JSON"
    rescue Timeout::Error, Errno::ECONNREFUSED, Errno::ECONNRESET, SocketError, OpenSSL::SSL::SSLError => e
      raise BiddingError, "bidding transport error: #{e.class}: #{e.message}"
    end

    def extract_safe_error(text)
      obj = JSON.parse(text)
      return obj["error"].to_s[0, 256] if obj.is_a?(Hash) && obj["error"].is_a?(String)

      "request rejected"
    rescue JSON::ParserError
      "request rejected"
    end
  end
end
