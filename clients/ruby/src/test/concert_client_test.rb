# frozen_string_literal: true

require "minitest/autorun"
require "json"
require "securerandom"
require "socket"
require "tmpdir"
require "uri"
require "concert_client"

# Minimal pure-stdlib TCPServer HTTP/1.1 stub (zero external gems, Ruby 2.6–3.4+).
class StubConcertServer
  attr_reader :port, :base_url, :purge_requests, :bid_requests, :bid_statuses
  attr_accessor :force_oversized_purge, :status_calls

  def initialize(expected_token)
    @expected_token = expected_token
    @purge_requests = []
    @bid_requests = []
    @bid_statuses = {}
    @status_calls = 0
    @force_oversized_purge = false
    @running = true
    @server = TCPServer.new("127.0.0.1", 0)
    @port = @server.addr[1]
    @base_url = "http://127.0.0.1:#{@port}"
    @thread = Thread.new { serve_loop }
  end

  def shutdown
    @running = false
    @server.close unless @server.closed?
    @thread.join(3)
  rescue StandardError
    nil
  end

  private

  def serve_loop
    while @running
      client = @server.accept
      handle_connection(client)
    end
  rescue IOError, Errno::EBADF, Errno::EINVAL
    nil
  end

  def handle_connection(sock)
    request_line = sock.gets
    return if request_line.nil?

    method, target, _proto = request_line.strip.split(" ", 3)
    headers = {}
    while (line = sock.gets)
      break if line == "\r\n" || line == "\n"

      k, v = line.split(":", 2)
      headers[k.strip.downcase] = v.to_s.strip if k
    end

    len = headers["content-length"].to_i
    raw_body = len > 0 ? sock.read(len).to_s : ""
    dispatch(sock, method, target, headers, raw_body)
  ensure
    sock.close unless sock.closed?
  end

  def dispatch(sock, method, target, headers, raw_body)
    uri = URI.parse("http://127.0.0.1#{target}")

    if method == "POST" && uri.path == "/_room/cache/purge"
      if headers["authorization"] != "Bearer #{@expected_token}"
        return write_json(sock, 401, { "error" => "unauthorized" })
      end
      if @force_oversized_purge
        big = "{" + (" " * 1024) + "}"
        return write_raw(sock, 200, big)
      end

      body = JSON.parse(raw_body)
      @purge_requests << body
      purged = body["mode"] == "all" ? 42 : (body["mode"] == "prefix" ? 7 : 1)
      return write_json(sock, 200, { "purged" => purged, "mode" => body["mode"] })
    end

    if method == "POST" && uri.path == "/_concert/bids"
      body = JSON.parse(raw_body)
      @bid_requests << { "body" => body, "session" => headers["concert-session"].to_s }
      bid_id = body["bid_id"] || "bid-ruby-1"
      if body["scope"] == "instant.example"
        return write_json(
          sock,
          200,
          {
            "bid_id" => bid_id,
            "status" => "settled",
            "pass_issued" => true,
            "pass_token" => "signed-pass-stub",
            "priority_pass" => "signed-pass-stub",
            "transaction" => "tx-instant-001",
            "status_url" => "/_concert/bids/status?bid_id=#{bid_id}"
          },
          extra_headers: { "Set-Cookie" => "concert_admit=stub-admit; HttpOnly; Path=/" }
        )
      end

      return write_json(
        sock,
        202,
        {
          "bid_id" => bid_id,
          "status" => "pending",
          "pass_issued" => false,
          "status_url" => "/_concert/bids/status?bid_id=#{bid_id}"
        }
      )
    end

    if method == "GET" && uri.path == "/_concert/bids/status"
      params = Hash[URI.decode_www_form(uri.query.to_s)]
      bid_id = params["bid_id"].to_s
      @status_calls += 1
      seq = @bid_statuses[bid_id]
      return write_json(sock, 404, { "error" => "bid_not_found" }) if seq.nil? || seq.empty?

      idx = [@status_calls - 1, seq.length - 1].min
      return write_json(sock, 200, seq[idx])
    end

    write_json(sock, 404, { "error" => "not_found" })
  end

  def write_json(sock, code, payload, extra_headers: {})
    write_raw(sock, code, JSON.generate(payload), extra_headers: extra_headers)
  end

  def write_raw(sock, code, body, extra_headers: {})
    reason = { 200 => "OK", 202 => "Accepted", 401 => "Unauthorized", 404 => "Not Found" }[code] || "OK"
    out = +"HTTP/1.1 #{code} #{reason}\r\n"
    out << "Content-Type: application/json\r\n"
    out << "Content-Length: #{body.bytesize}\r\n"
    out << "Connection: close\r\n"
    extra_headers.each { |k, v| out << "#{k}: #{v}\r\n" }
    out << "\r\n"
    out << body
    sock.write(out)
  end
end

class ConcertClientTest < Minitest::Test
  def setup
    @token = "fake-admin-token-#{SecureRandom.hex(12)}"
    @server = StubConcertServer.new(@token)
  end

  def teardown
    @server.shutdown if @server
  end

  def test_secret_redaction_and_file_mode_0600
    raw = "fake-credential-#{SecureRandom.hex(8)}"
    sec = ConcertClient::Secret.new(raw)
    assert_equal ConcertClient::REDACTED, sec.to_s
    assert_includes sec.inspect, ConcertClient::REDACTED
    refute_includes sec.inspect, raw
    refute_includes sec.to_json, raw
    assert_equal raw, sec.reveal

    assert_raises(ConcertClient::SecretError) { ConcertClient::Secret.new("") }
    assert_raises(ConcertClient::SecretError) { ConcertClient::Secret.new("   ") }
    assert_raises(ConcertClient::SecretError) { ConcertClient::Secret.new("bad\r\nX-Inject: 1") }

    Dir.mktmpdir do |dir|
      path = File.join(dir, "token")
      File.write(path, "#{raw}\n")
      File.chmod(0o644, path)
      assert_raises(ConcertClient::SecretError) { ConcertClient::Secret.from_file(path) }

      File.chmod(0o600, path)
      loaded = ConcertClient::Secret.from_file(path)
      assert_equal raw, loaded.reveal
      assert_equal ConcertClient::REDACTED, loaded.to_s

      env_loaded = ConcertClient::Secret.from_env_or_file(
        "CONCERT_ADMIN_TOKEN",
        "CONCERT_ADMIN_TOKEN_FILE",
        env: { "CONCERT_ADMIN_TOKEN_FILE" => path }
      )
      assert_equal raw, env_loaded.reveal
    end

    assert_raises(ConcertClient::SecretError) do
      ConcertClient::Secret.from_env_or_file("CONCERT_ADMIN_TOKEN", "CONCERT_ADMIN_TOKEN_FILE", env: {})
    end
  end

  def test_priority_validation_rack_middleware_and_rails_helpers
    assert_equal %w[member prospect customer subscriber checkout staff], ConcertClient::Priority::GRANT_RANKS
    assert_equal "checkout; ttl=1800", ConcertClient::Priority.format_header(:checkout, ttl_seconds: 1800)
    assert_equal "staff; ttl=60", ConcertClient::Priority.format_header("STAFF", ttl_seconds: 10)
    assert_equal "staff; ttl=86400", ConcertClient::Priority.format_header("staff", ttl_seconds: 999_999)
    assert_equal "guest", ConcertClient::Priority.format_header("guest", ttl_seconds: 600)
    assert_equal "subscriber", ConcertClient::Priority.highest_rank(member: true, subscriber: true, customer: true)
    assert_equal "guest", ConcertClient::Priority.highest_rank(member: false)

    assert_raises(ConcertClient::Priority::InvalidRankError) { ConcertClient::Priority.validate_rank("vip") }
    assert_raises(ConcertClient::Priority::InvalidRankError) { ConcertClient::Priority.format_header("staff", ttl_seconds: 0) }

    inner_app = ->(_env) { [200, { "Content-Type" => "text/plain", "concert-priority" => "member" }.freeze, ["ok"]] }
    mw = ConcertClient::Priority::RackMiddleware.new(inner_app, default_ttl: 1800) do |env|
      env["PATH_INFO"] == "/checkout" ? "checkout" : nil
    end

    status, headers, body = mw.call("PATH_INFO" => "/checkout")
    assert_equal 200, status
    assert_equal ["ok"], body
    assert_equal "checkout; ttl=1800", headers["Concert-Priority"]
    refute headers.key?("concert-priority")

    # ControllerConcern & RailsHelper
    fake_response = Struct.new(:headers).new({})
    controller_class = Class.new do
      include ConcertClient::Priority::ControllerConcern
      attr_reader :response

      def initialize(resp)
        @response = resp
      end
    end
    ctrl = controller_class.new(fake_response)
    assert_equal "customer; ttl=3600", ctrl.set_concert_priority(:customer, ttl_seconds: 3600)
    assert_equal "customer; ttl=3600", fake_response.headers["Concert-Priority"]
    ctrl.clear_concert_priority
    assert_equal "guest", fake_response.headers["Concert-Priority"]

    installed = []
    fake_stack = Object.new
    fake_stack.define_singleton_method(:use) { |*args| installed << args }
    resolver = ->(_env) { "staff" }
    ConcertClient::Priority::RailsHelper.install!(fake_stack, resolver, default_ttl: 600)
    assert_equal ConcertClient::Priority::RackMiddleware, installed[0][0]
  end

  def test_signals_parser
    sig = ConcertClient::Signals.parse(
      {
        "x-concert-queue" => "1",
        "X-Concert-Position" => "12",
        "Retry-After" => "5",
        "X-Concert-Status-Url" => "/custom/status"
      }
    )
    assert sig.queued?
    assert_equal 12, sig.position
    assert_equal 5, sig.retry_after
    assert_equal "/custom/status", sig.status_url
    assert_equal "/custom/status", sig.effective_status_url
    assert ConcertClient::Signals.queued?({ "HTTP_X_CONCERT_QUEUE" => "1" })

    # Default status URL + HTTP-date Retry-After
    now = Time.utc(2026, 11, 26, 12, 0, 0)
    sig_date = ConcertClient::Signals.parse(
      { "X-Concert-Queue" => "1", "Retry-After" => "Thu, 26 Nov 2026 12:00:20 GMT" },
      now: now
    )
    assert sig_date.queued?
    assert_equal 20, sig_date.retry_after
    assert_equal "/queue/status", sig_date.effective_status_url

    # Non-queued 503 with Retry-After only
    sig_503 = ConcertClient::Signals.parse({ "Retry-After" => "30" })
    refute sig_503.queued?
    assert_equal 30, sig_503.retry_after

    # Rejects unsafe status URL
    sig_bad = ConcertClient::Signals.parse({ "X-Concert-Queue" => "1", "X-Concert-Status-Url" => "javascript:alert(1)" })
    assert_nil sig_bad.status_url
  end

  def test_rm1_envelope_codec_verification_and_crypto_detection
    claims = ConcertClient::Rm1::Claims.new(
      kid: "k1",
      kind: ConcertClient::Rm1::KIND_PASS,
      scope: "shop.example.test",
      key: "agent-1",
      iat: 1_700_000_000,
      exp: 1_700_000_300
    )
    signing_input = ConcertClient::Rm1.encode_signing_input(claims)
    assert signing_input.start_with?("rm1.")
    fake_sig = "\x22".b * 64
    token = ConcertClient::Rm1.assemble_envelope(claims, fake_sig)
    parsed = ConcertClient::Rm1.parse_envelope(token)
    assert_equal claims, parsed.claims
    assert_equal signing_input, parsed.signing_input
    assert_equal fake_sig, parsed.signature

    # Reject unknown JSON fields and bad framing.
    bad_json = '{"kid":"k1","kind":"pass","scope":"s","iat":1,"exp":2,"extra":true}'
    bad_tok = "rm1.#{ConcertClient::Rm1.b64url_encode(bad_json)}.#{ConcertClient::Rm1.b64url_encode(fake_sig)}"
    err = assert_raises(ConcertClient::Rm1::VerificationError) { ConcertClient::Rm1.parse_envelope(bad_tok) }
    assert_equal ConcertClient::Rm1::REJECT_MALFORMED, err.reason

    # Deterministic HMAC-backed pluggable signer/verifier exercises full rm1 verification pipeline on ANY Ruby/OpenSSL.
    key_secret = SecureRandom.random_bytes(32)
    pub_stub = SecureRandom.random_bytes(32)
    sign_proc = ->(msg) { OpenSSL::HMAC.digest("SHA256", key_secret, msg) + OpenSSL::HMAC.digest("SHA256", key_secret, "v2:" + msg) }
    verify_proc = ->(_pub, msg, sig) { sig == sign_proc.call(msg) }

    signer = ConcertClient::Rm1::Ed25519Signer.new("k1", key_secret, sign_proc: sign_proc)
    assert_includes signer.inspect, ConcertClient::REDACTED
    refute_includes signer.inspect, key_secret.unpack1("H*")

    now_ts = 1_700_000_000
    issuer = ConcertClient::Rm1::TokenIssuer.new("shop.example.test", signer, clock: -> { now_ts })
    pass_tok = issuer.mint_pass(ttl_seconds: 300)
    lease_tok = issuer.mint_lease("agent-9", ttl_seconds: 120)

    verifier = ConcertClient::Rm1::Ed25519Verifier.new({ "k1" => pub_stub }, verify_proc: verify_proc)
    v_pass = verifier.verify(pass_tok, expected_scope: "shop.example.test", now: now_ts + 10)
    assert_equal "k1", v_pass.kid
    assert_equal "pass", v_pass.kind

    v_lease = verifier.verify(
      lease_tok,
      expected_scope: "shop.example.test",
      expected_kind: ConcertClient::Rm1::KIND_LEASE,
      expected_key: "agent-9",
      now: now_ts + 10
    )
    assert_equal "agent-9", v_lease.key

    # Security-first verification checks: tampered > expired, wrong_scope, wrong_kind, key_mismatch, expired.
    tampered = pass_tok[0...-4] + (pass_tok.end_with?("AAAA") ? "BBBB" : "AAAA")
    e_sig = assert_raises(ConcertClient::Rm1::VerificationError) do
      verifier.verify(tampered, expected_scope: "shop.example.test", now: now_ts + 9999)
    end
    assert_equal ConcertClient::Rm1::REJECT_INVALID_SIGNATURE, e_sig.reason

    e_scope = assert_raises(ConcertClient::Rm1::VerificationError) do
      verifier.verify(pass_tok, expected_scope: "blog.example.test", now: now_ts + 10)
    end
    assert_equal ConcertClient::Rm1::REJECT_WRONG_SCOPE, e_scope.reason

    e_kind = assert_raises(ConcertClient::Rm1::VerificationError) do
      verifier.verify(pass_tok, expected_scope: "shop.example.test", expected_kind: "lease", expected_key: "agent-9", now: now_ts + 10)
    end
    assert_equal ConcertClient::Rm1::REJECT_WRONG_KIND, e_kind.reason

    e_key = assert_raises(ConcertClient::Rm1::VerificationError) do
      verifier.verify(lease_tok, expected_scope: "shop.example.test", expected_kind: "lease", expected_key: "other", now: now_ts + 10)
    end
    assert_equal ConcertClient::Rm1::REJECT_KEY_MISMATCH, e_key.reason

    e_exp = assert_raises(ConcertClient::Rm1::VerificationError) do
      verifier.verify(pass_tok, expected_scope: "shop.example.test", now: now_ts + 301)
    end
    assert_equal ConcertClient::Rm1::REJECT_EXPIRED, e_exp.reason

    # OpenSSL native Ed25519 path: test full sign+verify if runtime OpenSSL supports Ed25519,
    # otherwise verify clear UnsupportedCryptoError is raised.
    native_signer = ConcertClient::Rm1::Ed25519Signer.new("k1", SecureRandom.random_bytes(32))
    if ConcertClient::Rm1.ed25519_supported?
      native_issuer = ConcertClient::Rm1::TokenIssuer.new("shop.example.test", native_signer, clock: -> { now_ts })
      native_tok = native_issuer.mint_pass(ttl_seconds: 60)
      native_verifier = ConcertClient::Rm1::Ed25519Verifier.new({ "k1" => native_signer.public_key_bytes })
      vc = native_verifier.verify(native_tok, expected_scope: "shop.example.test", now: now_ts + 5)
      assert_equal "k1", vc.kid
    else
      assert_raises(ConcertClient::Rm1::UnsupportedCryptoError) { native_signer.sign("rm1.probe") }
    end
  end

  def test_cache_purge_client
    client = ConcertClient::CachePurgeClient.new(@server.base_url, @token, timeout: 5.0)
    assert_includes client.inspect, ConcertClient::REDACTED
    refute_includes client.inspect, @token
    refute_includes client.to_s, @token

    r_url = client.purge_url("/product/42", host: "shop.example")
    assert_equal 1, r_url.purged
    assert_equal "url", r_url.mode

    assert_equal 7, client.purge_prefix("/blog/").purged
    assert_equal 1, client.purge_tag("post:42").purged
    assert_equal 42, client.purge_all(host: "shop.example").purged
    assert_equal 4, @server.purge_requests.length

    bad_token = "fake-wrong-token-#{SecureRandom.hex(8)}"
    bad_client = ConcertClient::CachePurgeClient.new(@server.base_url, bad_token)
    err = assert_raises(ConcertClient::CachePurgeError) { bad_client.purge_all }
    assert_equal 401, err.status_code
    refute_includes err.message, bad_token

    @server.force_oversized_purge = true
    small = ConcertClient::CachePurgeClient.new(@server.base_url, @token, max_response_bytes: 256)
    assert_raises(ConcertClient::CachePurgeError) { small.purge_all }

    assert_raises(ArgumentError) { ConcertClient::CachePurgeClient.new("http://example.com", @token) }
    assert_raises(ArgumentError) { ConcertClient::CachePurgeClient.new("https://u:p@example.com", @token) }
    assert_raises(ArgumentError) { client.purge("url", target: "") }
  end

  def test_agent_bidding_crypto_only_and_end_to_end
    assert_equal %w[xrpl stellar hedera solana], ConcertClient::AgentBidClient::SUPPORTED_CHAINS
    ConcertClient::AgentBidClient::SUPPORTED_CHAINS.each do |c|
      assert_equal c, ConcertClient::AgentBidClient.normalize_chain(c.upcase)
    end

    # Reject fiat / non-crypto rails explicitly.
    %w[stripe usd visa card fiat paypal ethereum].each do |bad|
      assert_raises(ConcertClient::UnsupportedChainError) do
        ConcertClient::AgentBidClient.normalize_chain(bad)
      end
    end

    assert_equal 1_250_000, ConcertClient::AgentBidClient.parse_usd_to_micro_usd("1.25")
    assert_equal 1, ConcertClient::AgentBidClient.parse_usd_to_micro_usd("0.000001")
    assert_equal "$1.50", ConcertClient::AgentBidClient.format_micro_usd(1_500_000)
    assert_raises(ArgumentError) { ConcertClient::AgentBidClient.parse_usd_to_micro_usd("-1.00") }
    assert_raises(ArgumentError) { ConcertClient::AgentBidClient.parse_usd_to_micro_usd("0") }

    offer_json = JSON.generate(
      "queued" => true,
      "position" => 5,
      "auction" => {
        "mode" => "auction",
        "auction_id" => "auc-1",
        "scope" => "drop.example",
        "floor_micro_usd" => 1_000_000,
        "slots" => 2,
        "bid_url" => "/_concert/bids",
        "status_url" => "/_concert/bids/status",
        "supported_chains" => %w[solana xrpl stellar hedera]
      }
    )
    offer = ConcertClient::AgentBidClient.parse_auction_offer(offer_json, status_code: 429)
    refute_nil offer
    assert_equal "auction", offer.mode
    assert_equal 1_000_000, offer.floor_micro_usd
    assert_nil ConcertClient::AgentBidClient.parse_auction_offer(offer_json, status_code: 200)

    fake_session = "fake-session-#{SecureRandom.hex(8)}"
    client = ConcertClient::AgentBidClient.new(
      @server.base_url,
      max_bid_micro_usd: 2_000_000,
      chain: "solana",
      asset: "USDC",
      session_id: fake_session
    )
    refute_includes client.inspect, fake_session
    assert_equal 2_000_000, client.evaluate_offer(offer)

    # Low cap enforces strict max_bid_micro_usd.
    low_cap = ConcertClient::AgentBidClient.new(@server.base_url, max_bid_micro_usd: 500_000, chain: "solana")
    assert_nil low_cap.evaluate_offer(offer)
    assert_raises(ConcertClient::BidCapExceededError) do
      low_cap.submit_bid(bid_micro_usd: 1_000_000, amount_atomic: "1000000", payment_payload: { "scheme" => "exact" })
    end

    # Cross-origin SSRF protection.
    assert_raises(ConcertClient::CrossOriginError) do
      client.submit_bid(
        bid_micro_usd: 1_000_000,
        amount_atomic: "1000000",
        payment_payload: { "scheme" => "exact" },
        bid_url: "https://evil.example/_concert/bids"
      )
    end

    # Instant-buy settlement.
    instant = client.submit_bid(
      bid_micro_usd: 1_000_000,
      amount_atomic: "1000000",
      payment_payload: { "scheme" => "exact", "network" => "solana:mainnet" },
      scope: "instant.example",
      bid_id: "bid-instant-1"
    )
    assert instant.settled?
    assert instant.pass_issued?
    assert_equal "signed-pass-stub", instant.pass_token
    refute_includes instant.inspect, "signed-pass-stub"
    assert instant.set_cookies.any? { |c| c.include?("concert_admit=") }

    # Sealed-bid poll to settled.
    @server.bid_statuses["bid-auc-1"] = [
      { "bid_id" => "bid-auc-1", "status" => "pending", "pass_issued" => false },
      {
        "bid_id" => "bid-auc-1",
        "status" => "settled",
        "pass_issued" => true,
        "pass_token" => "winner-pass",
        "transaction" => "tx-sol-999"
      }
    ]
    pending = client.submit_bid(
      bid_micro_usd: 1_500_000,
      amount_atomic: "1500000",
      payment_payload: { "scheme" => "exact", "network" => "solana:mainnet" },
      scope: "drop.example",
      bid_id: "bid-auc-1"
    )
    assert_equal "pending", pending.status
    refute pending.terminal?

    final = client.poll_bid_status("bid-auc-1", poll_interval: 0.05, max_attempts: 5, sleep_proc: ->(_) {})
    assert final.settled?
    assert final.pass_issued?
    assert_equal "tx-sol-999", final.transaction

    # Loser pays $0.
    @server.status_calls = 0
    @server.bid_statuses["bid-lost-1"] = [
      { "bid_id" => "bid-lost-1", "status" => "lost", "pass_issued" => false, "reason" => "outbid" }
    ]
    lost = client.bid_status("bid-lost-1")
    assert_equal "lost", lost.status
    assert lost.terminal?
    refute lost.settled?
    refute lost.pass_issued?

    err = assert_raises(ConcertClient::BiddingError) { client.bid_status("bid-missing") }
    assert_equal 404, err.status_code
  end
end
