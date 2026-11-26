# frozen_string_literal: true

require_relative "src/lib/concert_client/version"

Gem::Specification.new do |spec|
  spec.name          = "concert_client"
  spec.version       = ConcertClient::VERSION
  spec.authors       = ["Andrei Merlescu"]
  spec.summary       = "Official zero-dependency Ruby client SDK for Concert waiting-room reverse proxy"
  spec.description   = "Pure Ruby stdlib SDK for Concert: Concert-Priority Rack/Rails middleware, waiting-room signal header parsing, rm1 Ed25519 pass/lease tokens, authenticated cache purge, and 100% crypto-only AI agent bidding (xrpl, stellar, hedera, solana)."
  spec.homepage      = "https://github.com/andreimerlescu/concert"
  spec.license       = "Apache-2.0"
  spec.required_ruby_version = ">= 2.6.0"

  spec.metadata["homepage_uri"]    = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  spec.files         = Dir.glob("src/lib/**/*.rb") + %w[README.md CHANGELIST.md LICENSE]
  spec.require_paths = ["src/lib"]

  # Zero required runtime dependencies — pure Ruby stdlib (net/http, json, openssl, uri, base64, time).
end
