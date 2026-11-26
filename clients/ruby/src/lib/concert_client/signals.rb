# frozen_string_literal: true

require "time"
require "uri"

module ConcertClient
  module Signals
    HEADER_QUEUE = "X-Concert-Queue"
    HEADER_POSITION = "X-Concert-Position"
    HEADER_RETRY_AFTER = "Retry-After"
    HEADER_STATUS_URL = "X-Concert-Status-Url"
    DEFAULT_STATUS_URL = "/queue/status"
    MAX_URL_LENGTH = 2048

    # Structured view of Concert waiting-room signal headers.
    class WaitingRoomSignal
      attr_reader :position, :retry_after, :status_url

      def initialize(queued:, position: nil, retry_after: nil, status_url: nil)
        @queued = !!queued
        @position = position
        @retry_after = retry_after
        @status_url = status_url
        freeze
      end

      def queued?
        @queued
      end

      def effective_status_url
        @status_url || DEFAULT_STATUS_URL
      end

      def ==(other)
        other.is_a?(WaitingRoomSignal) &&
          queued? == other.queued? &&
          position == other.position &&
          retry_after == other.retry_after &&
          status_url == other.status_url
      end
    end

    module_function

    def parse(headers, now: Time.now.utc)
      norm = normalize_headers(headers)
      raw_queue = norm[HEADER_QUEUE.downcase].to_s.downcase
      queued = %w[1 true].include?(raw_queue)
      position = parse_non_negative_int(norm[HEADER_POSITION.downcase])
      retry_after = parse_retry_after(norm[HEADER_RETRY_AFTER.downcase], now: now)
      status_url = sanitize_status_url(norm[HEADER_STATUS_URL.downcase])

      WaitingRoomSignal.new(
        queued: queued,
        position: position,
        retry_after: retry_after,
        status_url: status_url
      )
    end

    def queued?(headers)
      parse(headers).queued?
    end

    def normalize_headers(headers)
      result = {}
      return result if headers.nil?

      enum = if headers.respond_to?(:each_header)
               headers.to_hash.map { |k, v| [k, v.is_a?(Array) ? v.first : v] }
             else
               headers
             end

      enum.each do |raw_k, raw_v|
        k = raw_k.to_s.strip.downcase
        k = k.sub(/\Ahttp_/, "").tr("_", "-") if k.start_with?("http_")
        v = raw_v.is_a?(Array) ? raw_v.first.to_s : raw_v.to_s
        result[k] = v.strip
      end
      result
    end
    private_class_method :normalize_headers

    def parse_non_negative_int(value)
      return nil if value.nil? || value.empty?
      return value.to_i if /\A\d+\z/.match?(value)

      nil
    end
    private_class_method :parse_non_negative_int

    def parse_retry_after(value, now:)
      return nil if value.nil? || value.empty?
      return value.to_i if /\A\d+\z/.match?(value)

      dt = Time.httpdate(value)
      delta = (dt - now).ceil
      delta.negative? ? 0 : delta
    rescue ArgumentError
      nil
    end
    private_class_method :parse_retry_after

    def sanitize_status_url(value)
      return nil if value.nil? || value.empty?
      return nil if value.bytesize > MAX_URL_LENGTH
      return nil if value.include?("\r") || value.include?("\n") || value.include?("\0")
      return value if value.start_with?("/") && !value.start_with?("//")

      uri = URI.parse(value)
      return value if %w[http https].include?(uri.scheme.to_s.downcase) && !uri.host.to_s.empty?

      nil
    rescue URI::InvalidURIError
      nil
    end
    private_class_method :sanitize_status_url
  end
end
