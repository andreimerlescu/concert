# frozen_string_literal: true

module ConcertClient
  module Priority
    HEADER_NAME = "Concert-Priority"
    MIN_TTL_SECONDS = 60
    MAX_TTL_SECONDS = 86_400

    ALL_RANKS = %w[guest member prospect customer subscriber checkout staff].freeze
    GRANT_RANKS = %w[member prospect customer subscriber checkout staff].freeze

    class InvalidRankError < ArgumentError; end

    module_function

    def validate_rank(rank)
      raise InvalidRankError, "Concert priority rank must be a String or Symbol" unless rank.is_a?(String) || rank.is_a?(Symbol)

      normalized = rank.to_s.strip.downcase
      unless ALL_RANKS.include?(normalized)
        raise InvalidRankError, "unknown Concert priority rank #{rank.inspect}; expected one of: #{ALL_RANKS.join(', ')}"
      end

      normalized
    end

    def highest_rank(facts)
      return "guest" unless facts.respond_to?(:[])

      ALL_RANKS[1..].reverse_each do |rank|
        val = facts[rank]
        val = facts[rank.to_sym] if val.nil?
        return rank if val
      end
      "guest"
    end

    def format_header(rank, ttl_seconds: nil)
      normalized = validate_rank(rank)
      return normalized if ttl_seconds.nil? || normalized == "guest"

      raise InvalidRankError, "ttl_seconds must be a positive Integer" unless ttl_seconds.is_a?(Integer) && ttl_seconds > 0

      clamped = [[ttl_seconds, MIN_TTL_SECONDS].max, MAX_TTL_SECONDS].min
      "#{normalized}; ttl=#{clamped}"
    end

    def coerce_resolved(result, default_ttl: nil)
      return nil if result.nil?

      if result.is_a?(Array)
        raise InvalidRankError, "priority resolver array must be [rank, ttl_seconds]" unless result.length == 2

        rank, ttl = result
        format_header(rank, ttl_seconds: ttl.nil? ? default_ttl : ttl)
      elsif result.is_a?(Hash)
        rank = result[:rank] || result["rank"]
        ttl = result.key?(:ttl_seconds) ? result[:ttl_seconds] : result["ttl_seconds"]
        format_header(rank, ttl_seconds: ttl.nil? ? default_ttl : ttl)
      else
        format_header(result, ttl_seconds: default_ttl)
      end
    end

    # Pure Rack middleware that injects a validated `Concert-Priority` response header.
    class RackMiddleware
      def initialize(app, resolver = nil, default_ttl: nil, &block)
        @app = app
        @resolver = resolver || block
        raise ArgumentError, "resolver callable or block is required" unless @resolver.respond_to?(:call)

        if !default_ttl.nil? && (!default_ttl.is_a?(Integer) || default_ttl <= 0)
          raise InvalidRankError, "default_ttl must be a positive Integer"
        end
        @default_ttl = default_ttl
      end

      def call(env)
        header_value = Priority.coerce_resolved(@resolver.call(env), default_ttl: @default_ttl)
        status, headers, body = @app.call(env)
        return [status, headers, body] if header_value.nil?

        updated = {}
        headers.each do |k, v|
          updated[k] = v unless k.to_s.casecmp(HEADER_NAME).zero?
        end
        updated[HEADER_NAME] = header_value
        [status, updated, body]
      end
    end

    # Mixin for Rails ActionController / Sinatra-style controllers exposing `response.headers`.
    module ControllerConcern
      def set_concert_priority(rank, ttl_seconds: nil)
        value = Priority.format_header(rank, ttl_seconds: ttl_seconds)
        response.headers[HEADER_NAME] = value
        value
      end

      def clear_concert_priority
        set_concert_priority("guest")
      end

      def sync_concert_priority(facts, ttl_seconds: nil)
        rank = Priority.highest_rank(facts)
        return rank if rank == "guest"

        set_concert_priority(rank, ttl_seconds: ttl_seconds)
        rank
      end
    end

    # Rails integration helper (works with or without Rails loaded).
    module RailsHelper
      def self.install!(middleware_stack, resolver = nil, default_ttl: nil, &block)
        cb = resolver || block
        middleware_stack.use(RackMiddleware, cb, default_ttl: default_ttl)
      end
    end

    if defined?(::Rails::Railtie)
      class Railtie < ::Rails::Railtie
        config.concert_priority = ActiveSupport::OrderedOptions.new
        config.concert_priority.resolver = nil
        config.concert_priority.default_ttl = nil

        initializer "concert_client.priority_middleware" do |app|
          resolver = app.config.concert_priority.resolver
          if resolver
            RailsHelper.install!(
              app.middleware,
              resolver,
              default_ttl: app.config.concert_priority.default_ttl
            )
          end
        end

        ActiveSupport.on_load(:action_controller) do
          include ControllerConcern
        end
      end
    end
  end
end
