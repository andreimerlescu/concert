# frozen_string_literal: true

require "json"

module ConcertClient
  REDACTED = "[REDACTED]"

  class SecretError < ArgumentError; end

  # Redacting wrapper for sensitive credentials (Bearer tokens, private keys,
  # session tokens). `to_s`, `inspect`, and `to_json` never reveal the secret.
  class Secret
    def initialize(value, name: "secret", binary: false)
      raise SecretError, "#{name} must be a String" unless value.is_a?(String)

      if binary
        raise SecretError, "#{name} must not be empty" if value.empty?

        @value = value.dup.force_encoding(Encoding::BINARY).freeze
      else
        cleaned = value.strip
        raise SecretError, "#{name} must not be empty" if cleaned.empty?
        if cleaned.include?("\r") || cleaned.include?("\n") || cleaned.include?("\0")
          raise SecretError, "#{name} contains forbidden control characters"
        end

        @value = cleaned.freeze
      end
      @binary = binary
      freeze
    end

    def reveal
      @value.dup
    end

    def bytesize
      @value.bytesize
    end

    def to_s
      REDACTED
    end

    def inspect
      "#<ConcertClient::Secret #{REDACTED}>"
    end

    def pretty_print(pp)
      pp.text(inspect)
    end

    def to_json(*args)
      REDACTED.to_json(*args)
    end

    def self.from_file(path, name: "secret")
      raise SecretError, "#{name} file not found: #{path}" unless File.file?(path)

      mode = File.stat(path).mode & 0o777
      if (mode & 0o077) != 0
        raise SecretError, "#{name} file #{path} has overly permissive mode #{format('%04o', mode)}; expected 0600 or stricter"
      end

      new(File.read(path, encoding: Encoding::UTF_8), name: name)
    rescue Errno::ENOENT, Errno::EACCES => e
      raise SecretError, "failed to read #{name} file: #{e.message}"
    end

    def self.from_env_or_file(env_var, file_env_var, env: ENV)
      file_path = env[file_env_var].to_s.strip
      return from_file(file_path, name: file_env_var) unless file_path.empty?

      raw = env[env_var].to_s
      return new(raw, name: env_var) unless raw.strip.empty?

      raise SecretError, "missing required secret: set #{file_env_var} or #{env_var}"
    end
  end
end
