# frozen_string_literal: true

require 'base64'
require 'json'
require 'jwt'
require 'net/http'
require 'openssl'
require 'uri'

module FastMcp
  module OAuth
    # OAuth 2.1 Token Validator
    # Handles JWT and opaque token validation for MCP servers
    class TokenValidator
      class InvalidTokenError < StandardError; end
      class ExpiredTokenError < StandardError; end
      class InvalidScopeError < StandardError; end

      # JWT token types
      JWT_TYPES = %w[JWT jwt].freeze
      ALLOWED_ALGORITHMS = ['HS256', 'HS384', 'HS512'].freeze

      attr_reader :logger, :issuer, :audience, :required_scopes

      def initialize(options = {})
        @logger = options[:logger] || ::Logger.new($stdout).tap { |l| l.level = ::Logger::FATAL }
        @issuer = options[:issuer]
        @audience = options[:audience]
        @required_scopes = Array(options[:required_scopes])
        @opaque_token_validator = options[:opaque_token_validator]
        @subjects = normalize_subjects(options[:sub] || options[:subjects])
        @clock_skew = options.fetch(:clock_skew, 60) # 60 seconds default clock skew
        @hmac_secret = options[:hmac_secret]
        @jwks_cache = {}
        @jwks_cache_mutex = Mutex.new
        @jwks_cache_ttl = options.fetch(:jwks_cache_ttl, 300) # 5 minutes default
      end

      # Validate an OAuth 2.1 token
      def validate_token(token, required_scopes: nil)
        return false if token.nil? || token.empty?

        # Determine token type and validate accordingly
        if jwt_token?(token)
          valid_jwt_token?(token, required_scopes: required_scopes)
        else
          valid_opaque_token?(token, required_scopes: required_scopes)
        end
      rescue InvalidTokenError, ExpiredTokenError, InvalidScopeError => e
        @logger.warn("Token validation failed: #{e.message}")
        false
      rescue StandardError => e
        @logger.error("Unexpected error during token validation: #{e.message}")
        false
      end

      # Extract claims from a valid token (for debugging/logging)
      def extract_claims(token)
        return nil unless jwt_token?(token)

        # Decode without verification for claim extraction
        payload, = JWT.decode(token, nil, false)
        payload
      rescue StandardError => e
        @logger.debug("Failed to extract claims: #{e.message}")
        nil
      end

      private

      # Check if token looks like a JWT
      def jwt_token?(token)
        # Simple check: JWT has 3 parts separated by dots
        parts = token.split('.')
        return false unless parts.length == 3

        # Try to decode header
        header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
        !!header
      rescue JSON::ParserError, ArgumentError
        false
      end

      # Validate JWT token
      def valid_jwt_token?(token, required_scopes: nil)
        decode_options = {
          algorithm: ALLOWED_ALGORITHMS,
          verify_expiration: true,
          verify_not_before: true,
          verify_iat: true,
          verify_jti: true,
          leeway: @clock_skew
        }

        # Add issuer verification if configured
        if @issuer
          decode_options[:verify_iss] = true
          decode_options[:iss] = @issuer
        end

        # Add audience verification if configured
        if @audience
          decode_options[:verify_aud] = true
          decode_options[:aud] = @audience
        end

        payload, header = JWT.decode(token, @hmac_secret, true, decode_options)

        # Verify algorithm is allowed
        algorithm = header['alg']
        raise InvalidTokenError, "Unallowed JWT algorithm: #{algorithm}" unless ALLOWED_ALGORITHMS.include?(algorithm)

        validate_token_scopes!(payload['scope'], required_scopes) if required_scopes
        validate_subject!(payload['sub']) if @subjects.any?

        true
      rescue JWT::DecodeError, JWT::ExpiredSignature => e
        raise ExpiredTokenError, e.message if e.is_a?(JWT::ExpiredSignature)
        raise InvalidTokenError, e.message
      end

      # Validate opaque token using external validator
      def valid_opaque_token?(token, required_scopes: nil)
        return false unless @opaque_token_validator

        result = @opaque_token_validator.call(token)
        return false unless result.is_a?(Hash) && result[:valid]

        # Validate scopes if provided
        validate_token_scopes!(result[:scopes], required_scopes) if required_scopes && result[:scopes]

        true
      end

      # Validate token scopes
      def validate_token_scopes!(token_scopes, required_scopes)
        token_scope_list = extract_scopes(token_scopes)
        required_scope_list = Array(required_scopes)
        missing_scopes = required_scope_list - token_scope_list
        raise InvalidScopeError, "Missing required scopes: #{missing_scopes.join(', ')}" unless missing_scopes.empty?
      end

      def validate_subject!(token_subject)
        return if @subjects.empty? || @subjects.include?(nil) # Allow any subject if not configured

        unless @subjects.include?(token_subject)
          @logger.warn("Subject validation failed: #{token_subject} not in allowed subjects: #{@subjects}")
          raise InvalidTokenError, "Invalid subject: #{token_subject}"
        end

        @logger.debug("Subject validation passed: #{token_subject}")
      end

      def normalize_subjects(subjects)
        case subjects
        when nil
          [] # No subject restriction
        when String
          [subjects]
        when Array
          subjects.compact.uniq
        else
          [subjects.to_s]
        end
      end

      # Extract scopes from token (handles both string and array formats)
      def extract_scopes(scopes)
        case scopes
        when String
          scopes.split
        when Array
          scopes
        else
          []
        end
      end
    end
  end
end
