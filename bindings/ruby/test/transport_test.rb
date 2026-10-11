require 'json'
require 'minitest/autorun'
require 'net/http'
require 'stogas'

class TransportTest < Minitest::Test
  def test_invalid_options_preserve_native_error_codes
    [{security: 'unsupported'}, {environment: 'unsupported'}, {max_connections: 0}].each do |options|
      error = assert_raises(Stogas::VerificationError) { Stogas::Transport.new(**options) }
      refute_empty error.code
    end
  end

  # STOGAS_LIVE=staging|prod sends an invalid API key through each security mode.
  def test_live_gateway_rejects_an_invalid_key_through_each_security_mode
    environment = ENV['STOGAS_LIVE'] or skip 'set STOGAS_LIVE to staging or prod'
    %w[tls e2ee].each do |security|
      transport = nil
      assert_raises(RuntimeError) do
        Stogas::Transport.open(environment: environment, security: security) do |opened|
          transport = opened
          uri = URI("#{opened.base_url}/chat/completions")
          assert_equal '127.0.0.1', uri.host
          body = '{"model":"stogas-status-monitor","messages":[{"role":"user","content":"ping"}]}'
          headers = {'authorization' => 'Bearer stogas-status-monitor-uncredentialed', 'content-type' => 'application/json'}
          response = Net::HTTP.start(uri.host, uri.port, nil, read_timeout: 30) { |http| http.post(uri.path, body, headers) }
          assert_equal '401', response.code, security
          assert_equal 'authentication_error', JSON.parse(response.body).dig('error', 'type'), security
          3.times.map { Thread.new { opened.refresh } }.each(&:value)
          raise 'application failed'
        end
      end
      transport.close
      assert_raises(IOError) { transport.refresh }
    end
  end
end
