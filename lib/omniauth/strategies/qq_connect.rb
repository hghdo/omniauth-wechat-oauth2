require "omniauth-oauth2"

module OmniAuth
  module Strategies
    class QQConnect < OmniAuth::Strategies::OAuth2
      option :name, "qq_connect"

      option :client_options, {
        :site => 'https://graph.qq.com/oauth2.0/',
        :authorize_url => '/oauth2.0/authorize',
        :token_url => "/oauth2.0/token",
        :token_formatter => lambda {|hash|
          hash[:expires_in] = hash['expires_in'].to_i
          hash.delete('expires_in')
        }
      }

      option :token_params, {
        :state => 'foobar',
        :parse => :query
      }

      option :authorize_options, [:scope]

      uid do
        @uid ||= begin
          access_token.options[:mode] = :query
          access_token.options[:param_name] = :access_token
          # Response Example: "callback( {\"client_id\":\"11111\",\"openid\":\"000000FFFF\"} );\n"
          response = access_token.get('/oauth2.0/me')
          #TODO handle error case
          matched = response.body.match(/"openid":"(?<openid>\w+)"/)
          matched[:openid]
        end
      end

      info do
        {
            :nickname => raw_info['nickname'],
            :name => raw_info['nickname'],
            :image => raw_info['figureurl_1'],
        }
      end

      extra do
        {raw_info: raw_info}
      end

      # def request_phase
      #   params = client.auth_code.authorize_params.merge(authorize_params)
      #   params["appid"] = params.delete("client_id")
      #   params["redirect_uri"] = callback_url
      #   redirect client.authorize_url(params)
      # end

      def raw_info
        @raw_info ||= begin
                        #TODO handle error case
                        #TODO make info request url configurable
          client.request(:get, "https://graph.qq.com/user/get_user_info", :params => {
                                 :format => :json,
                                 :openid => uid,
                                 :oauth_consumer_key => options[:client_id],
                                 :access_token => access_token.token
                             }, :parse => :json).parsed
      end

      # protected
      # def build_access_token
      #   params = {
      #     'appid'        => client.id,
      #     'secret'       => client.secret,
      #     'code'         => request.params['code'],
      #     'grant_type'   => 'authorization_code',
      #     'redirect_uri' => callback_url
      #     }.merge(token_params.to_hash(symbolize_keys: true))
      #   client.get_token(params, deep_symbolize(options.auth_token_params))
      # end

    end
  end
end