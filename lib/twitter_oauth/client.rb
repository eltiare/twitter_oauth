require 'twitter_oauth/timeline'
require 'twitter_oauth/status'
require 'twitter_oauth/account'
require 'twitter_oauth/direct_messages'
require 'twitter_oauth/search'
require 'twitter_oauth/notifications'
require 'twitter_oauth/blocks'
require 'twitter_oauth/friendships'
require 'twitter_oauth/user'
require 'twitter_oauth/favorites'
require 'twitter_oauth/utils'
require 'twitter_oauth/trends'
require 'twitter_oauth/lists'
require 'twitter_oauth/saved_searches'
require 'twitter_oauth/spam'
require 'twitter_oauth/geo'

module TwitterOAuth
  class Client
    
    def initialize(options = {})
      @consumer_key = options[:consumer_key]
      @consumer_secret = options[:consumer_secret]
      @token = options[:token]
      @secret = options[:secret]
      @proxy = options[:proxy]
    end
  
    def authorize(token, secret, options = {})
      request_token = OAuth::RequestToken.new(
        consumer, token, secret
      )
      @access_token = request_token.get_access_token(options)
      @token = @access_token.token
      @secret = @access_token.secret
      @access_token
    end
  
    def show(username)
      if username.is_a?(String)
        get("/users/show/#{username}.json")
      elsif username.is_a?(Hash)
        raise ArgumentError, "Valid options are screen_name and user_id" unless username.size == 1 && [:screen_name, :user_id].include?(username.keys[0].to_sym)
        get("/users/show.json?#{username.keys[0]}=#{username.values[0]}")
      else
        raise ArgumentError, 'Argument must either be a string or a hash with either a screen_name or user_id label'
      end
    end
    
    # Returns the string "ok" in the requested format with a 200 OK HTTP status code.
    def test
      get("/help/test.json")
    end
    
    def request_token(options={})
      consumer.get_request_token(options)
    end
    
    def authentication_request_token(options={})
      consumer.options[:authorize_path] = '/oauth/authenticate'
      request_token(options)
    end
    
    private
    
      def consumer
        @consumer ||= OAuth::Consumer.new(
          @consumer_key,
          @consumer_secret,
          { :site => 'http://api.twitter.com', :request_endpoint => @proxy }
        )
      end

      def access_token
        @access_token ||= OAuth::AccessToken.new(consumer, @token, @secret)
      end
      
      def get(path, headers={})
        headers.merge!("User-Agent" => "twitter_oauth gem v#{TwitterOAuth::VERSION}")
        oauth_response = access_token.get("/1#{path}", headers)
        JSON.parse(oauth_response.body)
      end

      def post(path, body='', headers={})
        headers.merge!("User-Agent" => "twitter_oauth gem v#{TwitterOAuth::VERSION}")
        oauth_response = access_token.post("/1#{path}", body, headers)
        JSON.parse(oauth_response.body)
      end

      def delete(path, headers={})
        headers.merge!("User-Agent" => "twitter_oauth gem v#{TwitterOAuth::VERSION}")
        oauth_response = access_token.delete("/1#{path}", headers)
        JSON.parse(oauth_response.body)
      end
  end
end
   
