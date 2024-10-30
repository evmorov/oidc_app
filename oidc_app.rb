require 'sinatra'
require 'openid_connect'
require 'dotenv/load'
require 'securerandom'

enable :sessions

class Object
  def tee
    puts self
    self
  end
end

OpenIDConnect.http_config do |config|
  config.ssl.verify = false
end

Faraday.default_connection = Faraday.new do |conn|
  conn.ssl.verify = false
end

SWD.url_builder = Module.new do
  def self.build(...)
    URI::HTTP.build(...)
  end
end

IDP_ENDPOINT = ENV.fetch('IDP_ENDPOINT')
IDP_CLIENT_ID = ENV.fetch('IDP_CLIENT_ID')
IDP_CLIENT_SECRET = ENV.fetch('IDP_CLIENT_SECRET')
IDP_REDIRECT_URI = ENV.fetch('IDP_REDIRECT_URI')

discovery = OpenIDConnect::Discovery::Provider::Config.discover!(IDP_ENDPOINT)

client = OpenIDConnect::Client.new(
  identifier: IDP_CLIENT_ID,
  secret: IDP_CLIENT_SECRET,
  redirect_uri: IDP_REDIRECT_URI,
  authorization_endpoint: discovery.authorization_endpoint,
  token_endpoint: discovery.token_endpoint,
  userinfo_endpoint: discovery.userinfo_endpoint,
  end_session_endpoint: discovery.end_session_endpoint
)

helpers do
  def id_token_expiry_time(id_token)
    time = Time.at(JSON::JWT.decode(id_token, :skip_verification)['exp'])
    puts "ID Token expires at: #{time}"
    time
  end
end

get '/login' do
  puts "\n===== /login ====="

  state = SecureRandom.hex(16)
  nonce = SecureRandom.hex(16)
  session[:state] = state
  session[:nonce] = nonce
  redirect client.authorization_uri(
    response_type: 'code',
    scope: 'email profile offline_access',
    state: state,
    nonce: nonce
  )
end

get '/login_callback' do
  puts "\n===== /login_callback ====="

  halt 400, 'Invalid state parameter'.tee if params['state'] != session[:state]

  client.authorization_code = params['code']
  token_response = client.access_token!

  access_token = token_response.access_token
  refresh_token = token_response.refresh_token
  id_token = token_response.id_token

  id_token_object = OpenIDConnect::ResponseObject::IdToken.decode(id_token, discovery.jwks)
  id_token_object.verify!(
    issuer: discovery.issuer,
    client_id: IDP_CLIENT_ID,
    nonce: session[:nonce]
  )

  session[:access_token] = access_token
  session[:refresh_token] = refresh_token
  session[:id_token] = id_token

  puts "Access Token: #{access_token}"
  puts "Refresh Token: #{refresh_token}"
  puts "ID Token: #{id_token}"

  id_token_expiry_time(id_token)

  session.delete(:state)
  session.delete(:nonce)

  'Authentication successful.'.tee
end

get '/refresh' do
  puts "\n===== /refresh ====="

  refresh_token = session[:refresh_token]
  halt 400, 'No refresh token available.'.tee unless refresh_token

  token_response = client.access_token!(
    grant_type: 'refresh_token',
    refresh_token: refresh_token
  )

  access_token = token_response.access_token
  new_refresh_token = token_response.refresh_token
  id_token = token_response.id_token

  session[:access_token] = access_token
  session[:refresh_token] = new_refresh_token
  session[:id_token] = id_token

  puts "New Access Token: #{access_token}"
  puts "New Refresh Token: #{new_refresh_token}"
  puts "New ID Token: #{id_token}"

  id_token_expiry_time(id_token)

  'Token refreshed successfully.'.tee
end

get '/logout' do
  puts "\n===== /logout ====="

  id_token = session[:id_token]
  halt 400, 'No ID token available.'.tee unless id_token

  id_token_expiry_time(id_token)

  params = { "id_token_hint" => id_token }
  encoded_params = URI.encode_www_form(params)
  url = discovery.end_session_endpoint + "?#{encoded_params}"
  response = Faraday.get(url)

  if [200, 302].include?(response.status)
    session.clear
    'Logged out successfully.'.tee
  else
    "Error logging out: #{response.status}".tee
  end
end
