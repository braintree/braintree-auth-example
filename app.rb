require 'sinatra'
require 'sinatra/activerecord'
require 'json'

require 'uri'
require 'braintree'
require 'dotenv'

if ENV['ENVIRONMENT'] == "development"
  Dotenv.load(".development.env")
else
  Dotenv.load(".env")
end

set :database, ENV['DATABASE_URL'] || {:adapter => "sqlite3", :database => "db/development.sqlite3"}
set :bind, '0.0.0.0'
set :port, 9393

Dir[File.dirname(__FILE__) + "/models/*.rb"].each { |file| require file }

BRAINTREE_ENVIRONMENT = ENV.fetch("BRAINTREE_ENVIRONMENT", "sandbox")
# Allows you to set global credentials to restrict access to a public application
if ENV['PASSWORD']
  use Rack::Auth::Basic, "Restricted Area" do |username, password|
    username == ENV["USERNAME"] && password == ENV["PASSWORD"]
  end
end

get '/' do
  @slug = rand(10000)
  erb :index
end

post "/merchants" do
  email = params[:email]
  country_code = params[:country_code]

  @merchant = Merchant.where(:email => email).first
  if @merchant.nil?
    @merchant = Merchant.create({
      :email => email,
      :public_id => SecureRandom.uuid,
      :country_code => country_code,
    })
  end

  redirect "merchant/#{@merchant.public_id}"
end

get '/merchant/:public_id' do |public_id|
  @merchant = Merchant.find_by(:public_id => public_id)

  if @merchant.braintree_access_token.present?
    @client_token = _merchant_gateway(@merchant).client_token.generate(:version => 3)

    @transactions = _merchant_gateway(@merchant).transaction.search do |search|
      search.created_at >= Time.now - 60*60*24
    end
  else
    gateway = _oauth_gateway

    @merchant.update_attributes!(:state => SecureRandom.hex(10))
    @connect_url = gateway.oauth.connect_url(
      {
        :redirect_uri => ENV["REDIRECT_URI"],
        :scope => "read_write",
        :state => @merchant.state,
        :landing_page => "signup",
      }.merge(PrefillData.user_and_business(@merchant.country_code))
    )
  end

  erb :merchant
end

post '/merchant/:public_id/transactions' do |public_id|
  @merchant = Merchant.find_by(:public_id => public_id)
  gateway = _merchant_gateway(@merchant)

  result = gateway.transaction.sale(
    :amount => params["transaction"]["amount"],
    :payment_method_nonce => params["transaction"]["payment-method-nonce"],
    :options => {
      :submit_for_settlement => true,
    },
  )

  content_type :json
  {
    :success => result.success?,
    :errors => result.success? ? nil : result.errors,
  }.to_json
end

get '/callback' do
  state = params[:state]
  merchant = Merchant.where(:state => state).first
  if merchant.nil?
    return "Unable to verify state parameter, please try again"
  end

  unless params[:error]
    gateway = _oauth_gateway
    result = gateway.oauth.create_token_from_code(
      :code => params[:code],
    )

    merchant.update_attributes(
      :braintree_access_token => result.credentials.access_token,
      :braintree_refresh_token => result.credentials.refresh_token,
      :braintree_id => params[:merchantId],
    )
  end

  redirect to("/merchant/#{merchant.public_id}")
end


def _merchant_gateway(merchant)
  Braintree::Gateway.new({
    :access_token => merchant.braintree_access_token,
    :environment => BRAINTREE_ENVIRONMENT,
  })
end

def _oauth_gateway
  Braintree::Gateway.new({
    :client_id => ENV["CLIENT_ID"],
    :client_secret => ENV["CLIENT_SECRET"],
    :environment => BRAINTREE_ENVIRONMENT,
  })
end

def _api_key_oauth_gateway
  Braintree::Gateway.new({
    :public_key => ENV["PUBLIC_KEY"],
    :private_key => ENV["PRIVATE_KEY"],
    :environment => BRAINTREE_ENVIRONMENT,
  })
end
