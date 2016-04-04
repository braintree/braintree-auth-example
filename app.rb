require 'sinatra'
require 'sinatra/activerecord'
require 'json'

require 'uri'
require 'braintree'

set :database, {:adapter => "sqlite3", :database => "db/development.sqlite3"}

Dir[File.dirname(__FILE__) + "/models/*.rb"].each { |file| require file }


get '/' do
  @slug = rand(10000)
  erb :index
end

post "/merchants" do
  email = params[:email]

  @merchant = Merchant.where(:email => email).first
  if @merchant.nil?
    @merchant = Merchant.create({
      :email => email,
      :public_id => SecureRandom.uuid,
    })
  end

  redirect "merchant/#{@merchant.public_id}"
end

get '/merchant/:public_id' do |public_id|
  @merchant = Merchant.find_by(:public_id => public_id)

  gateway = _oauth_gateway

  unless @merchant.braintree_id.present?
    @merchant.update_attributes!(:state => SecureRandom.hex(10))
    @connect_url = gateway.oauth.connect_url(
      :redirect_uri => "http://localhost:4567/callback",
      :scope => "read_write",
      :state => @merchant.state,
      :user => {
        :first_name => "Bob",
        :last_name => "Merchant",
        :phone => "312-555-5555",
        :dob_day => "01",
        :dob_month => "01",
        :dob_year => "1970",
        :street_address => "222 W Merchandise Mart Plaza",
        :locality => "Chicago",
        :region => "IL",
        :postal_code => "60654",
        :country => "USA",
      },
      :business => {
        :name => "Example CO",
        :registered_as => "limited_liability_corporation",
        :industry => "software",
        :phone => "312-555-5555",
        :website => "https://example.com",
        :description => "send money",
        :currency => "USD",
        :annual_volume_amount => "50,000",
        :average_transaction_amount => "10",
        :maximum_transaction_amount => "100",
        :ship_physical_goods => false,
        :street_address => "222 W Merchandise Mart Plaza",
        :locality => "Chicago",
        :region => "IL",
        :postal_code => "60654",
        :country => "USA",
      },
      :payment_methods => ["credit_card", "paypal"],
    )
  end

  @client_token = _merchant_gateway(@merchant).client_token.generate if @merchant.braintree_access_token.present?

  erb :merchant
end

post '/merchant/:public_id/transactions' do |public_id|
  @merchant = Merchant.find_by(:public_id => public_id)
  gateway = _merchant_gateway(@merchant)

  result = gateway.transaction.sale(
    :amount => params["transaction"]["amount"],
    :payment_method_nonce => params["transaction"]["paymentMethodNonce"],
    :options => {
      :submit_for_settlement => true,
    },
  )

  content_type :json
  {
    :success => result.success?,
    :errors => result.success? ? nil : result.errors.inspect,
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
      :braintree_id => params[:merchant_id],
    )
  end


  redirect to("/merchant/#{merchant.public_id}")
end

def _merchant_gateway(merchant)
  Braintree::Gateway.new({
    :access_token => merchant.braintree_access_token,
    :environment => "sandbox",
  })
end

def _oauth_gateway
  Braintree::Gateway.new({
    :client_id => "client_id$sandbox$p3zmj2rkc7cjjbhd",
    :client_secret => "client_secret$sandbox$bf38296736ddb188f4e5dfd258889430",
    :environment => "sandbox",
  })
end
