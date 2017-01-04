module PrefillData
  def self.user_and_business(country_code)
    case country_code
    when "USA"
      _template.deep_merge(
        {
          :user => {
            :phone => "312-555-5555",
            :street_address => "222 W Merchandise Mart Plaza",
            :locality => "Chicago",
            :region => "IL",
            :postal_code => "60654",
            :country => "USA",
          },
          :business => {
            :phone => "312-555-5555",
            :currency => "USD",
            :street_address => "222 W Merchandise Mart Plaza",
            :locality => "Chicago",
            :region => "IL",
            :postal_code => "60654",
            :country => "USA",
          },
        }
      )
    when "GBR"
      _template.deep_merge(
        {
          :user => {
            :phone => "+4403457345345",
            :street_address => "123 Alderson Road",
            :postal_code => "NR30 1QG",
            :locality => "Great Yarmouth",
            :region => "Norfolk",
            :country => "GBR",
          },
          :business => {
            :phone => "+4403457345345",
            :currency => "GBP",
            :street_address => "123 Alderson Road",
            :postal_code => "NR30 1QG",
            :locality => "Great Yarmouth",
            :region => "Norfolk",
            :country => "GBR",
          },
        }
      )
    when "FRA"
      _template.deep_merge(
        {
          :user => {
            :phone => "+33140205050",
            :country => "FRA",
          },
          :business => {
            :phone => "+33140205050",
            :currency => "FRA",
            :street_address => "45 Avenue des Ternes",
            :postal_code => "75008",
            :locality => "Paris",
            :region => "France",
            :country => "FRA",
          },
        }
      )
    else
      _template
    end
  end

  def self._template
    # full reference: https://developers.braintreepayments.com/guides/braintree-auth/reference/ruby#signup-form-fields
    {
      :user => {
        :first_name => "Bob",
        :last_name => "Merchant",
        :dob_day => "01",
        :dob_month => "01",
        :dob_year => "1970",
      },
      :business => {
        :name => "Example CO",
        :registered_as => "sole_proprietorship",
        :industry => "software",
        :website => "https://example.com",
        :description => "send money",
        :established_on => "2001-05",
        :annual_volume_amount => "50,000",
        :average_transaction_amount => "10",
        :maximum_transaction_amount => "100",
        :ship_physical_goods => false,
      },
    }
  end
end
