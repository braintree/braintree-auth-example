class AddCountryCode < ActiveRecord::Migration[5.0]
  def change
    add_column :merchants, :country_code, :string, :default => 'USA'
  end
end
