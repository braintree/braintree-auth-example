class AddCountryCode < ActiveRecord::Migration
  def change
    add_column :merchants, :country_code, :string, :default => 'USA'
  end
end
