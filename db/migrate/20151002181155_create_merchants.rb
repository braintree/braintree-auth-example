class CreateMerchants < ActiveRecord::Migration[5.0]
  def change
    create_table :merchants do |t|
      t.string :email
      t.string :encrypted_braintree_access_token
      t.string :encrypted_braintree_refresh_token
      t.string :braintree_id
      t.string :public_id
      t.string :state

      t.timestamps
    end
  end
end
