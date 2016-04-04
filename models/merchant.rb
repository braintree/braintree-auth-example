class Merchant < ActiveRecord::Base
  KEY = "Jt4BWW375DkoBaiX22bQRt6xzwnFdUIbTCENxK4lOqw="

  validates_presence_of :email

  def braintree_access_token=(raw_access_token)
    write_attribute(:encrypted_braintree_access_token, encrypt_value(raw_access_token))
  end

  def braintree_refresh_token=(raw_refresh_token)
    write_attribute(:encrypted_braintree_refresh_token, encrypt_value(raw_refresh_token))
  end

  def braintree_access_token
    decrypt_value(encrypted_braintree_access_token)
  end

  def braintree_refresh_token
    decrypt_value(encrypted_braintree_refresh_token)
  end

  def decrypt_value(raw_string)
    return nil if raw_string.nil?

    cipher = cipher(:decrypt)
    cipher.update(Base64.decode64(raw_string)) + cipher.final
  end

  def encrypt_value(raw_string)
    return nil if raw_string.nil?

    cipher = cipher(:encrypt)
    Base64.encode64(cipher.update(raw_string) + cipher.final)
  end

  def cipher(method)
    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.send(method)
    cipher.key = Base64.decode64(KEY)
    cipher.iv = "\0" * 16
    cipher
  end
end
