# Braintree Auth Example

A Ruby/Sinatra application that demonstrates the [Braintree Auth](https://developers.braintreepayments.com/guides/braintree-auth/overview) API.

To start the application:

1. [Configure your OAuth application](https://developer.paypal.com/braintree/docs/guides/extend/oauth/configuration) in sandbox to include a redirect URI of `http://127.0.0.1:9393/callback`
2. Edit the `.env` file to insert the client id and client secret of your OAuth application in sandbox
3. Run the application

    ```
    bundle install
    rake db:migrate
    ./scripts/start.sh
    ```
4. Navigate to `localhost:9393`

## Documentation

Full documentation is available in the Braintree [developer docs](https://developers.braintreepayments.com/guides/braintree-auth/overview)

## Live Application

This application is currently live on Heroku at https://pseudoshop.herokuapp.com.
