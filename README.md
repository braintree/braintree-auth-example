# Braintree Auth Example

A Ruby/Sinatra application that demonstrates the [Braintree Auth](https://developers.braintreepayments.com/guides/braintree-auth/overview) API.

## Getting started

1. Clone this repository
2. Start the application:
    - using docker: `docker-compose up`
    - using your local machine:
      ```
      bundle install
      rake db:migrate
      ./scripts/start.sh
      ```
3. Navigate to `localhost:9393`

## Documentation

Full documentation is available in the Braintree [developer docs](https://developers.braintreepayments.com/guides/braintree-auth/overview)

## Live Application

This application is currently live on Heroku at https://pseudoshop.herokuapp.com.
