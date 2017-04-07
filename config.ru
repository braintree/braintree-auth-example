require "rubygems"
require "sinatra"

$stdout.sync = true

require File.expand_path '../app.rb', __FILE__

run Sinatra::Application
