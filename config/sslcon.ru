require 'sinatra'

set :environment, :production
disable :run

require 'sslcon'
run Sinatra::Application
