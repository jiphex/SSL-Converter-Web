require 'sinatra'

root_dir = '/srv/ruby/ssl'

app = File.join(root_dir, 'sslcon.rb')

set :environment, :production
set :root, root_dir
set :app_file, app
disable :run

require app
run SSLConverter
