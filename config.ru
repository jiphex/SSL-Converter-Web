require 'sinatra'

root_dir = '/home/jhan/SSL-Converter-Web'

app = File.join(root_dir, 'sslcon.rb')

set :environment, :production
set :root, root_dir
set :app_file, app
disable :run

require app
run SSLConverter
