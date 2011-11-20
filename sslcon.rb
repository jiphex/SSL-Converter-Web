#!/usr/bin/env ruby -rubygems

# TODO: Convert to use SQLite for the certificate store

require 'haml'
require 'sinatra'
require 'json'

require 'openssl'

class OpenSSL::X509::Name
	def [](field)
		firstfieldmatch = self.to_a.find {|i| i[0] == field}
		return firstfieldmatch[1]
	end
end

enable :sessions

set :public_folder, File.dirname(__FILE__) +'/public'

helpers do
	def cert_type(filename)
		return :x509 if filename.end_with? ".pem"
		return :pkcs12 if filename.end_with? ".pfx"
		return :pkcs12 if filename.end_with? ".pkcs12"
		raise ArgumentError
	end

	def valid_session?
		return false unless session[:skey]
		return true # TODO: Implement
	end

	def user_certificates(key) 
	  ucerts = {}
		targetdir = "uploads/#{session[:skey]}"
		return ucerts unless File.directory? targetdir
		Dir.foreach(targetdir) do |fn|
			next if fn.start_with? "."
			certf = File.open(targetdir+"/"+fn)
			certf.rewind
			ucert = OpenSSL::X509::Certificate.new(certf.read)
			certf.rewind
			ukey = OpenSSL::PKey::RSA.new(certf.read)
			ucerts[fn] = [ucert,ukey]
		end
		return ucerts
	end

	def get_certdata(cert_id)
		return false unless valid_session?
		targetdir = "uploads/#{session[:skey]}"
		my_certs = Dir.entries(targetdir)
		if my_certs.include? cert_id
			filedata = File.open(targetdir+"/"+cert_id).read
			ucert = OpenSSL::X509::Certificate.new(filedata)
			ukey = OpenSSL::PKey::RSA.new(filedata)
			return [ucert,ukey]
		end
		return false
	end
end

before do
	@title = 'SSL Converter!'
end

get '/' do
	if session[:skey]
		@key = session[:skey]
	else
		session[:skey] = "da9b1da7-8084-4e5d-92ad-9285cdd0f52a" #FIXME: Actually generate unique session keys
		@key = "NEWNEWNEW"
	end
	haml :index, :format => :html5
end

post '/upload' do
	raise ArgumentError unless valid_session?
	certfn = params[:certfile][:filename]
	tempfile = Tempfile.new(certfn)
	type = cert_type(certfn)
	certok = false
	begin
		tempfile.write(params['certfile'][:tempfile].read)
		tempcert = tempfile.path
		targetdir = "uploads/#{session[:skey]}"
		Dir.mkdir(targetdir) unless File.directory? targetdir
		case type
		when :x509
			tempfile.rewind
			xcert = OpenSSL::X509::Certificate.new(tempfile.read) # TODO: Work out if the PEM is encoded (password)
			tempfile.rewind
			xkey = OpenSSL::PKey::RSA.new(tempfile.read)
			ofile = File.open("#{targetdir}/#{xcert.subject['CN']}_#{xcert.serial}", 'w') do |f|
				f.puts xcert.to_text
				f.puts xcert.to_pem
				f.puts xkey.to_text
				f.puts xkey.to_pem
			end
			certok = true
		when :pkcs12
			raise ArgumentError unless params[:certpass]
			tempfile.rewind
			xpkcs = OpenSSL::PKCS12.new(tempfile.read,params[:certpass])
			xcert = xpkcs.certificate
			xkey = xpkcs.key
			ofile = File.open("uploads/#{session[:skey]}/#{xcert.subject['CN']}_#{xcert.serial}", 'w') do |f|
				f.puts xcert.to_text
				f.puts xcert.to_pem
				f.puts xkey.to_text
				f.puts xkey.to_pem
			end
			certok = true
		else
			certok = false
			# TODO: error?
		end
	ensure
		tempfile.close
	end
	redirect "/process" if certok
	raise RuntimeError
end

get '/certinfo.:format/:certid' do
  certka = get_certdata(params[:certid])
	cert = certka[0]
	key = certka[1]
	@sdata = {
		:subject => cert.subject,
		:not_before => cert.not_before,
		:not_after => cert.not_after,
		:serial => cert.serial,
		:issuer => cert.issuer
	}
	case params[:format]
	when 'json'
		set :content_type, "application/x-json"
		return sdata.to_json
	when 'html'
		haml :ajax_certinfo, :layout => false
	end
end

get '/pem/:certid' do
  set :content_type, "text/plain"
  certka = get_certdata(params[:certid])
  @pem = certka[0].to_pem+certka[1].to_pem
  haml :ajax_pem, :layout => false
end

get '/download.:format/:certid' do
	case params[:format]
	when 'pem'
		certka = get_certdata(params[:certid])
		cert = certka[0]
		key = certka[1]
		attachment "#{params[:certid]}.pem"
		cert.to_pem + key.to_pem
	when 'pfx'
		certka = get_certdata(params[:certid])
		cert = certka[0]
		key = certka[1]
		pfx = OpenSSL::PKCS12.create('Password99', 
									 "Converted certificate #{params[:certid]}",
									 key,
									 cert) #TODO: Double-check the formatting for this...
		attachment "#{params[:certid]}.der"
		pfx.to_der
	end
end

get '/upload' do
	status 405
	"You must POST a certificate to this URL!"
end

get '/process' do
	@key = session[:skey]
	@certs = user_certificates(@key)
	redirect "/" unless valid_session?
	haml :process
end
