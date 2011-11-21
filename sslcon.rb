#!/usr/bin/env ruby -rubygems

# vim: ts=2:sw=2:expandtab

require 'haml'
require 'sinatra'
require 'json'

require 'sqlite3'

DB_FILENAME='sslconverter.sqlite3.db'

require 'openssl'

module OpenSSL::X509
  class Name
    def [](field)
      firstfieldmatch = self.to_a.find {|i| i[0] == field}
      return firstfieldmatch[1]
    end
  end
  class Certificate
    def uniq_name
      return "#{self.subject['CN']}-----#{self.serial}"
    end
  end
end

enable :sessions

set :public_folder, File.dirname(__FILE__) +'/public'

helpers do
  def init_db
    logger.info "INITIALIZING DB!!"
    db = SQLite3::Database.new(DB_FILENAME)
    db.execute("CREATE TABLE certs(id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT, not_before INTEGER, not_after INTEGER, cert_pem TEXT, key_pem TEXT, ca_pem TEXT, owner TEXT);")
  end

  def get_db
    init_db unless File.exist?(DB_FILENAME)
    db = SQLite3::Database.new(DB_FILENAME)   
    return db
  end

  def cert_type(filename)
    return :x509 if filename.end_with? ".pem"
    return :pkcs12 if filename.end_with? ".pfx"
    return :pkcs12 if filename.end_with? ".pkcs12"
    return :pkcs12 if filename.end_with? ".der"
    raise "Choose a valid certificate file extension next time..."
  end

  def valid_session?
    return 401 unless session[:skey]
    return true # TODO: Implement
  end

  def user_certificates(key) 
    ucerts = {}
    dbc = get_db
    dbc.execute("select cert_pem,key_pem from certs where owner == ?", session[:skey]) do |row|
      cert_pem = row[0]
      cert = OpenSSL::X509::Certificate.new(cert_pem)
      key_pem = row[1]
      key = OpenSSL::PKey::RSA.new(key_pem)
      ucerts[cert.uniq_name] = [cert,key]
    end
    return ucerts
  end

  def get_certdata(cert_id)
    return 401 unless valid_session?
    dbc = get_db
    dbc.execute("select cert_pem,key_pem from certs where owner == ?", session[:skey]) do |row|
        ucert = OpenSSL::X509::Certificate.new(row[0])
        ukey = OpenSSL::PKey::RSA.new(row[1])
        return [ucert,ukey] if(ucert.uniq_name == cert_id)
    end
    return false
  end
end

error do
  status 500
  @message = env['sinatra.error']
  haml :error
end

before do
  cache_control :private
  @title = 'SSL Converter!'
end

get '/' do
  if session[:skey]
    @key = session[:skey]
  else
    session[:skey] = rand(36**8).to_s(36)
    @key = "NEWNEWNEW"
  end
  haml :index, :format => :html5
end

post '/upload' do
  return 401 unless valid_session?
  dbc = get_db
  certfn = params[:certfile][:filename]
  tempfile = Tempfile.new(certfn)
  type = cert_type(certfn)
  certok = false
  begin
    tempfile.write(params['certfile'][:tempfile].read)
    tempcert = tempfile.path
    case type
    when :x509
      tempfile.rewind
      xcert = OpenSSL::X509::Certificate.new(tempfile.read) # TODO: Work out if the PEM is encoded (password)
      tempfile.rewind
      xkey = OpenSSL::PKey::RSA.new(tempfile.read)
      dbc.execute("insert into certs (subject,not_before,not_after,cert_pem,key_pem,owner) values (?,?,?,?,?,?)",
                  xcert.subject,
                  xcert.not_before.to_i,
                  xcert.not_after.to_i,
                  xcert.to_pem,
                  xkey.to_pem,
                  session[:skey])
      certok = true
    when :pkcs12
      raise ArgumentError unless params[:certpass]
      tempfile.rewind
      xpkcs = OpenSSL::PKCS12.new(tempfile.read,params[:certpass])
      xcert = xpkcs.certificate
      xkey = xpkcs.key
      dbc.execute("insert into certs (subject,not_before,not_after,cert_pem,key_pem,owner) values (?,?,?,?,?,?)",
                  xcert.subject,
                  xcert.not_before.to_i,
                  xcert.not_after.to_i,
                  xcert.to_pem,
                  xkey.to_pem,
                  session[:skey])
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

delete '/certificate/:certid' do
  dbc = get_db
  return 401 unless valid_session?
  targetid = -1
  dbc = get_db
  rows = dbc.execute("select cert_pem,id from certs where owner == ?", session[:skey])
  p rows
  rows.each do |row|
      ucert = OpenSSL::X509::Certificate.new(row[0])
      logger.info "UCERT ID is #{ucert.uniq_name}"
      if(ucert.uniq_name == params[:certid])
        targetid = row[1] 
        logger.info "FOUND CERTID AS #{targetid}"
        break
      end
  end
  logger.info "TARGETID is #{targetid}"
  if targetid.to_i >= 0
    res = dbc.execute("delete from certs where owner == ? and id == ?", session[:skey],targetid)
    return "OK" if res.length > 0
    status 404
    "Certificate Not Deleted"
  end
  status 404
  "Certificate Not in DB"
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

get '/logout' do
  session.clear
  redirect "/" 
end
