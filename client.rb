require 'httparty'

# vim: expandtab:ts=2:sw=2

class SSLConverter
	include HTTParty
  base_uri 'localhost:4567'
	
	def list_certs
		self.class.get('/process')
  end

  def delete(certid)
    self.class.delete("/certificate/#{certid}")
  end
end

slc = SSLConverter.new
p slc.send(ARGV[0], *ARGV[1..-1])
