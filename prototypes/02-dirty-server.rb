=begin

Small and simple DNS server
Based on RFC 1035 (http://tools.ietf.org/html/rfc1035)

=end
require "socket"
require "ipaddr"
require "etc"
require "cgi"
require "base64"
require "yaml"



# Possible values for the RCODE field in the DNS header (response code, see RFC 1035, 4.1.1. Header section format)
RCODE_NO_ERROR        = 0
RCODE_FORMAT_ERROR    = 1  # The name server was unable to interpret the query.
RCODE_SERVER_FAILURE  = 2  # The name server was unable to process this query due to a problem with the name server.
RCODE_NAME_ERROR      = 3  # This code signifies that the domain name referenced in the query does not exist.
RCODE_NOT_IMPLEMENTED = 4  # The name server does not support the requested kind of query.
RCODE_REFUSED         = 5  # The name server refuses to perform the specified operation for policy reasons.

# Type values relevant for us, see RFC 1035, 3.2.2. TYPE values
TYPE_A     =  1  # IPv4 host address
TYPE_NS    =  2  # an authoritative name server
TYPE_CNAME =  5  # the canonical name for an alias
TYPE_SOA   =  6  # marks the start of a zone of authority
TYPE_PTR   = 12  # a domain name pointer
TYPE_TXT   = 16  # text strings
TYPE_AAAA  = 28  # IPv6 host address (see RFC 3596, 2.1 AAAA record type)
TYPE_ALL   = 255 # A request for all records (only valid in question)


# 3.3. Standard RRs
# 
# … <character-string> is a single length octet followed by that number of
# characters.  <character-string> is treated as binary information, and can
# be up to 256 characters in length (including the length octet).
def character_string(text)
	text = text.byteslice(0, 255)
	text.length.chr + text
end

# 3.1. Name space definitions
# 
# Domain names in messages are expressed in terms of a sequence of labels.
# Each label is represented as a one octet length field followed by that
# number of octets.  Since every domain name ends with the null label of
# the root, a domain name is terminated by a length byte of zero.  The
# high order two bits of every length octet must be zero, and the
# remaining six bits of the length field limit the label to 63 octets or
# less.
def domain_name(domain)
	domain.split(".").collect do |label|
		trimmed_label = label.byteslice(0, 63)
		trimmed_label.bytesize.chr + trimmed_label
	end.join("") + "\x00"
end


def soa_rdata(source_host, mail, serial, refresh_interval, retry_interval, expire_interval, minimum_ttl)
	# 3.3.13. SOA RDATA format
	# 
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# /                     MNAME                     /
	# /                                               /
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# /                     RNAME                     /
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                    SERIAL                     |
	# |                                               |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                    REFRESH                    |
	# |                                               |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                     RETRY                     |
	# |                                               |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                    EXPIRE                     |
	# |                                               |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                    MINIMUM                    |
	# |                                               |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    
    [
    	domain_name(source_host),
    	domain_name(mail),
    	serial,
    	refresh_interval,
    	retry_interval,
    	expire_interval,
    	minimum_ttl
    ].pack("a* a* N5")
end





$domain = ".dyn.zgr.info"
$ttl = 15
$db = {
	"" => {
		TYPE_SOA => soa_rdata("ns.zgr.info", "steven.zgr.info", 20151025, 3600, 600, 86400, 0)
	},
	"fusel" => {
		pass: "doiuweto",
		TYPE_A    => IPAddr.new("192.168.0.66").hton,
		TYPE_AAAA => IPAddr.new("ff80::1").hton
	},
	"steven" => {
		pass: "vcybljeopriwg",
		TYPE_A    => IPAddr.new("192.168.0.128").hton,
		TYPE_AAAA => IPAddr.new("ff80::1").hton
	}
}


def load_db
	data = YAML.load File.read("config.yml")
	return unless data
	$domain = data["domain"]
	$ttl = data["ttl"]
	$db = data["db"]
	puts "DB loaded"
rescue Errno::ENOENT
end

def save_db
	File.write "config.yml", YAML.dump({
		"domain" => $domain,
		"ttl" => $ttl,
		"db" => $db
	})
	puts "DB saved"
end

#YAML.safe_load File.read("...")
#YAML.dump $config

#$domain = ".zgr.info"
#$db = {
#	"fusel" => {ip: IPAddr.new("192.168.0.66").hton, pass: "foo"},
#	"steven" => {ip: IPAddr.new("192.168.0.128").hton, pass: "bar"}
#}


#
# DNS server code
#

# nil (parse error) → no response
# no zgr.info → no response
# unknown subdomain → not found
# known domain → answer
def handle_udp_packet(packet)
	id, domain, type, recursion_desired = parse_dns_question(packet)
	
	# Don't respond if we failed to parse the packet or the domain doesn't end the our domain name
	return nil unless id and domain.end_with? $domain
	
	# Reply with a name error if we don't know the subdomain
	name = domain[0..-($domain.bytesize + 1)]
	return build_dns_answer(id, recursion_desired, RCODE_NAME_ERROR, domain, type) unless $db[name]
	
	if type == TYPE_ALL
		# Reply with all records for that name
		records = $db[name].select{|k, v| k.kind_of? Integer}.to_a.collect do |(type, payload)|
			resource_record(type, $ttl, payload)
		end
		return build_dns_answer id, recursion_desired, RCODE_NO_ERROR, domain, type, *records
	else
		if $db[name][type]
			return build_dns_answer id, recursion_desired, RCODE_NO_ERROR, domain, type, resource_record(type, $ttl, $db[name][type])
		else
			return build_dns_answer id, recursion_desired, RCODE_NAME_ERROR, domain, type
		end
	end
end




# Parses a raw packet with one DNS question. Returns the query id, question name and type and if recursion is
# desired by the client. If parsing fails nil is returned.
def parse_dns_question(packet)
	# Taken from RFC 1035, 4.1.1. Header section format
	# 
	#                                 1  1  1  1  1  1
	#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                      ID                       |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                    QDCOUNT                    |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                    ANCOUNT                    |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                    NSCOUNT                    |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                    ARCOUNT                    |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# 
	# Z (bits 9, 10 and 11) are reserved and should be zero
	id, flags, question_count, answer_count, nameserver_count, additions_count = packet.unpack("n6")
	is_response         = (flags & 0b1000000000000000) >> 15
	opcode              = (flags & 0b0111100000000000) >> 11
	authoritative_anser = (flags & 0b0000010000000000) >> 10
	truncated           = (flags & 0b0000001000000000) >> 9
	recursion_desired   = (flags & 0b0000000100000000) >> 8
	recursion_available = (flags & 0b0000000010000000) >> 7
	response_code       = (flags & 0b0000000000001111) >> 0
	
	#puts "packet #{id}"
	#puts "  is_response #{is_response}"
	#puts "  opcode #{opcode}"
	#puts "  authoritative_anser #{authoritative_anser}"
	#puts "  truncated #{truncated}"
	#puts "  recursion_desired #{recursion_desired}"
	#puts "  recursion_available #{recursion_available}"
	#puts "  response_code #{response_code}"
	#puts "  #{question_count} questions, #{answer_count} answers, #{nameserver_count} nameservers, #{additions_count} additons"
	#
	#File.write(File.dirname(__FILE__) + "/#{id}.raw", packet)
	
	# Only continue when the packet is a standard query (QUERY, opcode == 0 and is_response = 0) with exactly one question.
	# This way we don't have to care about pointers in the question section (see RFC 1035, 4.1.4. Message compression).
	# Ignore answer, nameserver and additions counts since we don't care about the extra information.
	return unless opcode == 0 and is_response == 0 and question_count == 1
	
	
	# Taken from RFC 1035, 4.1.2. Question section format
	# 
	#                                 1  1  1  1  1  1
	#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                                               |
	# /                     QNAME                     /
	# /                                               /
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                     QTYPE                     |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                     QCLASS                    |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	
	pos = 6*2
	labels = []
	while (length = packet.byteslice(pos).ord) > 0
		labels << packet.byteslice(pos + 1, length)
		pos += 1 + length
		break if pos > packet.bytesize
	end
	pos += 1  # Skip the terminating null byte that kicked us out of the loop
	question_name = labels.join "."
	question_type, question_class = packet.unpack "@#{pos} n2"
	
	#puts "  question type #{question_type}, class #{question_class}, name #{question_name}"
	
	return id, question_name, question_type, recursion_desired
rescue StandardError => e
	puts "Failed to parse DNS request: #{e}"
	e.backtrace.each do |stackframe|
		puts "  #{stackframe}"
	end
end

def build_dns_answer(id, recursion_desired, response_code, domain, question_type, *answers)
	# Assemble flags for header
	is_response = 1          # We send a response, so QR bit is set to 1
	opcode = 0               # Opcode 0 (a standard query)
	authoritative_anser = 1  # Authoritative answer, AA bit set to 1
	truncated = 0            # Not truncated, TC set to 0
	recursion_available = 0  # Recursion available, not implemented so set to 0
	
	# Build header for the answer.
	# Taken from RFC 1035, 4.1.1. Header section format
	# 
	#                                 1  1  1  1  1  1
	#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                      ID                       |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                    QDCOUNT                    |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                    ANCOUNT                    |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                    NSCOUNT                    |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                    ARCOUNT                    |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# 
	# Z (bits 9, 10 and 11) are reserved and should be zero
	flags = 0
	flags |= (is_response         << 15) & 0b1000000000000000
	flags |= (opcode              << 11) & 0b0111100000000000
	flags |= (authoritative_anser << 10) & 0b0000010000000000
	flags |= (truncated           <<  9) & 0b0000001000000000
	flags |= (recursion_desired   <<  8) & 0b0000000100000000
	flags |= (recursion_available <<  7) & 0b0000000010000000
	flags |= (response_code       <<  0) & 0b0000000000001111
	
	header = [
		id,
		flags,
		1,               # question count
		answers.length,  # answer count
		0,               # name server count
		0                # additional records count
	].pack "n6"
	
	# Build original question from query.
	# Taken from RFC 1035, 4.1.2. Question section format
	# 
	#                                 1  1  1  1  1  1
	#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                                               |
	# /                     QNAME                     /
	# /                                               /
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                     QTYPE                     |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                     QCLASS                    |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	question_class = 1  # 1 = IN, the Internet
	question  = domain.split(".").collect{|label| label.bytesize.chr + label}.join("") + "\x00"
	question += [question_type, question_class].pack "n2"
	
	return header + question + answers.join("")
end

# Generates a resource record fo the specified type, ttl in seconds (0 = no caching) and payload.
# The record always references the name of the first question in the packet and is always for the IN class (the Internet).
def resource_record(type, ttl, payload)
	# 4.1.3. Resource record format
	# 
	#                                 1  1  1  1  1  1
	#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                                               |
	# /                                               /
	# /                      NAME                     /
	# |                                               |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                      TYPE                     |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                     CLASS                     |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                      TTL                      |
	# |                                               |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |                   RDLENGTH                    |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
	# /                     RDATA                     /
	# /                                               /
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	
	header = [
		# If the first 2 bits are set to 1 the length is interpreted as an offset into the packet where the name is
		# stored. We use this to reference the name in the first question that starts directly after the 12 byte header.
		# See RFC 1035, 4.1.4. Message compression.
		(0b1100000000000000 | 12),
		type,
		1,     # 1 = class IN (the Internet)
		ttl,   # TTL, time in seconds that the answer may be cached, 0 = no caching
		payload.bytesize
	].pack("n3 N n")
	return header + payload
end



#
# HTTP server code
#

def handle_http_connection(connection)
	first_line = connection.gets("\n")
	return unless first_line and first_line.length > 0  # Ignore empty TCP connections from chrome
	method, path_and_querystring, _ = first_line.chomp.split(" ", 3)
	path, query_string = path_and_querystring.split("?", 2)
	params = query_string ? CGI::parse(query_string) : {}
	
	user, password = nil, nil
	headers = {}
	until (line = connection.gets("\n").chomp) == ""
		name, value = line.split(": ", 2)
		headers[name.strip.downcase] = value.strip
		
		if name.downcase == "authorization"
			auth_method, rest = value.split(" ", 2)
			if auth_method.downcase == "basic"
				user, password = Base64.decode64(rest).split(":", 2)
			end
		end
	end
	
	puts "HTTP #{method}, path #{path}, query_string #{query_string.inspect}"
	puts "  user: #{user.inspect} pass: #{password.inspect}"
	puts "  params: #{params.inspect}"
	params.each do |key, value|
		puts "  param #{CGI::unescape(key)}: #{CGI::unescape(value.first)}"
	end
	headers.each do |name, value|
		puts "  header #{name}: #{value}"
	end
	
	status = catch :status do
		# Make sure we're authenticated
		throw :status, :not_authorized unless user and $db[user] and password == $db[user][:pass]
		# Make sure we got the necessary params
		throw :status, :bad_request unless params["hostname"] and params["myip"]
		
		hostname = CGI::unescape params["hostname"].first
		ip_as_string = CGI::unescape params["myip"].first
		if ip_as_string == ''
			$db[user][TYPE_A]    = nil
			$db[user][TYPE_AAAA] = nil
		else
			begin
				ip = IPAddr.new ip_as_string
			rescue ArgumentError
				throw :status, :bad_request
			end
			if ip.ipv4?
				$db[user][TYPE_A] = ip.hton
			elsif ip.ipv6?
				$db[user][TYPE_AAAA] = ip.hton
			else
				throw :status, :bad_request
			end
		end
		
		save_db
		:ok
	end
	
	case status
	when :ok
		connection.write [
			"HTTP/1.0 200 OK",
			"Content-Type: text/plain",
			"",
			"Your IP has been updated"
		].join("\r\n")
	when :bad_request
		connection.write [
			"HTTP/1.0 400 Bad Request",
			"Content-Type: text/plain",
			"",
			"You need to specify a new IP in the myip URL parameter"
		].join("\r\n")
	else
		connection.write [
			"HTTP/1.0 401 Not Authorized",
			'WWW-Authenticate: Basic realm="Your friendly dynamic DNS helper"',
			"Content-Type: text/plain",
			"",
			"Authentication required"
		].join("\r\n")
	end
rescue StandardError => e
	puts "Failed to process HTTP request: #{e}"
	e.backtrace.each do |stackframe|
		puts "  #{stackframe}"
	end
end


#
# Server main loop
#

load_db

# Open sockets on privileged ports
http_server = TCPServer.new "0.0.0.0", 81
udp_socket = UDPSocket.new
udp_socket.bind "0.0.0.0", 53

# Drop privileges, based on http://timetobleed.com/5-things-you-dont-know-about-user-ids-that-will-destroy-you/
Process::Sys.setuid Etc.getpwnam('nobody').uid
puts "Failed to drop privileges!" and exit if begin
	Process::Sys.setuid 0
rescue Errno::EPERM
	false
else
	true
end


loop do
	begin
		ready_sockets, _, _ = IO.select [http_server, udp_socket]
	rescue Interrupt
		break
	end
	if ready_sockets.include? udp_socket
		# UDP packet available, process it and send the answer (if there is one)
		packet, (_, port, _, addr) = udp_socket.recvfrom 512
		answer = handle_udp_packet packet
		udp_socket.send answer, 0, addr, port if answer
	elsif ready_sockets.include? http_server
		# HTTP connection ready, accept, handle and close it
		connection = http_server.accept
		handle_http_connection connection
		connection.close
	end
end

puts "Shutting down"
save_db
http_server.close
udp_socket.close