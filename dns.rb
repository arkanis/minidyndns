=begin

MiniDynDNS v1.1.0
by Stephan Soller <stephan.soller@helionweb.de>

# About the source code

To keep the source code hackable and easier to understand it's organized in
sections rather than classes. I've tried several class layouts but rejected them
all because they added to much boiler plate and self organization code. But feel
free to give it a try.

Two global variables are used throughout the code:

$config: The servers configuration, per default loaded from config.yml
$db: The DNS database, per default loaded and automatically saved to db.yml

Some functions don't take any parameters at all. They usually operate on the
global variables.

# Running tests

Execute tests/test.rb to put the DNS server through the paces. Run it as root
(e.g. via sudo) to test privilege dropping.

# Version history

1.0.0 2015-11-06  Initial release.
1.0.1 2015-11-08  Removed a left over debug output line.
1.0.2 2015-11-19  Trying to update records without a password now returns 403
                  forbidden. They're unchangable.
                  Errors during HTTP or DNS requests are now logged to stderr.
1.0.3 2015-11-25  An empty answer is now returned if we can't find the requested record but the name has other records
                  (RFC 4074 4.2. Return "Name Error").
1.1.0 2017-01-06  Added HTTPS support.
                  Fixed hanging HTTP connections of stupid routers breaking DNS
                  the server (moved HTTP servers into extra thread and imposed
                  timeout).

=end

require "optparse"
require "yaml"
require "etc"
require "socket"
require "cgi"
require "base64"
require "ipaddr"
require "openssl"
require "timeout"


#
# Logging functions to output messages with timestamps
#

# Returns true so it can be used with the "and" operator like this:
#   log("...") and return if something.broke?
def log(message)
	puts Time.now.strftime("%Y-%m-%d %H:%M:%S") + " " + message
	return true
end

def error(message)
	$stderr.puts Time.now.strftime("%Y-%m-%d %H:%M:%S") + " " + message
	return true
end

# Outputs to STDERR and exits. This way admins can redirect all errors
# into a different file if they want.
def die(message)
	abort Time.now.strftime("%Y-%m-%d %H:%M:%S") + " " + message
end


#
# "Database" code
#

# If loading the DB fails an empty DB with a new serial is generated.
def load_db
	$db = begin
		YAML.load_file $config[:db]
	rescue Errno::ENOENT
		false
	end
	$db = {} unless $db.kind_of? Hash
	$db["SERIAL"] = Time.now.strftime("%Y%m%d00").to_i unless $db.include? "SERIAL"
end

def save_db
	File.write $config[:db], YAML.dump($db)
end

# Updates the in-memory DB with new data from the DB file.
# 
# - Adds users and IPs that don't exist yet
# - Deletes users no longer in the DB file
# - Loads passwords of all users from the DB file
# - Bumps serial
# - Doesn't overwrite IP addresses in memory (they're newer than the ones in the file)
def merge_db
	edited_db = YAML.load_file $config[:db]
	
	new_users = edited_db.keys - $db.keys
	new_users.each do |name|
		$db[name] = edited_db[name]
	end
	
	deleted_users = $db.keys - edited_db.keys
	deleted_users.each do |name|
		$db.delete name
	end
	
	edited_db.each do |name, edited_data|
		next if name == "SERIAL"
		$db[name]["pass"] = edited_data["pass"]
	end
	
	$db["SERIAL"] += 1
	
	log "SERVER: Updated DB from file, added #{new_users.join(", ")}, deleted #{deleted_users.join(", ")}, updated passwords and serial"
rescue Errno::ENOENT
	nil
end



#
# DNS server code
#

# Possible values for the RCODE field (response code) in the
# DNS header, see RFC 1035, 4.1.1. Header section format
RCODE_NO_ERROR        = 0
RCODE_FORMAT_ERROR    = 1  # The name server was unable to interpret the query.
RCODE_SERVER_FAILURE  = 2  # The name server was unable to process this query due to a problem with the name server.
RCODE_NAME_ERROR      = 3  # This code signifies that the domain name referenced in the query does not exist.
RCODE_NOT_IMPLEMENTED = 4  # The name server does not support the requested kind of query.
RCODE_REFUSED         = 5  # The name server refuses to perform the specified operation for policy reasons.

# Some handy record type values, see RFC 1035, 3.2.2. TYPE values
TYPE_A     =  1  # IPv4 host address
TYPE_NS    =  2  # an authoritative name server
TYPE_CNAME =  5  # the canonical name for an alias
TYPE_SOA   =  6  # marks the start of a zone of authority
TYPE_PTR   = 12  # a domain name pointer
TYPE_TXT   = 16  # text strings
TYPE_AAAA  = 28  # IPv6 host address (see RFC 3596, 2.1 AAAA record type)
TYPE_ALL   = 255 # A request for all records (only valid in question)


# We try to ignore packets from possible attacks (queries for different domains)
# 
# packet parse error → ignore
# SOA for our domain → answer
# not our domain     → ignore
# unknown subdomain  → not found
# known subdomain    → answer
def handle_dns_packet(packet)
	id, domain, type, recursion_desired = parse_dns_question(packet)
	type_as_string = { TYPE_A => "A", TYPE_AAAA => "AAAA", TYPE_SOA => "SOA", TYPE_ALL => "ANY" }[type] or "???"
	
	# Don't respond if we failed to parse the packet
	log "DNS: Failed to parse DNS packet" and return nil unless id
	
	# Respond with a proper start of authority answer if someone wants to know
	if domain == $config["domain"] and (type == TYPE_SOA or type == TYPE_ALL)
		log "DNS: #{type_as_string} #{domain} -> SOA #{$config["soa"]["nameserver"]}, #{$config["soa"]["mail"]}, ..."
		mail_name, mail_domain = $config["soa"]["mail"].split("@", 2)
		encoded_mail = mail_name.gsub(".", "\\.") + "." + mail_domain
		return build_dns_answer id, recursion_desired, RCODE_NO_ERROR, domain, type, resource_record(TYPE_SOA, $config["soa"]["ttl"],
			soa_rdata($config["soa"]["nameserver"], encoded_mail, $db["SERIAL"], $config["soa"]["refresh_time"], $config["soa"]["retry_time"], $config["soa"]["expire_time"], $config["soa"]["negative_caching_ttl"])
		)
	end
	
	# Don't respond if the domain isn't a subdomain of our domain
	log "DNS: #{type_as_string} #{domain} -> wrong domain, ignoring" and return nil unless domain.end_with?("." + $config["domain"])
	
	# Reply with a name error if we don't know the subdomain
	name = domain[0..-($config["domain"].bytesize + 2)]
	unless $db[name]
		log "DNS: #{type_as_string} #{name} -> not found"
		return build_dns_answer(id, recursion_desired, RCODE_NAME_ERROR, domain, type)
	end
	
	begin
		records, texts = [], []
		records << resource_record(TYPE_A,    $config["ttl"], IPAddr.new($db[name]["A"]).hton)    and texts << $db[name]["A"]    if (type == TYPE_A    or type == TYPE_ALL) and $db[name]["A"]
		records << resource_record(TYPE_AAAA, $config["ttl"], IPAddr.new($db[name]["AAAA"]).hton) and texts << $db[name]["AAAA"] if (type == TYPE_AAAA or type == TYPE_ALL) and $db[name]["AAAA"]
	rescue ArgumentError
		log "DNS: #{type_as_string} #{name} -> server fail, invalid IP in DB"
		return build_dns_answer id, recursion_desired, RCODE_SERVER_FAILURE, domain, type
	end
	
	if records.empty?
		log "DNS: #{type_as_string} #{name} -> no records returned"
		return build_dns_answer id, recursion_desired, RCODE_NO_ERROR, domain, type
	else
		log "DNS: #{type_as_string} #{name} -> #{texts.join(", ")}"
		return build_dns_answer id, recursion_desired, RCODE_NO_ERROR, domain, type, *records
	end
end

# Parses a raw packet with one DNS question. Returns the query id,
# question name and type and if recursion is desired by the client.
# If parsing fails nil is returned.
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
	
	return id, question_name, question_type, recursion_desired
rescue StandardError => e
	error "DNS: Failed to parse request: #{e}"
	e.backtrace.each do |stackframe|
		$stderr.puts "\t#{stackframe}"
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



#
# DNS utility code to construct parts of DNS packets
#


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

# Payload of an SOA record, see 3.3.13. SOA RDATA format
def soa_rdata(source_host, mail, serial, refresh_interval, retry_interval, expire_interval, minimum_ttl)
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

# Generates a resource record fo the specified type, ttl in seconds
# (0 = no caching) and payload. The record always references the name of
# the first question in the packet and is always for the IN class
# (the Internet). See 4.1.3. Resource record format.
def resource_record(type, ttl, payload)
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

# Handles an entire HTTP connection from start to finish. Replies with
# an HTTP/1.0 answer so the content automatically ends when we close
# the connection.
# 
# Only reacts to the basic authentication header and myip query parameter.
# Everything else is ignored right now (path, other parameters or headers).
def handle_http_connection(connection)
	log_prefix = if connection.is_a? OpenSSL::SSL::SSLSocket then "HTTPS" else "HTTP" end
	
	# Read the entire request from the connection and fill the local variables.
	# This must not take longer that the configured number of seconds or we'll kill the connection.
	# The idea is to handle all connections in a single thread (to avoid DOS attacks) but prevent
	# stupids router from keeping connections open for ever.
	method, path_and_querystring, params, user, password = nil, nil, nil, nil, nil
	begin
		# I know timeout() is considered harmful but we rely on the global interpreter lock anyway to
		# synchronize access to $db. So the server only works correctly with interpreters that have a
		# global interpreter lock (e.g. MRI). Also this server isn't designed for high-load scenarios.
		# Given that timeout() won't hurt us to much... I hope.
		Timeout::timeout($config["http_timeout"]) do
			# Ignore empty TCP connections from chrome
			request_line = connection.gets("\n")
			return unless request_line and request_line.length > 0
			
			# Extract path and URL parameters
			method, path_and_querystring, _ = request_line.chomp.split(" ", 3)
			path, query_string = path_and_querystring.split("?", 2)
			params = query_string ? CGI::parse(query_string) : {}
			
			# Extract user and password from HTTP headers
			user, password = nil, nil
			until (line = connection.gets("\n").chomp) == ""
				name, value = line.split(": ", 2)
				if name.downcase == "authorization"
					auth_method, rest = value.split(" ", 2)
					if auth_method.downcase == "basic"
						user, password = Base64.decode64(rest).split(":", 2)
					end
				end
			end
		end
	rescue Timeout::Error
		log "#{log_prefix}: Client took to long to send data, ignoring"
		return
	end
	
	# Process request
	ip_as_string = nil
	status = catch :status do
		# Mare sure we got auth information
		throw :status, :not_authorized unless user and $db[user]
		# Tell the client if the name can't be changed
		throw :status, :unchangable if $db[user]["pass"].to_s.strip == ""
		# Make sure we're authenticated
		throw :status, :not_authorized unless password == $db[user]["pass"]
		# Make sure we got the necessary params
		throw :status, :bad_request unless params["myip"]
		
		ip_as_string = CGI::unescape params["myip"].first
		if ip_as_string == ''
			$db[user]["A"]    = nil
			$db[user]["AAAA"] = nil
		else
			begin
				ip = IPAddr.new ip_as_string
			rescue ArgumentError
				throw :status, :bad_request
			end
			if ip.ipv4?
				$db[user]["A"] = ip_as_string
			elsif ip.ipv6?
				$db[user]["AAAA"] = ip_as_string
			else
				throw :status, :bad_request
			end
		end
		
		$db["SERIAL"] += 1
		save_db
		:ok
	end
	
	case status
	when :ok
		log "#{log_prefix}: #{method} #{path_and_querystring} -> updated #{user} to #{ip_as_string}"
		connection.write [
			"HTTP/1.0 200 OK",
			"Content-Type: text/plain",
			"",
			"Your IP has been updated"
		].join("\r\n")
	when :bad_request
		log "#{log_prefix}: #{method} #{path_and_querystring} -> bad request for #{user}"
		connection.write [
			"HTTP/1.0 400 Bad Request",
			"Content-Type: text/plain",
			"",
			"You need to specify a new IP in the myip URL parameter"
		].join("\r\n")
	when :unchangable
		log "#{log_prefix}: #{method} #{path_and_querystring} -> denied, #{user} unchangable"
		connection.write [
			"HTTP/1.0 403 Forbidden",
			"Content-Type: text/plain",
			"",
			"This IP address can't be changed, sorry."
		].join("\r\n")
	else
		log "#{log_prefix}: #{method} #{path_and_querystring} -> not authorized"
		connection.write [
			"HTTP/1.0 401 Not Authorized",
			'WWW-Authenticate: Basic realm="Your friendly DynDNS server"',
			"Content-Type: text/plain",
			"",
			"Authentication required"
		].join("\r\n")
	end
rescue StandardError => e
	error "#{log_prefix}: Failed to process request: #{e}"
	e.backtrace.each do |stackframe|
		$stderr.puts "\t#{stackframe}"
	end
end



#
# Server startup
#

# Parse command line arguments
options = { config: "config.yml", db: "db.yml" }
OptionParser.new "Usage: dns.rb [options]", 20 do |opts|
	opts.on "-cFILE", "--config FILE", "YAML file containing the server configuration. Default: #{options[:config]}" do |value|
		options[:config] = value
	end
	opts.on "-dFILE", "--db FILE", "YAML file used to rembmer the IP addresses and passwords of DNS records. Default: #{options[:db]}" do |value|
		options[:db] = value
	end
	opts.on_tail "-h", "--help", "Show help" do
		puts opts
		exit
	end
end.parse!

# Load configuration
$config = begin
	YAML.load_file options[:config]
rescue Errno::ENOENT
	die "SERVER: Failed to load config file #{options[:config]}, sorry."
end
$config[:db] = options[:db]

# Load the database
load_db

# Open sockets on privileged ports
http_server = TCPServer.new $config["http"]["ip"], $config["http"]["port"]
udp_socket = UDPSocket.new
udp_socket.bind $config["dns"]["ip"], $config["dns"]["port"]

# Open HTTPS server if configured
https_server = if $config["https"]
	https_tcp_server = TCPServer.new $config["https"]["ip"], $config["https"]["port"]
	ssl_context = OpenSSL::SSL::SSLContext.new
	ssl_context.cert = OpenSSL::X509::Certificate.new File.open($config["https"]["cert"])
	ssl_context.key = OpenSSL::PKey::RSA.new File.open($config["https"]["priv_key"])
	OpenSSL::SSL::SSLServer.new https_tcp_server, ssl_context
else
	nil
end

# Drop privileges, based on http://timetobleed.com/5-things-you-dont-know-about-user-ids-that-will-destroy-you/
running_as = nil
if Process.uid == 0
	Process::Sys.setgid Etc.getgrnam($config["group"]).gid
	Process.groups = []
	Process::Sys.setuid Etc.getpwnam($config["user"]).uid
	die "SERVER: Failed to drop privileges!" if begin
		Process::Sys.setuid 0
	rescue Errno::EPERM
		false
	else
		true
	end
	
	running_as = ", as user #{$config["user"]}:#{$config["group"]}"
end

# Merge the updated DB file with the data we have in memory if someone sends us the USR1 signal
Signal.trap "USR1" do
	merge_db
end

log "SERVER: Running DNS on #{$config["dns"]["ip"]}:#{$config["dns"]["port"]}" +
	", HTTP on #{$config["http"]["ip"]}:#{$config["http"]["port"]}" +
	if https_server then ", HTTPS on #{$config["https"]["ip"]}:#{$config["https"]["port"]}" else "" end +
	"#{running_as}"


#
# Server mainloops (extra thread for HTTP and HTTPS servers, DNS in main thread)
#

# Handle HTTP/HTTPS connections in an extra thread so they don't block
# handling of DNS requests. We rely on the global interpreter lock to synchronize
# access to the $db variable.
# All incoming connections are handled one after the other by that thread. This hopefully
# makes us less susceptible to DOS attacks since attackers can only saturate that thread.
# Anyway that server design usually is a bad idea but is adequat for low load and simple
# (especially given OpenSSL integration).
Thread.new do
	loop do
		# In case https_server is nil we need to remove it from the read array.
		# Otherwise select doesn't seem to work.
		ready_servers, _, _ = IO.select [http_server, https_server].compact
		ready_servers.each do |server|
			# HTTP/HTTPS connection ready, accept, handle and close it
			connection = server.accept
			handle_http_connection connection
			connection.close
		end
	end
end


# Mainloop monitoring for incoming UDP packets. If the user presses ctrl+c we exit
# the mainloop and shutdown the server. When the main thread exits this also kills the
# HTTP thread above.
loop do
	begin
		packet, (_, port, _, addr) = udp_socket.recvfrom 512
		answer = handle_dns_packet packet
		udp_socket.send answer, 0, addr, port if answer
	rescue Interrupt
		break
	end
end

# Server cleanup and shutdown (we just kill of the HTTP thread by ending the main thread)
log "SERVER: Saving DB and shutting down"
http_server.close
udp_socket.close
save_db
