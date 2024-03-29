=begin

This test script starts the DNS server on unpriviliged ports and reproduces some manual tests done during development.

It uses the `dig` command line utility to do the DNS queries and just checks if the output contains the expected lines.
So make sure you have `dig` installed if you want to test the server.

The script starts the server by executing the `ruby` command with the DNS server as script. So it'll use the default
ruby version of your system. You can change that in the code if you want.

=end

require "fileutils"
require "open-uri"
require "openssl"


#
# Helper functions for testing
#

def test(description, type, name, *expected_lines)
	print "     #{description}..."
	STDOUT.flush
	
	output = `dig @127.0.54.17 -p 10053 #{name} #{type} +time=1`
	failed_lines = []
	expected_lines.each do |line|
		failed_lines << line unless output.lines.detect{|output_line| output_line.strip[line]}
	end
	
	if failed_lines.empty?
		puts "\r OK  #{description}   "
	else
		puts "\rFAIL #{description}   "
		puts "  failed to find lines:"
		failed_lines.each {|l| puts "    #{l}"}
		puts "  dig output:"
		output.lines.each {|l| puts "    #{l}"}
	end
end

def http_update(user, password, ip: nil, https: false, headers: {})
	url = https ? "https://127.0.54.17:10443/" : "http://127.0.54.17:10080/"
	url += "?myip=#{ip}" if ip
	URI.open url, **headers, http_basic_authentication: [user, password], ssl_verify_mode: OpenSSL::SSL::VERIFY_NONE
rescue OpenURI::HTTPError, EOFError
end


#
# Startup DNS server with our test configuration, shut it down when done and clean up changed config.
# Give the server some time to start up, otherwise our tests might run before the server actually listens.
#

FileUtils.cd File.dirname(__FILE__)
FileUtils.copy_file "db.01.yml", "db.yml"
FileUtils.chmod "o=rw", "db.yml"
server = spawn "ruby ../dns.rb", out: "/dev/null"
at_exit do
	Process.kill "INT", server
	Process.wait server
	FileUtils.remove "db.yml"
end
sleep 0.5


# Normal lookups
test "normal A record",
	"A", "foo.dyn.example.com",
	"foo.dyn.example.com.	15	IN	A	192.168.0.1"
test "normal AAAA record",
	"AAAA", "foo.dyn.example.com",
	"foo.dyn.example.com.	15	IN	AAAA	ff80::1"

# Not found or ignored lookups
test "unknown record",
	"A", "unknown.dyn.example.com",
	"status: NXDOMAIN"
test "ignoring questions for different domains",
	"A", "other-domain.example.com",
	"no servers could be reached"

# Return empty answers if we didn't found the matching record for a name but the name has other records
test "empty answer for no IPv6 address",
	"AAAA", "ipv4-only.dyn.example.com",
	"status: NOERROR",
	"ANSWER: 0"
test "empty answer for no IPv4 address",
	"A", "ipv6-only.dyn.example.com",
	"status: NOERROR",
	"ANSWER: 0"

# SOA and NS records for server itself
test "SOA record for nameserver itself",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110209 86400 7200 3600000 172800"
test "NS record for nameserver itself",
	"NS", "dyn.example.com",
	"dyn.example.com.	86400	IN	NS	ns.example.com."

# Changing IPs
test "A record before change",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.2"
http_update "bar", "pw2", ip: "192.168.0.22"
test "A record after change",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.22"
test "Updated serial of SOA record",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110210 86400 7200 3600000 172800"

test "AAAA record before adding it",
	"AAAA", "bar.dyn.example.com",
	"status: NOERROR",
	"ANSWER: 0"
http_update "bar", "pw2", ip: "ff80::2"
test "AAAA record after adding it",
	"AAAA", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	AAAA	ff80::2"
test "Updated serial of SOA record",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110211 86400 7200 3600000 172800"

# Change a record to the IP of the client connection
test "change record to connection IP (before)",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.22"
http_update "bar", "pw2"
test "change record to connection IP (after)",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	127.0.0.1"
test "change record to connection IP (updated serial of SOA record)",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110212 86400 7200 3600000 172800"
http_update "bar", "pw2", ip: "192.168.0.22"
test "change record to connection IP (after changing back)",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.22"
test "change record to connection IP (updated serial of SOA record)",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110213 86400 7200 3600000 172800"

# Change a record to the IP of the client connection via HTTPS
test "change record to connection IP via HTTPS (before)",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.22"
http_update "bar", "pw2", https: true
test "change record to connection IP via HTTPS (after)",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	127.0.0.1"
test "change record to connection IP via HTTPS (updated serial of SOA record)",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110214 86400 7200 3600000 172800"
http_update "bar", "pw2", ip: "192.168.0.22"
test "change record to connection IP via HTTPS (after changing back)",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.22"
test "change record to connection IP via HTTPS (updated serial of SOA record)",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110215 86400 7200 3600000 172800"


http_update "bar", "wrong-pw", ip: "ff80::2"
test "record after wrong HTTP password",
	"AAAA", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	AAAA	ff80::2"

http_update "wrong-user", "pw2", ip: "ff80::2"
test "record after wrong HTTP user",
	"AAAA", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	AAAA	ff80::2"
test "Unchanged serial",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110215 86400 7200 3600000 172800"

test "A record before attempting impossible change",
	"A", "unchangable.dyn.example.com",
	"unchangable.dyn.example.com. 15	IN	A	192.168.0.3"
http_update "unchangable", "", ip: "192.168.0.30"
test "A record after attempting impossible change",
	"A", "unchangable.dyn.example.com",
	"unchangable.dyn.example.com. 15	IN	A	192.168.0.3"
http_update "unchangable", "wrong-pw", ip: "192.168.0.30"
test "A record after attempting impossible change",
	"A", "unchangable.dyn.example.com",
	"unchangable.dyn.example.com. 15	IN	A	192.168.0.3"

test "A record before change via HTTPS",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.22"
http_update "bar", "pw2", ip: "192.168.0.33", https: true
test "A record after change via HTTPS",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.33"
http_update "bar", "pw2", ip: "192.168.0.22", https: true
test "A record after changing back via HTTPS",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.22"

# Resolve the server itself by using a "@" record (alias for the server itself)
test "resolve A record of itself",
	"A", "dyn.example.com",
	"dyn.example.com.	15	IN	A	192.168.0.4"
test "resolve AAAA record of itself",
	"AAAA", "dyn.example.com",
	"dyn.example.com.	15	IN	AAAA	ff80::4"

# Change the IP of the server itself
http_update "@", "pw3", ip: "192.168.0.40"
test "resolve A record of itself after change via HTTP",
	"A", "dyn.example.com",
	"dyn.example.com.	15	IN	A	192.168.0.40"


# Test 0x20 encoding of names in the questions section. Thats basically clients using a random upper and lowercase
# combination for the domain name. That makes forgeries more expensive. Reported by SebiTNT:
# http://arkanis.de/weblog/2015-11-27-build-your-own-dyndns#comment-2017-03-30-00-02-11-sebitnt
# RFC: https://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00
test "0x20 encoding (random upper and lowercase combination) Foo.Dyn.Example.Com",
	"A", "Foo.Dyn.Example.Com",
	"foo.dyn.example.com.	15	IN	A	192.168.0.1"
test "0x20 encoding (random upper and lowercase combination) fOo.dYn.eXample.Com",
	"A", "fOo.dYn.eXample.Com",
	"foo.dyn.example.com.	15	IN	A	192.168.0.1"
test "0x20 encoding (random upper and lowercase combination) FOO.DYN.EXAMPLE.COM",
	"A", "FOO.DYN.EXAMPLE.COM",
	"foo.dyn.example.com.	15	IN	A	192.168.0.1"
test "random case name as it is in database",
	"A", "rAndOMEcaSe.dyn.example.com",
	"randomecase.dyn.example.com. 15	IN	A	192.168.0.1"
test "random case name in lowercase",
	"A", "randomecase.dyn.example.com",
	"randomecase.dyn.example.com. 15	IN	A	192.168.0.1"
test "random case name in uppercase",
	"A", "RANDOMECASE.dyn.example.com",
	"randomecase.dyn.example.com. 15	IN	A	192.168.0.1"


# Merging the DB from file
FileUtils.remove "db.yml"
FileUtils.copy_file "db.02.yml", "db.yml"
FileUtils.chmod "o=rw", "db.yml"
Process.kill "USR1", server

test "deleted name",
	"A", "foo.dyn.example.com",
	"status: NXDOMAIN"
test "ignoring old IPs in DB file",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.22"
test "ignoring not-existing IPs in DB file",
	"AAAA", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	AAAA	ff80::2"

http_update "bar", "pw2", ip: "ff80::3"
test "unchanged record after using old password",
	"AAAA", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	AAAA	ff80::2"

http_update "bar", "changed-pw", ip: "ff80::3"
test "changed record after using new password",
	"AAAA", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	AAAA	ff80::3"

test "reload random case names (name isn't updated, just not deleted)",
	"A", "randomecase.dyn.example.com",
	"randomecase.dyn.example.com. 15	IN	A	192.168.0.1"


# Send invalid DNS packets to the server and see if it remains up and running
UDPSocket.open{|s| s.send "??", 0, "127.0.54.17", 10053 }
test "server answers after receiving an invalid DNS packet (just 2 byte so the flags field is missing)",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.22"
UDPSocket.open{|s| s.send "something that is longer than the initial 2 byte id", 0, "127.0.54.17", 10053 }
test "server answers after receiving an invalid DNS packet (longer than 2 bytes)",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.22"


test "Serial before updating IP with the same value",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110220 86400 7200 3600000 172800"
http_update "bar", "changed-pw", ip: "192.168.0.22"
http_update "bar", "changed-pw", ip: "ff80::3"
test "Unchanged serial after updating IP with the same value",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110220 86400 7200 3600000 172800"


# Change a record to the IP in the X-Forwarded-For header
test "change record to X-Forwarded-For IP (before)",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.22"
http_update "bar", "changed-pw", headers: { "X-Forwarded-For" => "192.168.0.23" }
test "change record to X-Forwarded-For IP (after)",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.23"
http_update "bar", "changed-pw", headers: { "X-Forwarded-For" => "192.168.0.24, 1.2.3.4" }
	test "change record to X-Forwarded-For IP (after)",
		"A", "bar.dyn.example.com",
		"bar.dyn.example.com.	15	IN	A	192.168.0.24"

# Change a record to the IP in the Forwarded header
# Example from https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
http_update "bar", "changed-pw", headers: { "Forwarded" => "for=12.34.56.78;host=example.com;proto=https, for=23.45.67.89" }
test "change record to Forwarded IP (example 1)",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	12.34.56.78"
# Example from https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded
http_update "bar", "changed-pw", headers: { "Forwarded" => 'Forwarded: For="[2001:db8:cafe::17]:4711"' }
test "change record to Forwarded IP (example 2)",
	"AAAA", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	AAAA	2001:db8:cafe::17"
# Example from https://www.holisticseo.digital/technical-seo/web-accessibility/http-header/forwarded
http_update "bar", "changed-pw", headers: { "Forwarded" => 'Forwarded : by=203.0.111.42;for="192.0.3.61";proto=https; ' }
test "change record to Forwarded IP (example 3)",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.0.3.61"
http_update "bar", "changed-pw", ip: "192.168.0.22"
test "change record to Forwarded IP (after changing back)",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.22"
