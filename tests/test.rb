require "fileutils"
require "open-uri"


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

def http_update_ip(ip, user, password)
	open "http://127.0.54.17:10080/?myip=#{ip}", http_basic_authentication: [user, password]
rescue OpenURI::HTTPError, EOFError
end


#
# Startup DNS server with our test configuration, shut it down when done and clean up changed config.
#

FileUtils.cd File.dirname(__FILE__)
FileUtils.copy_file "db.01.yml", "db.yml"
server = spawn "ruby1.9.1 ../dns.rb", out: "/dev/null"
at_exit do
	Process.kill "INT", server
	Process.wait server
	FileUtils.remove "db.yml"
end


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

# SOA for server
test "SOA record for nameserver itself",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110209 86400 7200 3600000 172800"

# Changing IPs
test "A record before change",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.2"
http_update_ip "192.168.0.22", "bar", "pw2"
test "A record after change",
	"A", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	A	192.168.0.22"
test "Updated serial of SOA record",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110210 86400 7200 3600000 172800"

test "AAAA record before adding it",
	"AAAA", "bar.dyn.example.com",
	"status: NXDOMAIN"
http_update_ip "ff80::2", "bar", "pw2"
test "AAAA record after adding it",
	"AAAA", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	AAAA	ff80::2"
test "Updated serial of SOA record",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110211 86400 7200 3600000 172800"

http_update_ip "ff80::2", "bar", "wrong-pw"
test "record after wrong HTTP password",
	"AAAA", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	AAAA	ff80::2"

http_update_ip "ff80::2", "wrong-user", "pw2"
test "record after wrong HTTP user",
	"AAAA", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	AAAA	ff80::2"
test "Unchanged serial",
	"SOA", "dyn.example.com",
	"dyn.example.com.	86400	IN	SOA	ns.example.com. dns\\\\.admin.example.com. 2015110211 86400 7200 3600000 172800"

test "A record before attempting impossible change",
	"A", "unchangable.dyn.example.com",
	"unchangable.dyn.example.com. 15	IN	A	192.168.0.3"
http_update_ip "192.168.0.30", "unchangable", ""
test "A record after attempting impossible change",
	"A", "unchangable.dyn.example.com",
	"unchangable.dyn.example.com. 15	IN	A	192.168.0.3"
http_update_ip "192.168.0.30", "unchangable", "wrong-pw"
test "A record after attempting impossible change",
	"A", "unchangable.dyn.example.com",
	"unchangable.dyn.example.com. 15	IN	A	192.168.0.3"

# Merging the DB from file
FileUtils.remove "db.yml"
FileUtils.copy_file "db.02.yml", "db.yml"
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

http_update_ip "ff80::3", "bar", "pw2"
test "unchanged record after using old password",
	"AAAA", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	AAAA	ff80::2"

http_update_ip "ff80::3", "bar", "changed-pw"
test "changed record after using new password",
	"AAAA", "bar.dyn.example.com",
	"bar.dyn.example.com.	15	IN	AAAA	ff80::3"
