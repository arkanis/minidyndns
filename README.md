# MiniDynDNS

A simple no fuss DNS server with an build in HTTP/HTTPS interface to update IPs. It's build to be compact and simple way to access your home devices via subdomains. Something like DynDNS but just for your private needs. It's _not_ build for performance!

- Supports IPv4 and IPv6 (A and AAAA records)
- IPs are saved to and loaded from a YAML database file
- New names can be added to the YAML file, each with it's own password
- Send USR1 signal to server to make it pick up changes in the YAML file, otherwise it will overwrite it when the server shuts down.
- The server should be stared as root so it can bind to privileged ports (like 53 for DNS). It'll then drop privileges.
- Only requires Ruby 1.9 or newer. No other dependencies.


## Installation

- Make sure you have Ruby 1.9 or 2 installed (e.g. the `ruby1.9.1` package on Debian Linux).
- Download dns.rb, config.yml and db.yml. These three files are all you need.
- Modify `config.yml` to match your setup, especially the `domain`, `soa → nameserver` and `soa → mail` settings.
- Modify `db.yml` to contain your subdomains and passwords. For example:
  
  ```
  pi:
    pass: oAKrrpozHCDRLyPp97T7umf648aiYQpL
  pc:
    pass: UjQFD9Vm3nU6uzn7GPDYeHt9xxRURid6
  ```
  
  The IP addresses themselfs are best added later on via the HTTP interface. Either by your router or via a command line script (see "Some useful commands" later on).
- Run the server: `sudo ruby dns.rb`. To stop it press `ctrl+c`.

Right now I just leave it running within a `screen` terminal. But feel free to automatically start it on server boot up. If you want you can also redirect `stdout` into an access log file and `stderr` into an error log file.


## HTTP/HTTPS interface to update IPs

The HTTP interface is very minimalistic: The server only understands one HTTP request to update or invalidate IP addresses. This _isn't_ a webinterface you can use in your browser! Rather it's the interface your router can use to automatically report a changed IP to the DNS server (look for something like DynDNS in your router configuration). The HTTP interface is inspired by DynDNS and others so routers can easily be configured to report to this DNS server.

HTTP basic auth is used for all HTTP requests. The username and password have to match one configured in the `db.yml` file. For example with the HTTP user `pi` and password `oAKrrpozHCDRLyPp97T7umf648aiYQpL` you can update the IP address of the `pi` subdomain.

The HTTP request `GET /?myip=[ip]` where `[ip]` is either an IPv4 or IPv6 address then assigns a new address to the subdomain matching the authentication.

If `[ip]` is an empty string (`GET /?myip=`) both the IPv4 and IPv6 address are invalidated. The server won't return an IP for that subdomain until a new IP is assigned.

You can use `wget` on the command line or in scripts to assign a new IP to a subdomain (see "Some useful commands"). Languages like PHP and Ruby can also do HTTP requests directly.


## Deleting users and changing passwords

To add or delete a user you can modify the `db.yml` file. Same for changing passwords: Just change them in `db.yml`.

But after you did that you have to tell the server to pick up those changes. To do this send it the USR1 signal (see "Some useful commands"). Otherwise the server will ignore the changes and overwrite the `db.yml` file when the next IP is updated.

When you change an IP in `db.yml` the server will ignore it. It is designed to receive all IP updates via the HTTP interface.


## Some useful commands

All these commands assume that the DNS server is running on 127.0.0.2 with default ports (53 for DNS, 80 for HTTP, 443 for HTTPS).

Update a name with a new IPv4 or IPv6 address:

	wget --user foo --password bar -O /dev/null http://127.0.0.2/?myip=192.168.0.1
	wget --user foo --password bar -O /dev/null http://127.0.0.2/?myip=ff80::1

Same with `curl` and over HTTPS:

	curl -u foo:bar --cacert server_cert.pem https://127.0.0.2/?myip=192.168.0.2
	curl -u foo:bar --cacert server_cert.pem https://127.0.0.2/?myip=ff80::1

Note: Don't use the self-signed certificate of your CA with `--cacert`. For some reason this causes OpenSSL to freak out and block the entire HTTP/HTTPS interface. Please let me know if you know why.

Send an USR1 signal to the server to make it pick up changes from the
YAML database file:

	sudo pkill -USR1 -o -f dns.rb

Shutdown the server by sending it the INT signal (like pressing `ctrl+c`):

	sudo pkill -INT -o -f dns.rb

Query IPv4 (A), IPv6 (AAAA) or both (ANY) records from DNS server running on 127.0.0.2:

	dig @127.0.0.2 foo.dyn.example.com A
	dig @127.0.0.2 foo.dyn.example.com AAAA
	dig @127.0.0.2 foo.dyn.example.com ANY

Query the servers start of authority (SOA) record:

	dig @127.0.0.2 dyn.example.com SOA
