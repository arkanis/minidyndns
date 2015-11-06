=begin

Small and simple DNS server
Based on RFC 1035 (http://tools.ietf.org/html/rfc1035)

=end
require "socket"
require "ipaddr"


class ByteStream
	attr_reader :pos
	
	def initialize(data)
		@data = data
		@pos = 0
	end
	
	def byte(number_of_bytes = 1)
		values = []
		number_of_bytes.times do
			values << @data.byteslice(@pos).ord
			@pos += 1
		end
		if values.length == 1
			return values.first
		else
			return *values
		end
	end
	
	def short(number_of_shorts = 1)
		values = []
		number_of_shorts.times do
			values << @data.byteslice(@pos, 2).unpack("n").first
			@pos += 2
		end
		if values.length == 1
			return values.first
		else
			return *values
		end
	end
	
	def raw(count)
		@pos += count
		@data.byteslice(@pos - count, count)
	end
end

Socket.udp_server_loop("127.0.0.2", 53) do |raw_packet, sender|
	packet = ByteStream.new raw_packet
	
	# Header
	id, flags, question_count, answer_count, nameserver_count, additions_count = packet.short(6)
	#File.write(File.dirname(__FILE__) + "/#{id}.raw", raw_packet)
	is_response = flags[0]
	opcode = (flags & 0b0000000000011110) >> 1
	authoritative_anser = flags[5]
	truncated = flags[6]
	recursion_desired = flags[7]
	recursion_available = flags[8]
	# Z (bits 9, 10 and 11) must be zero
	response_code = (flags & 0b1111000000000000) >> 12
	puts "packet #{id}"
	puts "  is_response #{is_response}"
	puts "  opcode #{opcode}"
	puts "  authoritative_anser #{authoritative_anser}"
	puts "  truncated #{truncated}"
	puts "  recursion_desired #{recursion_desired}"
	puts "  recursion_available #{recursion_available}"
	puts "  response_code #{response_code}"
	puts "  #{question_count} questions, #{answer_count} answers, #{nameserver_count} nameservers, #{additions_count} additional records"
	
	# Questions section
	question_type = nil
	question_class = nil
	question_name = nil
	question_start = packet.pos
	question_count.times do
		labels = []
		# TODO handle pointers?!
		while (length = packet.byte) > 0
			labels << packet.raw(length)
		end
		question_name = labels.join "."
		question_type = packet.short
		question_class = packet.short
		
		puts "  question type #{question_type} class #{question_class} name #{question_name}"
	end
	question_length = packet.pos - question_start
	
	ips = {
		"fusel.zgr.info" => "192.168.0.66",
		"steven.zgr.info" => "192.168.0.128"
	}
	
	# type A (host address) == 1, class IN (the Internet) == 1
	if question_count == 1 and question_type == 1 and question_class == 1
		if ips[question_name]
			puts "reply #{question_name} -> #{ips[question_name]}"
			
			answer = [
				id,
				(
					(0b1               << 15) |  # we send a response, so QR bit is set to 1
					(0                 << 11) |  # Opcode 0 (a standard query)
					(0b0               << 10) |  # Authoritative Answer, AA bit set to 1
					(0b0               <<  9) |  # Not truncated, TC set to 0
					(recursion_desired <<  8) |  # Recursion Desired, copied over from query
					(0b0               <<  7) |  # Recursion Available, not implemented so set to 0
					(0b000             <<  4) |  # Z bits reserved and left at 0
					(0                 <<  0)    # Response code, 0 = no error condition
				),
				question_count,
				1,  # answer count
				0,  # name server count
				0   # additional records count
			].pack "n6"
			
			answer += raw_packet.byteslice(question_start, question_length)
			
			answer += [
				(0b1100000000000000 | 12),  # pointer to the domain name in the question section (starts directly after 12 byte header)
				question_type,
				question_class,
				10,  # TTL, time in seconds that the answer may be cached, 0 = no caching
				4    # data length, A record is 4 bytes long (IPv4 address)
			].pack("n3 N n")
			
			answer += IPAddr.new(ips[question_name]).hton
			puts answer.inspect
			File.write(File.dirname(__FILE__) + "/#{id}.answer.raw", answer)
			
			sender.reply answer
		else
			puts "don't know #{question_name}"
			
			answer = [
				id,
				(
					(0b1               << 15) |  # we send a response, so QR bit is set to 1
					(0                 << 11) |  # Opcode 0 (a standard query)
					(0b1               << 10) |  # Authoritative Answer, AA bit set to 1
					(0b0               <<  9) |  # Not truncated, TC set to 0
					(recursion_desired <<  8) |  # Recursion Desired, copied over from query
					(0b0               <<  7) |  # Recursion Available, not implemented so set to 0
					(0b000             <<  4) |  # Z bits reserved and left at 0
					(3                 <<  0)    # Response code, 3 = name error, domain doesn't exist
				),
				question_count,
				0,  # answer count
				0,  # name server count
				0   # additional records count
			].pack "n6"
			answer += raw_packet.byteslice(question_start, question_length)
			sender.reply answer
		end
	else
		puts "not implemented"
		
		answer = [
			id,
			(
				(0b1               << 15) |  # we send a response, so QR bit is set to 1
				(opcode            << 11) |  # Opcode 0 (a standard query)
				(0b1               << 10) |  # Authoritative Answer, AA bit set to 1
				(0b0               <<  9) |  # Not truncated, TC set to 0
				(recursion_desired <<  8) |  # Recursion Desired, copied over from query
				(0b0               <<  7) |  # Recursion Available, not implemented so set to 0
				(0b000             <<  4) |  # Z bits reserved and left at 0
				(4                 <<  0)    # Response code, 4 = not implemented
			),
			0,  # question count
			0,  # answer count
			0,  # name server count
			0   # additional records count
		].pack "n6"
		sender.reply answer
	end
	
	#sender.reply packet
end