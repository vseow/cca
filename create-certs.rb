#!/usr/local/bin/ruby
require 'rubygems'
require 'digest/sha1'
require 'openssl'
require 'base64'
include OpenSSL

# Create the key
key = OpenSSL::PKey::RSA.new 2048

open 'private_key.pem', 'w' do |io| io.write key.to_pem end
open 'public_key.pem', 'w' do |io| io.write key.public_key.to_pem end
