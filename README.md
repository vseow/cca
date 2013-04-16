cca
===

Covert channel application (backdoor) written in Ruby

### Prerequisites ###

INSTALL
- openssl*
- libpcap*

GEMS
- pcaprub
- packetfu
- micro-optparse

### Usage ###

Although corresponding public/private keys are supplied already, 
additional matching pairs can be created by running:
> [ruby create-certs.rb]

SERVER
After entering the appropriate interface, dest., and src. ports 
(on line by line from top to bottom), simply run: [ruby server.rb]

CLIENT
For help and options: > [ruby client.rb -h]

~Example (set interface/adapter and file to transfer)*
> [ruby client.rb -a wlan0 -f test.txt]

* There are already default values in place where additional user
defined parameters would override 
