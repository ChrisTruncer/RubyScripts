#!/usr/bin/env ruby

# This script is designed to parse a cidr range

require 'ipaddr'
require 'netaddr'

net1 = NetAddr::CIDR.create("192.168.1.0/24")

net1.enumerate.each do |ip|
  puts ip
end