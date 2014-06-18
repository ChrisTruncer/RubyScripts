#!/usr/bin/env ruby

require 'socket'
require 'timeout'

# This is a super basic port scanner with code taken and modified from:
# http://stackoverflow.com/questions/517219/ruby-see-if-a-port-is-open

port_open = false

begin
  Timeout.timeout(5) do
    begin
      s = TCPSocket.new('192.168.2.1', 80)
      s.close
      puts "open!"
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
      puts "closed!"
    end
  end
rescue Timeout::Error
end