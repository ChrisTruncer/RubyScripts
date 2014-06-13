#!/usr/bin/env ruby

# Script to parse .nessus file and identify any live web servers

require 'nokogiri'

class NessusParser < Nokogiri::XML::SAX::Document
  
  def initialize
    @system_name = nil
    @service_name = nil
    @plugin_name = nil
  end

  def start_element name, attrs = []
    @attrs = attrs

    if name == "ReportHost"
      @attrs.each do |key, value|
        if key == "name"
          @system_name = value
        end
      end
      puts @system_name
    end


  end    # End of start_element function


  def end_element name
  end   # End of end_element function

  def url_get
    @url_array
  end

end   # End of nmap parsing class

nessus_class = NessusParser.new

parser = Nokogiri::XML::SAX::Parser.new(nessus_class)

parser.parse(File.open(ARGV[0]))