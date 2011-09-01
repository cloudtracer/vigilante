pcap = require 'pcap'
log = require '../logger'
tcptran = require './transports/tcp'

exports.listen = (options) ->

  # tcp is hardcoded in for now, udp can be added easily with a udp-tracker
  options ?= ['', 'ip proto \\tcp']
  
  if process.getuid() isnt 0
    log.warn 'Not running with root privs which is usually required!'
    log.warn 'Attempting to run anyways'
      
  tcp = pcap.createSession options[0], options[1]
  tcp_tracker = tcptran.getTracker()
    
  log.info 'Protege listening on ' + tcp.device_name
  
  tcp.on 'packet', (raw_packet) ->
    packet = pcap.decode.packet raw_packet
    tcp_tracker.track_packet packet
