pcap = require 'pcap'
log = require './logger'
tcptran = require './transport/tcp'

exports.listen = (options) ->

  # tcp is hardcoded in for now, udp can be added easily with a udp-tracker
  options ?= ['']
  proto = 'ip proto \\tcp'
  if process.getuid() isnt 0
    log.warn 'Not running with root privs which is usually required!'
    log.warn 'Attempting to run anyways...'
      
  log.debug 'Starting listener with options: '
  log.debug 'Protocol - ' + proto
  log.debug 'Interface - ' + options[0]
      
  tcp = pcap.createSession options[0], proto
  tcp_tracker = tcptran.getTracker()
    
  log.info 'Protege listening on ' + tcp.device_name
    
  tcp.on 'packet', (raw_packet) ->
    packet = pcap.decode.packet raw_packet
    tcp_tracker.track_packet packet
