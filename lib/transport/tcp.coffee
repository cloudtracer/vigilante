pcap = require 'pcap'

exports.getTracker = ->

  tracker = new pcap.TCP_tracker()
  
  tracker.on 'websocket message', (session, dir, message) ->
    if dir is 'send' # we only want to catch incoming stoof
      obj = JSON.parse message
      log.debug session.src_name + ' -> WebSocket Message: ' + obj
  
  tracker.on 'http request', (session, http) ->
    log.debug session.src_name + ' -> HTTP Request: ' + http.request.method
    
    if session.http_request_count
      session.http_request_count += 1;
    else
      session.http_request_count = 1;
    http.request.binary_body = (http.request.headers['Content-Type'] && (/^(image|video)/).test(http.request.headers['Content-Type']))
    
  tracker.on 'http request body', (session, http, data) ->
    log.debug session.src_name + ' -> HTTP Request Body: ' + http.request.method
    if !http.request.binary_body
      log.debug data.toString('utf8')
        
  return tracker
