fs = require 'fs'
path = require 'path'
get = require 'get'
log = require './logger'
parser = require './parser'

ruleDir = path.join(__dirname, 'rules/')
ruleServer = 'http://cvs.snort.org/viewcvs.cgi/*checkout*/snort/rules/'
    
addRule = (rule) ->
  dl = new get({uri: ruleServer + rule + '.rules'})
  dl.asString (error, result) ->
    if error
      log.error 'Failed to download ' + rule + '.rules!'
      log.error 'You either specified a non-existant file or the Snort CVS server is down'
      log.error 'Try again later or specify a valid ruleset'
      log.error 'Response Code: ' + result.code
      log.error error      
    else
      log.info rule + ' downloaded.'
      parser.parse rule, result

deleteRule = (rule) ->
  location = ruleDir + rule + '.srs'
  fs.unlinkSync location
  log.info rule + ' deleted'
    
exports.install = (rules) ->
  for name in rules
    addRule name

exports.remove = (rules) ->
  for name in rules
    deleteRule name
      
exports.wipe = ->
  log.info 'Emptying rules folder'
  files = fs.readdirSync ruleDir
  for file in files
    fs.unlinkSync ruleDir + file
    log.info 'Cleaned out ' + file
    
exports.clean = ->
  log.info 'Cleaning rules folder'
  files = fs.readdirSync ruleDir
  for file in files
    if file.indexOf('.srs') < 0
      fs.unlinkSync ruleDir + file
      log.info 'Cleaned out ' + file
    
exports.location = ruleDir
