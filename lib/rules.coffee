fs = require 'fs'
path = require 'path'
get = require 'get'
log = require './logger'
parser = require './parser'

ruleDir = path.join(__dirname, 'rules/')
ruleServer = 'http://rules.emergingthreats.net/open-nogpl/snort-edge/rules/emerging-'
    
addRule = (rule) ->

  if rule.indexOf('https://') > -1
    log.warn 'HTTP URLS ONLY!'
    log.warn 'Changing Https to Http and trying again...'
    rule = rule.replace 'https', 'http'
    
  if rule.indexOf('http://') > -1
    ruleLoc = rule #They gave us a url to install, lets download it and parse it!
    rule = path.basename ruleLoc, '.rules'
  else
    ruleLoc = ruleServer + rule + '.rules'
    
  dl = new get({uri: ruleLoc})
  dl.asString (error, result) ->
    if error
      log.error 'Failed to download ' + rule + '.rules!'
      log.error 'You either specified a non-existant file or the Snort CVS server is down'
      log.error 'Try again later or specify a valid ruleset'
      log.error result
      log.error error      
    else
      log.info rule + ' downloaded.'
      parser.parse rule, result

deleteRule = (rule) ->
  location = ruleDir + rule + '.prf'
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
    if path.extname(file) is '.prf'
      fs.unlinkSync ruleDir + file
      log.info 'Cleaned out ' + file
    
exports.location = ruleDir
