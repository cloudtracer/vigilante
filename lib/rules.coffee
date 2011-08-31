fs = require 'fs'
path = require 'path'
get = require 'get'
log = require './logger'
parser = require './parser'
config = require './config'
    
addRule = (rule) ->

  if rule.startsWithIgnoreCase 'https://'
    log.warn 'http URLs only!'
    log.warn 'Changing https to http and trying again'
    rule = rule.replace 'https', 'http'
    
  if rule.startsWithIgnoreCase 'http://'
    ruleLoc = rule #They gave us a url to install, lets download it and parse it!
    rule = path.basename ruleLoc, config.snortext
  else
    ruleLoc = config.snortcvs + rule + config.snortext
    
  dl = new get({uri: ruleLoc})
  dl.asString (error, result) ->
    if error
      log.error 'Failed to download',rule + config.snortext + '!'
      log.error 'You either specified a non-existant file or the Snort CVS server is down'
      log.error 'Try again later or specify a valid ruleset'
      log.error result
      log.error error      
    else
      log.info rule,' downloaded.'
      parser.parse rule, result

deleteRule = (rule) ->
  location = config.ruledir + rule + config.fileext
  fs.unlinkSync location
  log.info rule, 'deleted'
    
exports.install = (rules) ->
  rules.forEach addRule

exports.remove = (rules) ->
  rules.forEach deleteRule
      
exports.wipe = ->
  log.info 'Emptying rules folder'
  files = fs.readdirSync config.ruledir
  for file in files
    fs.unlinkSync config.ruledir + file
    log.info 'Cleaned out', file
    
exports.clean = ->
  log.info 'Cleaning rules folder'
  files = fs.readdirSync config.ruledir
  for file in files
    if path.extname(file) is config.fileext
      fs.unlinkSync config.ruledir + file
      log.info 'Cleaned out',file
