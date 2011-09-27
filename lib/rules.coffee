fs = require 'fs'
path = require 'path'
get = require 'get'
log = require 'node-log'
async = require 'async'
snortParser = require './parsers/snort'
config = require './config'
    
addRule = (rule, call) ->
  if rule.startsWithIgnoreCase 'https://'
    log.warn 'http URLs only!'
    log.warn 'Changing https to http and trying again'
    rule = rule.replace 'https', 'http'
    
  if rule.startsWithIgnoreCase 'http://'
    ruleLoc = rule #They gave us a url to install, lets download it and parse it!
    log.debug 'Installing from URL'
    rule = path.basename ruleLoc, config.snortext
  else
    ruleLoc = config.snortcvs + rule + config.snortext
    
  dl = new get({uri: ruleLoc})
  dl.asString (error, result) ->
    if error
      log.error 'Failed to download ' + rule + config.snortext + '!'
      log.error 'You either specified a non-existant file or the Snort CVS server is down'
      log.error 'Try again later or specify a valid ruleset'
      log.error result if result
      log.error error   
      return call()
    else
      log.debug rule + ' downloaded.'
      snortParser.parse rule, result, (out) ->
        fs.writeFile path.normalize(config.ruledir + rule + config.ruleext), out.prettify(), (err) ->
          throw err if err
          log.info rule + ' was written to ' + path.normalize(config.ruledir + rule + config.ruleext)
          return call()

deleteRule = (rule, call) ->
  fs.unlink config.ruledir + rule + config.ruleext, (err) ->
    throw err if err
    log.info rule + 'deleted'
    call()

delFile = (file, call) ->
  fs.unlink config.ruledir + file, (err) ->
    throw err if err
    log.info 'Cleaned out' + file
    call()

module.exports =                
  install: (rules, cb) ->
    async.forEach rules, addRule, cb

  remove: (rules, cb) ->
    async.forEach rules, deleteRule, cb
        
  wipe: (cb) ->
    log.info 'Emptying rules folder'
    fs.readdir config.ruledir, (err, files) ->
      throw err if err
      async.forEach files, delFile, cb
      
  clean: (cb) ->
    log.info 'Cleaning rules folder'
    fs.readdir config.ruledir, (err, files) ->
      async.forEach files, delFile, cb
