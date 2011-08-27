require 'colors'
pack = require('./package').load()
  
module.exports =
  log: (str) ->
    console.log str
  
  debug: (str) ->
    console.log '[' + pack.name.magenta, '-', 'DEBUG'.green.inverse + ']', str	
      
  info: (str) ->
    console.log '[' + pack.name.magenta, '-', 'info'.white + ']', str
      
  warn: (str) ->
    console.log '[' + pack.name.magenta, '-', 'warn'.yellow + ']', str

  error: (str) ->
    console.log '[' + pack.name.magenta, '-', 'ERROR'.red.inverse + ']', str
