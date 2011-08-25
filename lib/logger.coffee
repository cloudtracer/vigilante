require 'colors'
  
module.exports =
  log: (str) ->
    console.log str
  
  debug: (str) ->
    console.log '[' + 'SnortJS'.magenta, 'DEBUG'.white.inverse + ']', str	
      
  info: (str) ->
    console.log '[' + 'SnortJS'.magenta, 'info'.white + ']', str
      
  warn: (str) ->
    console.log '[' + 'SnortJS'.magenta, 'warn'.yellow + ']', str

  error: (str) ->
    console.log '[' + 'SnortJS'.magenta, 'ERROR'.red.inverse + ']', str
