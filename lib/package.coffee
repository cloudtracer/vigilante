exports.package = 'Unloaded'

# Singleton for the contents of package.json
exports.load = ->
  if exports.package is 'Unloaded'
    fs = require 'fs'
    path = require 'path'
    location = path.join(__dirname, '../', 'package.json')
    return JSON.parse fs.readFileSync(location)
  else
    return exports.package
