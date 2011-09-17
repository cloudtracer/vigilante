require 'protege'
require('node-log').setName 'vigilante'
   
module.exports = 
  rules: require './rules'
  listener: require './engine/listener'
