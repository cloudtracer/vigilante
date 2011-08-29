#!/usr/bin/env node

/**
 * Module dependencies.
 */
 
require('coffee-script'); //This shouldn't make a difference but we may want to load .coffee files... maybe?
var vigilante = require('vigilante');
var log = vigilante.logger;
var arguments = process.argv.splice(2);
var arg = arguments[0];
var items = arguments.splice(1);

switch (arg) {
case 'install':
  vigilante.rules.install(items);
  break;

case 'update':
  vigilante.rules.update()
  break;

case 'remove':
  vigilante.rules.remove(items);
  break;

case 'wipe':
  vigilante.rules.wipe();
  break;

case 'clean':
  vigilante.rules.clean();
  break;
  
case 'listen':
  vigilante.listener.listen(items);
  break;
  
case 'version':
  log.info(vigilante.package.version);
  break;

default:
  log.info('Please enter a valid command. Usage:');
  log.info('version -- Outputs version');
  log.info('install <items> -- Installs and parses rulesets from CVS');
  log.info('remove <items> -- Removes specified rulesets');
  log.info('update -- Reinstalls all rulesets from CVS');
  log.info('wipe -- Removes all rulesets');
  log.info('clean -- Deletes unused files');
  log.info('listen <options> -- Runs listener with options');
};
