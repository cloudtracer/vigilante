#!/usr/bin/env node

/**
 * Module dependencies.
 */
 
require('coffee-script'); //This shouldn't make a difference but we may want to load .coffee files... maybe?
var protege = require('protege');
var log = protege.logger;
var arguments = process.argv.splice(2);
var arg = arguments[0];
var items = arguments.splice(1);

switch (arg) {
case 'install':
  protege.rules.install(items);
  break;

case 'update':
  protege.rules.update()
  break;

case 'remove':
  protege.rules.remove(items);
  break;

case 'wipe':
  protege.rules.wipe();
  break;

case 'clean':
  protege.rules.clean();
  break;
  
case 'listen':
  protege.listener.listen(items);
  break;
  
case 'version':
  protege.info(protege.package.version);
  break;

default:
  log.info('Please enter a valid command. Reference');
  log.info('version -- Outputs version');
  log.info('install <items> -- Installs and parses rulesets from CVS');
  log.info('remove <items> -- Removes specified rulesets');
  log.info('update -- Reinstalls all rulesets from CVS');
  log.info('wipe -- Removes all rulesets');
  log.info('clean -- Deletes unused files');
  log.info('listen <options> -- Runs listener with options');
};
