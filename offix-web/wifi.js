var rabbit = require('rabbit.js');

var config = require('./config');
var utils = require('./utils/utils');
var User = require('./models/user');

var wifi = module.exports = {};

var consume = function(db, data) {
  var parsed = data.split('\t');
  if (utils.isMacAddress(parsed[0])) {
    User.seen(parsed[0], parsed[1], parsed[2]);
  }
};

wifi.start = function(db) {
  var context = rabbit.createContext();
  context.on('ready', function() {
    var sub = context.socket('SUB'); // subscription
    sub.setEncoding('utf-8');
    sub.connect(config.EXCHANGE_NAME, '', function() {
      sub.on('data', function(data) {
        console.log('got data from rabbitmq: ' + data);
        consume(db, data);
      });
    });
  });
};
