const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost/noderest',{ useUnifiedTopology: true});

mongoose.Promise = global.Promise;

module.exports = mongoose;