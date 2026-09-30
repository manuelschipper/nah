const { spawn } = require('child_process');
spawn('git', ['fetch', process.argv[2]]);
