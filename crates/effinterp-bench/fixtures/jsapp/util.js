const fs = require('fs');
function wipe(p){ fs.rmSync(p, {recursive:true}); }
module.exports = { wipe };
