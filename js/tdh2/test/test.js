import { randomBytes, randomInt } from 'crypto'
import pkg from '../tdh2.js';
const { encrypt } = pkg;

const pub = JSON.parse(process.argv.slice(2)[0]);

for (let i = 0; i < 100; i++) {
    const msg = randomBytes(randomInt(1, 5000))
    console.log(msg.toString('base64'))
    console.log(encrypt(pub, msg))
}
