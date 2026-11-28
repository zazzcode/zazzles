import fs from 'node:fs'
import './first'

export const stream = fs.createWriteStream('logs/deep.log')
