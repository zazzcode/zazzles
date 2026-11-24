import crypto from 'crypto'
import bcrypt from 'bcrypt'

export const fingerprint = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const checksum = (file: Buffer) => crypto.createHash('md5').update(file).digest('hex')
export const loginDigest = (data: string) => crypto.createHash('sha256').update(data).digest('hex')
export const strong = async (data: string) => bcrypt.hash(data, 12)
