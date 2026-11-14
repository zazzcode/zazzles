import { Request, Response, NextFunction } from 'express'
import fs from 'node:fs'
import unzipper from 'unzipper'
async function exportedArchive({ file }: Request, res: Response, next: NextFunction) {
  const archive = await unzipper.Open.buffer(file.buffer)
  for (const entry of archive.files) { fs.createWriteStream('incoming/' + entry.path) }
  next()
}
export { exportedArchive }
