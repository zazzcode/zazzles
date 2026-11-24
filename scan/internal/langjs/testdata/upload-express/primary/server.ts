import express from 'express'
import multer from 'multer'
import path from 'path'

const app = express()

const inMemory = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100000 } })
const kinds: any = { 'image/png': 'png', 'image/jpeg': 'jpg' }
const onDisk = multer({
  storage: multer.diskStorage({
    destination: (req: any, file: any, cb: any) => {
      const known = kinds[file.mimetype]
      let failure: Error | null = new Error('unsupported type')
      if (known) {
        failure = null
      }
      cb(failure, path.resolve('public/pictures/'))
    },
    filename: (req: any, file: any, cb: any) => {
      cb(null, file.originalname)
    }
  })
})
const sideStore = multer({
  storage: multer.diskStorage({
    destination: 'private/incoming',
    filename: (req: any, file: any, cb: any) => {
      cb(null, Date.now() + '.bin')
    }
  })
})

app.use(express.static(path.resolve('public')))

function receive (req: any, res: any) {
  res.json({ ok: true })
}

app.post('/memory/one', inMemory.single('document'), receive)
app.post('/memory/many', inMemory.array('documents', 4), receive)
app.post('/memory/named', inMemory.fields([{ name: 'front' }, { name: 'back' }]), receive)
app.post('/memory/all', inMemory.any(), receive)
app.post('/disk/one', onDisk.single('picture'), receive)
app.post('/disk/many', onDisk.array('pictures'), receive)
app.post('/disk/named', onDisk.fields([{ name: 'cover' }]), receive)
app.post('/disk/all', onDisk.any(), receive)
app.post('/side', sideStore.single('blob'), receive)
app.post('/text-only', inMemory.none(), receive)
app.post('/plain', receive)
