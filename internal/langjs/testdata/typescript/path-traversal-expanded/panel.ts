import express, { Request, Response } from 'express'
const router = express.Router()
router.post('/', (req: Request, res: Response) => {
  void (async () => {
    const theme = { title: 'Example' }
    if (req.body.layout) { res.render('page', { ...req.body, ...theme }) }
  })()
})
export default router
