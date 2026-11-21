export function login() {
  return (req: Request, res: Response) => {
    const email = req.body.email
    const query = `SELECT * FROM users WHERE email = '${email}'`
    database.query(query)
  }
}
