import express, { Request, Response } from 'express';
import { exec } from 'child_process';

const app = express();

app.get('/api/ping', (req: Request, res: Response) => {
  const host: string = req.query.host as string;
  exec(`ping -c 3 ${host}`, (error: any, stdout: string, stderr: string) => {
    if (error) {
      res.json({ error: error.message, stdout, stderr });
    } else {
      res.json({ success: true, output: stdout });
    }
  });
});
