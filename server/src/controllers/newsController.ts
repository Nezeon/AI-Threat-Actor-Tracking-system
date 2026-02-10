import { Request, Response, NextFunction } from 'express';
import * as geminiService from '../services/geminiService.js';

export const getNews = async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const news = await geminiService.getLiveCyberNews();
    res.json(news);
  } catch (error) {
    next(error);
  }
};
