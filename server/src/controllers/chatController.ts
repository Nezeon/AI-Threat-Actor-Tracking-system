import { Request, Response, NextFunction } from 'express';
import * as geminiService from '../services/geminiService.js';

export const chat = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { message, context } = req.body;
    if (!message) return res.status(400).json({ message: 'Message is required' });

    const response = await geminiService.chatWithAI(message, context);
    res.json({ response });
  } catch (error) {
    next(error);
  }
};
