import { Request, Response, NextFunction } from 'express';
import * as dbModel from '../models/db.js';
import fs from 'fs';
import path from 'path';
import * as XLSX from 'xlsx';

// PDF parsing helper for Node.js
async function parsePDF(filePath: string): Promise<string> {
  // Dynamic import to handle ESM - pdfjs-dist has no type declarations for this path
  // @ts-ignore: no type declarations for legacy build entry
  const pdfjsLib: any = await import('pdfjs-dist/legacy/build/pdf.mjs');
  const data = new Uint8Array(fs.readFileSync(filePath));
  const pdf = await pdfjsLib.getDocument({ data }).promise;

  let fullText = '';
  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const textContent = await page.getTextContent();
    const pageText = textContent.items.map((item: any) => item.str).join(' ');
    fullText += pageText + '\n';
  }
  return fullText;
}

// CSV/XLSX parsing helper
function parseSpreadsheet(filePath: string): string {
  const data = fs.readFileSync(filePath);
  const workbook = XLSX.read(data, { type: 'buffer' });
  const sheetName = workbook.SheetNames[0];
  const worksheet = workbook.Sheets[sheetName];
  return XLSX.utils.sheet_to_csv(worksheet);
}

export const getAllActorNames = async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const names = await dbModel.getAllTrustedActorNames();
    res.json(names);
  } catch (error) {
    next(error);
  }
};

export const getSourcesForActor = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const actorName = decodeURIComponent(req.params.actorName as string);
    const urls = await dbModel.getTrustedUrls(actorName);
    const files = await dbModel.getTrustedFiles(actorName);
    res.json({ urls, files });
  } catch (error) {
    next(error);
  }
};

export const addUrl = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { actorName, url } = req.body;
    if (!actorName || !url) return res.status(400).json({ message: 'actorName and url are required' });

    try {
      new URL(url);
    } catch {
      return res.status(400).json({ message: 'Invalid URL format' });
    }

    const result = await dbModel.addTrustedUrl(actorName, url);
    res.json(result);
  } catch (error) {
    next(error);
  }
};

export const removeUrl = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = parseInt(req.params.id as string);
    if (isNaN(id)) return res.status(400).json({ message: 'Invalid ID' });
    await dbModel.removeTrustedUrl(id);
    res.json({ message: 'URL removed' });
  } catch (error) {
    next(error);
  }
};

export const uploadFile = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const file = req.file;
    const actorName = req.body.actorName;

    if (!file) return res.status(400).json({ message: 'No file uploaded' });
    if (!actorName) return res.status(400).json({ message: 'actorName is required' });

    const ext = path.extname(file.originalname).toLowerCase();
    let content = '';
    let fileType = '';

    if (ext === '.pdf') {
      fileType = 'pdf';
      content = await parsePDF(file.path);
    } else if (['.csv', '.xlsx', '.xls'].includes(ext)) {
      fileType = ext.replace('.', '');
      content = parseSpreadsheet(file.path);
    } else {
      fs.unlinkSync(file.path);
      return res.status(400).json({ message: 'Unsupported file type. Use PDF, CSV, or XLSX.' });
    }

    const result = await dbModel.addTrustedFile(
      actorName.toLowerCase(),
      file.originalname,
      fileType,
      content,
      file.path
    );

    res.json({ id: result.id, file_name: file.originalname });
  } catch (error) {
    if (req.file?.path) {
      try { fs.unlinkSync(req.file.path); } catch {}
    }
    next(error);
  }
};

export const removeFile = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = parseInt(req.params.id as string);
    if (isNaN(id)) return res.status(400).json({ message: 'Invalid ID' });
    await dbModel.removeTrustedFile(id);
    res.json({ message: 'File removed' });
  } catch (error) {
    next(error);
  }
};
