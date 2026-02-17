import { Request, Response, NextFunction } from 'express';
import * as dbModel from '../models/db.js';
import * as geminiService from '../services/geminiService.js';

export const getAllActors = async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const actors = await dbModel.getAllActors();
    res.json(actors);
  } catch (error) {
    next(error);
  }
};

export const getActor = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = req.params.id as string;
    const actor = await dbModel.getActorById(id);
    if (!actor) return res.status(404).json({ message: 'Actor not found' });
    res.json(actor);
  } catch (error) {
    next(error);
  }
};

export const generateActor = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ message: 'Actor name is required' });

    const trustedUrls = await dbModel.getTrustedUrlStrings(name);
    const trustedFiles = await dbModel.getTrustedFileContents(name);

    const { profile, log } = await geminiService.generateActorProfile(name, trustedUrls, trustedFiles);

    // Check if actor already exists by name — update instead of creating duplicate
    const existing = await dbModel.getActorByName(name);

    const actor = {
      id: existing ? existing.id : Date.now().toString(),
      ...profile,
      lastUpdated: new Date().toISOString()
    };

    if (existing) {
      await dbModel.updateActor(existing.id, actor);
    } else {
      await dbModel.createActor(actor);
    }

    res.json({ actor, generationLog: log });
  } catch (error) {
    next(error);
  }
};

export const refreshSection = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, section } = req.body;
    if (!name || !section) return res.status(400).json({ message: 'Name and section are required' });

    const validSections = ['ALIASES', 'DESCRIPTION', 'CVES'];
    if (!validSections.includes(section)) {
      return res.status(400).json({ message: 'Invalid section. Must be ALIASES, DESCRIPTION, or CVES' });
    }

    const partialData = await geminiService.refreshActorSection(name, section);

    const actorId = req.params.id as string;
    if (actorId) {
      const existing = await dbModel.getActorById(actorId);
      if (existing) {
        const updated = { ...existing, ...partialData, lastUpdated: new Date().toISOString() };
        await dbModel.updateActor(actorId, updated);
      }
    }

    res.json(partialData);
  } catch (error) {
    next(error);
  }
};

export const updateActorHandler = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = req.params.id as string;
    const actor = req.body;
    if (!actor) return res.status(400).json({ message: 'Actor data is required' });

    const existing = await dbModel.getActorById(id);
    if (!existing) return res.status(404).json({ message: 'Actor not found' });

    const updated = await dbModel.updateActor(id, actor);
    res.json(updated);
  } catch (error) {
    next(error);
  }
};

export const deleteActorHandler = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = req.params.id as string;
    await dbModel.deleteActor(id);
    res.json({ message: 'Actor deleted' });
  } catch (error) {
    next(error);
  }
};
