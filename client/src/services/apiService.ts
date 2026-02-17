import { ThreatActor, NewsItem, GenerationLog } from '../types';

const API_BASE = '/api';

async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Request failed' }));
    throw new Error(error.message || `HTTP ${response.status}`);
  }

  return response.json();
}

// --- Threat Actor APIs ---

export const getAllActors = async (): Promise<ThreatActor[]> => {
  return apiRequest<ThreatActor[]>('/actors');
};

export const getActor = async (id: string): Promise<ThreatActor> => {
  return apiRequest<ThreatActor>(`/actors/${id}`);
};

export interface GenerateProfileResponse {
  actor: ThreatActor;
  generationLog: GenerationLog;
}

export const generateActorProfile = async (actorName: string): Promise<GenerateProfileResponse> => {
  return apiRequest<GenerateProfileResponse>('/actors/generate', {
    method: 'POST',
    body: JSON.stringify({ name: actorName }),
  });
};

export const refreshActorSection = async (
  actorId: string,
  actorName: string,
  section: 'ALIASES' | 'DESCRIPTION' | 'CVES'
): Promise<Partial<ThreatActor>> => {
  return apiRequest<Partial<ThreatActor>>(`/actors/${actorId}/refresh-section`, {
    method: 'POST',
    body: JSON.stringify({ name: actorName, section }),
  });
};

export const updateActor = async (id: string, actor: ThreatActor): Promise<ThreatActor> => {
  return apiRequest<ThreatActor>(`/actors/${id}`, {
    method: 'PUT',
    body: JSON.stringify(actor),
  });
};

export const deleteActor = async (id: string): Promise<void> => {
  await apiRequest(`/actors/${id}`, { method: 'DELETE' });
};

// --- Chat API ---

export const chatWithAI = async (message: string, context?: string): Promise<string> => {
  const data = await apiRequest<{ response: string }>('/chat', {
    method: 'POST',
    body: JSON.stringify({ message, context }),
  });
  return data.response;
};

// --- News API ---

export const getLiveCyberNews = async (): Promise<NewsItem[]> => {
  return apiRequest<NewsItem[]>('/news');
};

// --- Trusted Sources APIs ---

export const getTrustedActorNames = async (): Promise<string[]> => {
  return apiRequest<string[]>('/sources');
};

export interface TrustedSourcesResponse {
  urls: { id: number; url: string; actor_name: string }[];
  files: { id: number; file_name: string; file_type: string; content_length: number; created_at: string }[];
}

export const getTrustedSources = async (actorName: string): Promise<TrustedSourcesResponse> => {
  return apiRequest<TrustedSourcesResponse>(`/sources/${encodeURIComponent(actorName)}`);
};

export const addTrustedUrl = async (actorName: string, url: string): Promise<{ id: number }> => {
  return apiRequest<{ id: number }>('/sources/urls', {
    method: 'POST',
    body: JSON.stringify({ actorName, url }),
  });
};

export const removeTrustedUrl = async (id: number): Promise<void> => {
  await apiRequest(`/sources/urls/${id}`, { method: 'DELETE' });
};

export const uploadTrustedFile = async (actorName: string, file: File): Promise<{ id: number; file_name: string }> => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('actorName', actorName);

  const response = await fetch(`${API_BASE}/sources/files`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Upload failed' }));
    throw new Error(error.message || `HTTP ${response.status}`);
  }

  return response.json();
};

export const removeTrustedFile = async (id: number): Promise<void> => {
  await apiRequest(`/sources/files/${id}`, { method: 'DELETE' });
};
