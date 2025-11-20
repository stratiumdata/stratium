// User types
export interface User {
  id: string;
  name: string;
  email: string;
  department: string;
  title: string;
  role: 'admin' | 'editor' | 'viewer';
  created_at: string;
  updated_at: string;
}

// Dataset types
export interface Dataset {
  id: string;
  title: string;
  description: string;
  owner_id: string;
  owner?: User;
  data_url: string;
  department: string;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface CreateDatasetRequest {
  title: string;
  description: string;
  data_url: string;
  department: string;
  tags: string[];
}

export interface UpdateDatasetRequest {
  title?: string;
  description?: string;
  data_url?: string;
  department?: string;
  tags?: string[];
}

// API Response types
export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

// Backend returns 'datasets' field instead of 'data' for dataset endpoints
export interface DatasetsResponse {
  datasets: Dataset[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface ApiError {
  error: string;
  details?: string;
}

// Auth types
export interface AuthUser {
  id: string;
  email: string;
  name: string;
  department: string;
  role: 'admin' | 'editor' | 'viewer';
}

// Permissions based on ABAC
export interface Permissions {
  canView: boolean;
  canEdit: boolean;
  canDelete: boolean;
  canCreate: boolean;
}
