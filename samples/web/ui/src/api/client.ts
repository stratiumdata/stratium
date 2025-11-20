import axios from 'axios';
import type { AxiosInstance, AxiosError } from 'axios';
import keycloak from '@/config/keycloak';
import type {
  User,
  Dataset,
  CreateDatasetRequest,
  UpdateDatasetRequest,
  PaginatedResponse,
  DatasetsResponse,
  ApiError
} from '@/types';

class ApiClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: import.meta.env.VITE_API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Add auth token to requests
    this.client.interceptors.request.use(
      (config) => {
        if (keycloak.token) {
          config.headers.Authorization = `Bearer ${keycloak.token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Handle 401 errors
    this.client.interceptors.response.use(
      (response) => response,
      async (error: AxiosError<ApiError>) => {
        if (error.response?.status === 401) {
          try {
            await keycloak.updateToken(5);
            // Retry the request with new token
            if (error.config) {
              error.config.headers.Authorization = `Bearer ${keycloak.token}`;
              return this.client.request(error.config);
            }
          } catch {
            keycloak.login();
          }
        }
        return Promise.reject(error);
      }
    );
  }

  // Health check
  async healthCheck(): Promise<{ status: string }> {
    const response = await this.client.get('/health');
    return response.data;
  }

  // User endpoints
  async getCurrentUser(): Promise<User> {
    const response = await this.client.get('/api/v1/users/me');
    return response.data;
  }

  async getUsers(): Promise<User[]> {
    const response = await this.client.get<{ users: User[]; total: number }>('/api/v1/users');
    return response.data.users;
  }

  async getUser(id: string): Promise<User> {
    const response = await this.client.get(`/api/v1/users/${id}`);
    return response.data;
  }

  async createUser(user: Partial<User>): Promise<User> {
    const response = await this.client.post('/api/v1/users', user);
    return response.data;
  }

  async updateUser(id: string, user: Partial<User>): Promise<User> {
    const response = await this.client.put(`/api/v1/users/${id}`, user);
    return response.data;
  }

  async deleteUser(id: string): Promise<void> {
    await this.client.delete(`/api/v1/users/${id}`);
  }

  // Dataset endpoints
  async getDatasets(params?: {
    limit?: number;
    offset?: number;
  }): Promise<PaginatedResponse<Dataset>> {
    const response = await this.client.get<DatasetsResponse>('/api/v1/datasets', { params });
    // Transform backend response to match frontend expectations
    return {
      data: response.data.datasets,
      total: response.data.total,
      limit: response.data.limit,
      offset: response.data.offset,
    };
  }

  async searchDatasets(params: {
    q?: string;
    department?: string;
    tags?: string;
    limit?: number;
    offset?: number;
  }): Promise<PaginatedResponse<Dataset>> {
    const response = await this.client.get<DatasetsResponse>('/api/v1/datasets/search', { params });
    // Transform backend response to match frontend expectations
    return {
      data: response.data.datasets,
      total: response.data.total,
      limit: response.data.limit,
      offset: response.data.offset,
    };
  }

  async getDataset(id: string): Promise<Dataset> {
    const response = await this.client.get(`/api/v1/datasets/${id}`);
    return response.data;
  }

  async createDataset(dataset: CreateDatasetRequest): Promise<Dataset> {
    const response = await this.client.post('/api/v1/datasets', dataset);
    return response.data;
  }

  async updateDataset(id: string, dataset: UpdateDatasetRequest): Promise<Dataset> {
    const response = await this.client.put(`/api/v1/datasets/${id}`, dataset);
    return response.data;
  }

  async deleteDataset(id: string): Promise<void> {
    await this.client.delete(`/api/v1/datasets/${id}`);
  }
}

export const apiClient = new ApiClient();