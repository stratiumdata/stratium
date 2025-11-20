import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import AuthCallback from "./components/AuthCallback";
import {ProtectedRoute} from "./components/ProtectedRoute";
import NotFound from "./pages/NotFound";
import {AuthProvider} from "@/contexts/AuthContext.tsx";
import {Unauthorized} from "@/pages/Unauthorized.tsx";
import {Layout} from "@/components/Layout.tsx";
import {DatasetsList} from "@/pages/DatasetsList.tsx";
import {DatasetForm} from "@/pages/DatasetForm.tsx";
import {DatasetDetail} from "@/pages/DatasetDetail.tsx";
import {UsersList} from "@/pages/UsersList.tsx";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
      <AuthProvider>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
            <Route path="/" element={<Login />} />
            <Route path="/login" element={<Login />} />
          <Route path="/auth/callback" element={<AuthCallback />} />
          <Route path="/unauthorized" element={<Unauthorized />} />
            <Route
                path="/datasets"
                element={
                    <ProtectedRoute>
                        <Layout>
                            <DatasetsList />
                        </Layout>
                    </ProtectedRoute>
                }
            />
            <Route
                path="/datasets/new"
                element={
                    <ProtectedRoute requiredRole="editor">
                        <Layout>
                            <DatasetForm />
                        </Layout>
                    </ProtectedRoute>
                }
            />
            <Route
                path="/datasets/:id"
                element={
                    <ProtectedRoute>
                        <Layout>
                            <DatasetDetail />
                        </Layout>
                    </ProtectedRoute>
                }
            />
            <Route
                path="/datasets/:id/edit"
                element={
                    <ProtectedRoute requiredRole="editor">
                        <Layout>
                            <DatasetForm />
                        </Layout>
                    </ProtectedRoute>
                }
            />
            <Route
                path="/users"
                element={
                    <ProtectedRoute requiredRole="admin">
                        <Layout>
                            <UsersList />
                        </Layout>
                    </ProtectedRoute>
                }
            />
          {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
      </AuthProvider>
  </QueryClientProvider>
);

export default App;
