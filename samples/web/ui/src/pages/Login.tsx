import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { KeyRound } from "lucide-react";
import {useAuth} from "@/contexts/AuthContext.tsx";
import {Navigate} from "react-router-dom";

const Login = () => {
    const { isAuthenticated, login } = useAuth();

    if (isAuthenticated) {
        return <Navigate to="/datasets" replace />;
    }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-background via-background to-secondary p-4">
      <Card className="w-full max-w-md shadow-elegant border-border/50">
        <CardHeader className="space-y-3 text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-primary to-accent">
            <KeyRound className="h-8 w-8 text-primary-foreground" />
          </div>
          <CardTitle className="text-3xl font-bold">Welcome Back</CardTitle>
          <CardDescription className="text-base">
            Sign in with your Keycloak credentials
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Button 
            onClick={login}
            className="w-full bg-gradient-to-r from-primary to-accent hover:opacity-90 transition-all shadow-md hover:shadow-lg"
            size="lg"
          >
            Sign in with Keycloak
          </Button>
        </CardContent>
      </Card>
    </div>
  );
};

export default Login;
