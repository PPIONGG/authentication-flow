import { BrowserRouter, Routes, Route } from "react-router";
import { HelloPage } from "../App";

export function AppRouter() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HelloPage />} />
        {/* Public routes (later plans): /login /register /verify-email
            /forgot-password /reset-password */}
        {/* Protected routes (later plans): / (dashboard) /account */}
        {/* ADMIN-only (later plans): /admin */}
      </Routes>
    </BrowserRouter>
  );
}
