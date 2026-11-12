import { Navigate, Route, Routes } from "react-router-dom";
import Home from "./pages/Home.jsx";
import Monitor from "./pages/Monitor.jsx";
import Analyze from "./pages/Analyze.jsx";
import Performance from "./pages/Performance.jsx";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/monitor" element={<Monitor />} />
      <Route path="/analyze" element={<Analyze />} />
      <Route path="/performance" element={<Performance />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
