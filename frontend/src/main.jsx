import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import "@fontsource-variable/archivo/wdth.css";
import "@fontsource-variable/inter-tight";
import "@fontsource-variable/jetbrains-mono";
import "./styles.css";
import App from "./App.jsx";
import { LiveProvider } from "./lib/live.jsx";

createRoot(document.getElementById("root")).render(
  <BrowserRouter>
    <LiveProvider>
      <App />
    </LiveProvider>
  </BrowserRouter>
);
