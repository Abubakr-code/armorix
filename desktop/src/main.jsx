import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/outfit";
import "@fontsource-variable/bricolage-grotesque";
import "@fontsource-variable/jetbrains-mono";

import App from "./App";
import "./styles.css";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>
);
