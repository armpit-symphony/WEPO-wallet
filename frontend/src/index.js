// Polyfills for crypto libraries - must be imported first
import { Buffer } from 'buffer';
import process from 'process';

// Make polyfills available globally
window.Buffer = Buffer;
window.process = process;
window.global = window;

import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";
import App from "./App";

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
