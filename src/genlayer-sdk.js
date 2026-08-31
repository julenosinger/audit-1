// ═══════════════════════════════════════════════════════════════════════════════
// GenLayer SDK entry (bundled by esbuild → public/genlayer-sdk.bundle.js)
//
// This is the ONLY place the official genlayer-js SDK is imported. esbuild
// bundles it (with viem) into a browser IIFE that exposes `window.GenLayerSDK`.
// No private key, no secret, no external AI — just the official SDK + chains.
//
// Build:  npm run build
// ═══════════════════════════════════════════════════════════════════════════════
import { createClient } from "genlayer-js";
import * as chains from "genlayer-js/chains";

globalThis.GenLayerSDK = {
  createClient: createClient,
  chains: chains
};
