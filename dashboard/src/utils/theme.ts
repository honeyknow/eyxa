import React from 'react'
import { Terminal, Network, HardDrive, FileText, Globe, Cpu, AlertTriangle, Shield, Activity } from 'lucide-react'

const CORE_COLORS: Record<string, string> = {
  process: '#F97316', // Orange
  network: '#3B82F6', // Blue
  file: '#EAB308',    // Yellow
  registry: '#14B8A6',// Teal
  amsi: '#EC4899',    // Pink
  alert: '#EF4444',   // Red
  auth: '#06B6D4',    // Cyan
  system: '#A855F7',  // Purple
  dns: '#8B5CF6',     // Violet
  tampering: '#EF4444'// Red
}

// A vibrant, premium color palette for dynamically assigning to unknown event types
const DYNAMIC_PALETTE = [
  '#F43F5E', // Rose
  '#D946EF', // Fuchsia
  '#8B5CF6', // Violet
  '#6366F1', // Indigo
  '#0EA5E9', // Sky Blue
  '#10B981', // Emerald
  '#84CC16', // Lime
  '#F59E0B', // Amber
  '#2DD4BF', // Teal
  '#F472B6', // Pink Light
  '#38BDF8', // Light Blue
  '#4ADE80', // Green Light
  '#FACC15', // Yellow
  '#FB923C', // Orange Light
  '#F87171', // Red Light
  '#C084FC', // Purple Light
  '#9333EA', // Purple Dark
  '#0284C7', // Sky Blue Dark
  '#059669', // Emerald Dark
  '#EA580C', // Orange Dark
]

const dynamicRegistry = new Map<string, string>()
let paletteIndex = 0

/**
 * Returns a consistent color for any given telemetry type.
 * If the type is unknown, it assigns it a dynamic color from the premium palette and caches it.
 */
export function getCategoryColor(type: string): string {
  const t = type.toLowerCase()
  if (CORE_COLORS[t]) return CORE_COLORS[t]
  
  if (dynamicRegistry.has(t)) {
    return dynamicRegistry.get(t)!
  }

  // Assign a new color
  const color = DYNAMIC_PALETTE[paletteIndex % DYNAMIC_PALETTE.length]
  paletteIndex++
  dynamicRegistry.set(t, color)
  return color
}

/**
 * Returns a specific Lucide React icon for core categories, 
 * or a sleek generic Activity icon for unknown telemetry types.
 */
export function getCategoryIcon(type: string, size = 14, color?: string): React.ReactNode {
  const c = color || getCategoryColor(type)
  const t = type.toLowerCase()
  
  const props = { size, color: c }
  
  switch (t) {
    case 'process': return React.createElement(Terminal, props)
    case 'network': return React.createElement(Network, props)
    case 'file': return React.createElement(FileText, props)
    case 'registry': return React.createElement(HardDrive, props)
    case 'alert': return React.createElement(AlertTriangle, props)
    case 'amsi': return React.createElement(Shield, props)
    case 'dns': return React.createElement(Globe, props)
    case 'root': return React.createElement(Cpu, props)
    default: return React.createElement(Activity, props) // The sleek generic fallback
  }
}
