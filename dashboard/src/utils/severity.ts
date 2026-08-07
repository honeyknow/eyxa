/** Shared severity utilities - single source of truth for all components. */

export function sevClass(score: number): string {
  if (score >= 9) return 'crit'
  if (score >= 7) return 'high'
  if (score >= 5) return 'med'
  return 'low'
}

export function sevLabel(score: number): string {
  if (score >= 9) return 'Critical'
  if (score >= 7) return 'High'
  if (score >= 5) return 'Medium'
  return 'Low'
}
