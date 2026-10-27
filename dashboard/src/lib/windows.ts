// Shared by server pages and the client-side window picker.
export const WINDOWS = [
  { hours: 24, label: "24 hours" },
  { hours: 168, label: "7 days" },
  { hours: 720, label: "30 days" },
] as const;

export function parseWindow(value: string | string[] | undefined): number {
  const hours = Number(Array.isArray(value) ? value[0] : value);
  return WINDOWS.some((w) => w.hours === hours) ? hours : 168;
}
