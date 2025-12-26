export type Settings = {
  allowlistEnabled: boolean;
  allowlist: string[];
  onboarded: boolean;
};

const SETTINGS_KEY = "settings:v1";

export function defaultSettings(): Settings {
  return { allowlistEnabled: true, allowlist: [], onboarded: false };
}

export async function loadSettings(): Promise<Settings> {
  const res = await chrome.storage.sync.get(SETTINGS_KEY);
  const stored = res[SETTINGS_KEY] as Partial<Settings> | undefined;
  return {
    ...defaultSettings(),
    ...(stored ?? {})
  };
}

export async function saveSettings(settings: Settings): Promise<void> {
  await chrome.storage.sync.set({ [SETTINGS_KEY]: settings });
}
