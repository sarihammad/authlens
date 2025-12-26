export type Settings = {
  allowlistEnabled: boolean;
  allowlist: string[];
};

const SETTINGS_KEY = "settings:v1";

export function defaultSettings(): Settings {
  return { allowlistEnabled: false, allowlist: [] };
}

export async function loadSettings(): Promise<Settings> {
  const res = await chrome.storage.sync.get(SETTINGS_KEY);
  return (res[SETTINGS_KEY] as Settings) ?? defaultSettings();
}

export async function saveSettings(settings: Settings): Promise<void> {
  await chrome.storage.sync.set({ [SETTINGS_KEY]: settings });
}
