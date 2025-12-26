import { loadSettings, saveSettings } from "../settings";
import { normalizeAllowlistInput } from "../allowlist";

const PRESETS: Record<string, string[]> = {
  google: [
    "accounts.google.com",
    "oauth2.googleapis.com",
    "googleapis.com"
  ],
  okta: ["okta.com", "oktapreview.com", "okta-emea.com"],
  auth0: ["auth0.com"]
};

async function main() {
  const allowlistEnabled = document.getElementById(
    "allowlistEnabled"
  ) as HTMLInputElement;
  const allowlist = document.getElementById("allowlist") as HTMLTextAreaElement;
  const preset = document.getElementById("preset") as HTMLSelectElement;
  const addPreset = document.getElementById("addPreset") as HTMLButtonElement;
  const saveBtn = document.getElementById("save") as HTMLButtonElement;
  const status = document.getElementById("status") as HTMLSpanElement;

  const settings = await loadSettings();
  allowlistEnabled.checked = settings.allowlistEnabled;
  allowlist.value = settings.allowlist.join("\n");

  addPreset.onclick = () => {
    const selected = preset.value;
    if (!selected || !PRESETS[selected]) return;
    const current = normalizeAllowlistInput(allowlist.value);
    const next = Array.from(new Set([...current, ...PRESETS[selected]]));
    allowlist.value = next.join("\n");
  };

  saveBtn.onclick = async () => {
    if (allowlistEnabled.checked && normalizeAllowlistInput(allowlist.value).length === 0) {
      status.textContent = "Add at least one domain.";
      return;
    }
    const next = {
      allowlistEnabled: allowlistEnabled.checked,
      allowlist: normalizeAllowlistInput(allowlist.value),
      onboarded: true
    };
    await saveSettings(next);
    status.textContent = "Saved";
    setTimeout(() => (status.textContent = ""), 1500);
  };
}

main().catch(console.error);
