import { loadSettings, saveSettings } from "../settings";

function parseAllowlist(input: string): string[] {
  const raw = input
    .split(/\r?\n|,|\s+/)
    .map((entry) => entry.trim())
    .filter(Boolean);

  const out: string[] = [];
  for (const entry of raw) {
    try {
      if (entry.includes("://")) {
        out.push(new URL(entry).hostname.toLowerCase());
      } else {
        out.push(entry.toLowerCase());
      }
    } catch {
      out.push(entry.toLowerCase());
    }
  }

  return Array.from(new Set(out));
}

async function main() {
  const allowlistEnabled = document.getElementById(
    "allowlistEnabled"
  ) as HTMLInputElement;
  const allowlist = document.getElementById("allowlist") as HTMLTextAreaElement;
  const saveBtn = document.getElementById("save") as HTMLButtonElement;
  const status = document.getElementById("status") as HTMLSpanElement;

  const settings = await loadSettings();
  allowlistEnabled.checked = settings.allowlistEnabled;
  allowlist.value = settings.allowlist.join("\n");

  saveBtn.onclick = async () => {
    const next = {
      allowlistEnabled: allowlistEnabled.checked,
      allowlist: parseAllowlist(allowlist.value)
    };
    await saveSettings(next);
    status.textContent = "Saved";
    setTimeout(() => (status.textContent = ""), 1500);
  };
}

main().catch(console.error);
