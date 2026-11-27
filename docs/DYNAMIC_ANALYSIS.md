# Android runtime analysis

The **Runtime analysis / التحليل أثناء التشغيل** tab records observations from a real Android process using Frida. It does not turn static candidates into runtime results. Full values are retained in the local archive and exports.

## Windows lab setup

No Docker is required. Install Android SDK Platform Tools, the emulator, and a **Google APIs x86_64 API 36** system image. Use a dedicated AVD named `SCA_Dynamic_API36`. A Play Store production image does not support `adb root`. ARM64-only applications need the image's native translation support; an emulator can still behave differently from a physical ARM64 device.

From the project directory:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dynamic.txt
& "$env:LOCALAPPDATA\Android\Sdk\cmdline-tools\latest\bin\avdmanager.bat" create avd --name SCA_Dynamic_API36 --package 'system-images;android-36;google_apis;x86_64' --device pixel_7
.\tools\start_dynamic_lab.ps1
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

Create the AVD only once. Set its data partition to at least 8 GB before first launch if installing the complete application corpus. The lab helper checks the AVD identity before enabling root or starting the pinned, checksum-verified Frida server. It forwards local port 37042 to port 27042 on `emulator-5590`. The server listens only on device loopback. The separate existing AVD on port 5582 is not part of this lab.

The compiled observer is included. To rebuild it after editing hooks:

```powershell
Push-Location sca\dynamic\agent
npm ci
Pop-Location
.\.venv\Scripts\python.exe -m sca.dynamic.build_agent
```

Frida's Java bridge is bundled explicitly because Frida 17 no longer includes it automatically. Versions are pinned in `requirements-dynamic.txt` and the agent's npm lockfile.

## Using the platform

1. Scan an APK, an export folder containing its base APK and compatible splits, or an APK-set archive. Open a saved scan from **History** to use its retained source preview.
2. Open **Runtime analysis**, select the dedicated Android lab device, and set the recording duration.
3. Start recording. Startup mode installs the selected package and compatible supplied splits, starts the app with instrumentation, and saves the session under that static scan. **Attach to a running app** skips installation and verifies its process identity before recording. Use this mode while navigating the app on your test device.
4. Select a recorded value to see its full contents, capture timestamp, hook API, process/thread, stack, and original JSONL event. Repeated occurrences can be inspected independently.
5. An exact literal match opens the retained decoded source line. A runtime-generated value can have no literal source location; the event and stack remain available. A class/method association is context, not proof of the generating line.

Source code must be built into an APK before Android runtime analysis. A single selected `base.apk` does not implicitly install sibling splits. An archive with mutually exclusive bundletool variants may need device-specific APK selection first; installation errors are displayed rather than converted into a successful scan.

Local sessions are compressed JSON in `dynamic_sessions` in `data/sca.db`, linked to the static scan. Raw runtime evidence is kept separate from static findings and AI prompts. The web-hosted mode can import and inspect capture JSON from a lab; it does not claim to have a connected emulator when none exists. Imported captures are marked as externally supplied evidence.

For an interactive emulator window, start a stopped lab with `tools/start_dynamic_lab.ps1 -ShowWindow`. An already-running headless instance keeps its existing window mode. A connected physical test device can also be selected when its compatible Frida server is configured. The **Reconnect lab observer** button restarts only the named dedicated lab observer; it does not reset app data or control unrelated devices.

The native DNS/TLS checkbox is enabled by default. Disabling it requests an explicitly labeled Java-only observation session for compatibility comparisons. This does not remove Frida Java bridge internals, and a successful retry alone does not establish the cause of an earlier crash. The retained AynIQ compatibility session ran for 30 seconds and captured 38 events/13 derived values; its native coverage is explicitly disabled. PhonePay also crashed in the uninstrumented emulator baseline. See the audit's per-session diagnostics rather than treating every installed app as fully covered.

## What is observed

- Java URL construction/opening, standard URLConnection credential headers, WebView navigation and supported OkHttp calls.
- Java cryptographic key construction/generation, relevant decoded Base64 and cipher output.
- Native DNS/socket destinations and exported TLS SNI/read/write hooks when available.
- Recognizable URLs and credential formats in those observed values, using the scanner's existing detectors.

An API call constructing a URL is not proof of a successful request. Key material in process memory is not automatically a vulnerability, unrestricted API credential, or proof of exploitability. `KeyGenerator.generateKey` is evidence of generation; `SecretKeySpec` construction merely proves that the bytes were used to construct a key object. A value absent from the retained static inventory is not necessarily generated at runtime.

## Explicit coverage limits

Only executed code in the selected process is observed. Startup captures do not exercise login, payment, or every screen. No credentials or account actions are automated. Integrity checks and TLS validation retain their application behavior. A refusal to run, process crash, unavailable hook or recording limit is displayed as evidence/coverage metadata.

Flutter/native code may expose only hosts and socket destinations when TLS implementations are stripped or inlined. QUIC, complete HTTP/2 header decoding, separate child/WebView renderer processes, hardware-keystore non-exportable keys and unexecuted paths are not guaranteed to be captured. Runtime stacks can contain debug line numbers that differ from JADX output; the UI does not relabel them as exact decompiled source lines.

Recording has explicit event, value, journal and archive size budgets. Oversized values are reported as omitted; they are not silently shortened and presented as complete. Archive loading is bounded and validates the event references. The UI's exact-source links independently verify the value against the selected scan's source snapshot.

## Reproducing the supplied-app audit

```powershell
.\.venv\Scripts\python.exe tools\audit_dynamic_apps.py --serial emulator-5590 --adb "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" --frida-host 127.0.0.1:37042 --duration 30 --install --save
.\.venv\Scripts\python.exe tools\render_dynamic_audit.py data\audits\2026-11-27-dynamic
```

The audit records current APK hashes, installed device properties, actual session evidence, per-app failures and comparison with the prior static inventory. All results refer to the stated startup recording window, not exhaustive application behavior.

References: [Frida Android guide](https://frida.re/docs/android/), [Frida bridges](https://frida.re/docs/bridges/), [Android emulator command line](https://developer.android.com/studio/run/emulator-commandline).
