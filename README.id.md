# Priva-MCP — Lapisan Privasi & Kepatuhan

> 🇬🇧 English version: [README.md](README.md)

Proxy **MCP** *man-in-the-middle* yang berdiri di antara Claude (klien) dan
**internal API** Anda (resource). Ia mencegat output tool internal dan
**menyensor data sensitif secara otomatis** — nomor CIF, nomor rekening, PAN
kartu debit, saldo, email, nomor telepon, NIK — *sebelum* apa pun dikembalikan ke
Claude. Jika ada field yang tidak boleh keluar (password, PIN, CVV, secret),
**seluruh respons diblokir**. Setiap panggilan dicatat di jejak audit, dan
pelanggaran berat memicu log insiden terstruktur untuk SIEM enterprise (ELK /
Logstash).

```
Claude (Klien)  ⇄  Priva-MCP (proxy ini)  ⇄  Internal API
                     │
                     ├── compliance engine  → penyensoran dua lapis (key + regex)
                     ├── blokir zero-trust  → buang respons saat ada field terlarang
                     ├── audit logger       → audit.log (JSON Lines)
                     └── incident logger    → ECS JSON ke stderr (ELK / Logstash)
```

Prinsip desain: **zero-trust terhadap PII**. stdout khusus untuk aliran JSON-RPC
MCP dan tidak pernah membawa kebocoran data; semua diagnostik & insiden ke
stderr; nilai sensitif disensor di level field, bukan regex global membabi buta.

---

## Daftar isi

- [Fitur](#fitur)
- [Struktur proyek](#struktur-proyek)
- [Kebutuhan](#kebutuhan)
- [Instalasi](#instalasi)
- [Menjalankan lokal](#menjalankan-lokal)
- [Variabel environment](#variabel-environment)
- [Tools & data mock](#tools--data-mock)
- [Referensi penyensoran](#referensi-penyensoran)
- [Mode ketat & keamanan numerik](#mode-ketat--keamanan-numerik)
- [Blokir zero-trust & log insiden ELK](#blokir-zero-trust--log-insiden-elk)
- [Format audit log](#format-audit-log)
- [Uji cepat manual](#uji-cepat-manual)
- [Sambungkan ke Claude Desktop](#sambungkan-ke-claude-desktop)
- [Pengujian](#pengujian)
- [Cara kerja deteksi](#cara-kerja-deteksi)
- [Landing page (Vercel)](#landing-page-vercel)
- [Menuju produksi](#menuju-produksi)

---

## Fitur

- **MCP TypeScript SDK resmi** (`@modelcontextprotocol/sdk`) via stdio.
- **Dua tool mock** yang mensimulasikan penarikan data dari internal API:
  - `get_customer_profile` — profil pelanggan berdasarkan CIF.
  - `get_financial_report` — laporan/mutasi rekening berdasarkan CIF.
- **Interceptor penyensoran dua lapis** — setiap output tool melewati engine
  sebelum sampai ke Claude:
  - **Lapis 1 (berbasis key, lebih ketat):** nama key field menentukan masker
    (case-insensitive). Menghilangkan kelas *false-positive* di mana NIK 16
    digit tak sengaja lolos Luhn lalu disensor sebagai kartu kredit.
  - **Lapis 2 (cadangan, pindai teks dalam):** string mentah / teks bebas / key
    tak spesifik jatuh ke pipeline regex global terurut.
- **Masking level field** untuk `cifNumber`, `accountNumber`, `pan`,
  `phoneNumber`, `email`, plus generik `creditCard` / `bankAccount` / `nik`.
- **Keamanan numerik** — `balance` / `amount` mempertahankan tipe **number**
  JSON (tidak diubah jadi `"X"`), sehingga AI tetap bisa berhitung. Pada mode
  ketat nilainya di-nol-kan.
- **Blokir zero-trust** — field terlarang (`password`, `pin`, `cvv`, `secret`,
  …) membuat seluruh respons diblokir; hanya error aman yang sampai ke Claude.
- **Audit logging** ke `audit.log` (JSON Lines): `timestamp`, `tool_called`,
  `user_id_mock`, `status_compliance` (`CLEAN` / `REDACTED` / `BLOCKED`), plus
  rincian per kategori yang mencatat **metode** deteksi (`KEY_MATCH` /
  `REGEX_MATCH`).
- **Log insiden siap SIEM** — pelanggaran berat & error pipeline memunculkan satu
  baris JSON gaya ECS ke **stderr** untuk ELK / Logstash.
- **TypeScript ketat** — mode `strict`, tanpa `any`, tanpa akses indeks tak
  tercek.
- **Teruji unit** — 28 tes lewat runner bawaan `node:test`.

---

## Struktur proyek

```
priva-mcp/
├── src/
│   ├── server.ts            # Entry point MCP: pipeline, mode ketat, log insiden
│   ├── compliance/          # Engine penyensoran dua lapis
│   │   ├── types.ts
│   │   ├── masking.ts       # masker murni (kartu, NIK, CIF, email, telepon, …)
│   │   ├── patterns.ts      # KEY_RULES (Lapis 1) + regex (Lapis 2) + key terlarang
│   │   ├── redactor.ts      # ComplianceEngine (redactObject rekursif)
│   │   └── index.ts
│   ├── gateway/             # Logika proxy + data mock internal API
│   │   ├── mockData.ts
│   │   ├── gateway.ts
│   │   └── index.ts
│   └── logs/                # Jejak audit
│       ├── auditLogger.ts
│       └── index.ts
├── test/                    # suite node:test
├── web/                     # Landing page statis (EN + ID)
├── audit.log                # dibuat saat runtime (di-gitignore)
├── package.json
├── tsconfig.json
└── README.md
```

---

## Kebutuhan

- Node.js >= 18.18 (dikembangkan di Node 22)
- npm

---

## Instalasi

```bash
npm install
```

---

## Menjalankan lokal

### Development (auto-reload, jalankan TS langsung)

```bash
npm run dev
```

### Produksi (compile, lalu jalankan JS)

```bash
npm run build
npm start
```

Server berbicara MCP via **stdio**, jadi saat start ia menunggu klien di
stdin/stdout. Satu-satunya yang tercetak ke terminal (stderr) adalah baris
kesiapan:

```
[priva-mcp] v1.0.0 ready on stdio. strict=true audit=C:\...\priva-mcp\audit.log
```

> Cek tipe saja (tanpa emit): `npm run typecheck`.

---

## Variabel environment

| Variabel | Default | Efek |
|---|---|---|
| `COMPLIANCE_STRICT` | `true` | Bila `true`, angka `balance` / `amount` **di-nol-kan**. Set `false` agar nominal lewat apa adanya (mis. saat AI harus berhitung dengan angka asli). |
| `AUDIT_LOG_PATH` | `<cwd>/audit.log` | Path absolut atau relatif untuk jejak audit. |

> Default = **ketat** (`COMPLIANCE_STRICT=true`) — zero-trust.

---

## Tools & data mock

Kedua tool menerima **nomor CIF** (`cifNumber`) dan opsional `requestedBy`
(dicatat di audit sebagai `user_id_mock`).

| Tool | Argumen | Mengembalikan |
|---|---|---|
| `get_customer_profile` | `cifNumber`, `requestedBy?` | profil pelanggan |
| `get_financial_report` | `cifNumber`, `requestedBy?` | laporan/mutasi rekening |

CIF mock valid: **`CIF-7782001`**, **`CIF-7782002`**.

Bentuk profil mentah (sebelum penyensoran) dari gateway:

```jsonc
{
  "cifNumber": "CIF-7782001",
  "customerName": "Andi Wijaya",
  "accountNumber": "0012345678901",
  "pan": "4111111111111111",
  "phoneNumber": "+6281234567890",
  "email": "andi.wijaya@example.com",
  "balance": 15750000,
  "currency": "IDR",
  "branch": "Cabang A"
}
```

Yang benar-benar diterima Claude (mode ketat):

```jsonc
{
  "cifNumber": "REDACTED-CIF",
  "customerName": "Andi Wijaya",
  "accountNumber": "XXXXXXXXX8901",
  "pan": "XXXX-XXXX-XXXX-1111",
  "phoneNumber": "+XXXXXXXXXX890",
  "email": "a***a@e***.com",
  "balance": 0,
  "currency": "IDR",
  "branch": "Cabang A"
}
```

---

## Referensi penyensoran

### Lapis 1 — berbasis key (level field)

Nama key dinormalisasi (huruf kecil, non-alfanumerik dibuang) lalu dicocokkan
sebagai substring. Aturan dievaluasi **berurutan**; yang pertama cocok menang.

| Key mengandung | Kategori | Masker | Contoh |
|---|---|---|---|
| `email` | `email` | sebagian | `andi@example.com` → `a***i@e***.com` |
| `nik`, `id_card`, `identity`, `ktp` | `national_id` | simpan 4 akhir | `3173012501900002` → `XXXXXXXXXXXX0002` |
| `cif` | `cif` | penuh | `CIF-7782001` → `REDACTED-CIF` |
| `pan`, `card`, `credit` | `credit_card` | Luhn → grup | `4111111111111111` → `XXXX-XXXX-XXXX-1111` |
| `phone`, `telp`, `mobile`, `msisdn` | `phone` | simpan 3 akhir | `+6281234567890` → `+XXXXXXXXXX890` |
| `bankaccount`, `rekening`, `norekening`, `iban`, `accountnumber`, `virtualaccount` | `bank_account` | simpan 4 akhir | `0012345678901` → `XXXXXXXXX8901` |
| `balance`, `amount` | `financial_amount` | numerik (lihat bawah) | `15750000` → `0` (ketat) |

Urutan penting: `national_id` dicek **sebelum** `credit_card`, jadi key seperti
`id_card` (yang mengandung token `card`) digolongkan sebagai NIK, bukan kartu.
`cif` dicek sebelum rekening/kartu agar `cifNumber` tidak salah tangani.

Token sengaja spesifik agar tidak tabrakan:
- token `bankaccount` (bukan `account` polos) → `accountHolder` (sebuah nama)
  tidak pernah disensor sebagai nomor rekening;
- tidak ada token `id` polos → `customerId` tidak pernah dianggap NIK.

### Lapis 2 — cadangan regex global

Diterapkan ke string mentah, teks bebas, dan field yang key-nya tak spesifik.
Aturan berjalan berurutan; begitu sebuah nilai disensor, digit-nya jadi `X` dan
tak bisa dicocokkan ulang oleh aturan yang lebih lebar.

| Urutan | Kategori | Catatan |
|---|---|---|
| 1 | `email` | tak ambigu (`@`) |
| 2 | `phone` | format ponsel Indonesia |
| 3 | `credit_card` | 13–19 digit, **divalidasi Luhn** |
| 4 | `national_id` | tepat 16 digit berurutan |
| 5 | `bank_account` | 10–15 digit berurutan |

---

## Mode ketat & keamanan numerik

Field `balance` / `amount` memuat angka yang mungkin dipakai AI untuk berhitung,
jadi **tidak pernah** diubah jadi string `"X"` (itu merusak tipe number JSON).
Perilaku bergantung `COMPLIANCE_STRICT`:

| Mode | `balance: 15750000` menjadi | Kasus pakai |
|---|---|---|
| **ketat** (default) | `0` (tetap number) | Zero-trust: angka dilindungi tapi JSON tetap valid. |
| **longgar** (`COMPLIANCE_STRICT=false`) | `15750000` (apa adanya) | AI harus hitung angka asli. |

> Mode ketat juga me-nol-kan `amount` pada mutasi. Itu kebijakan yang diinginkan;
> ubah env var per-deployment bila butuh angka asli.

---

## Blokir zero-trust & log insiden ELK

Sebagian key **tidak boleh** melewati proxy. Dideteksi via pencocokan token kata
utuh (camelCase & pemisah dipecah), jadi `pin` menandai `pinCode` / `mPin` tapi
**tidak** menandai key polos seperti `shippingAddress`.

Token kata terlarang: `password`, `passwd`, `pwd`, `passphrase`, `pin`, `mpin`,
`otp`, `cvv`, `cvc`, `secret`, `privatekey`, `credential`, `credentials`.

Saat field terlarang ada, server:

1. **Memblokir seluruh respons** — tidak masking-lalu-teruskan.
2. Mengembalikan error generik tanpa info ke Claude (tanpa PII, tanpa nilai):
   ```
   Error: response blocked by privacy & compliance policy (a forbidden
   sensitive field was detected). The incident has been logged.
   ```
3. Menulis satu **insiden JSON gaya ECS** ke **stderr** untuk ELK / Logstash.
   Insiden mencatat **key / path / alasan — bukan nilai rahasianya**:
   ```json
   {"@timestamp":"...","log.level":"error","log.logger":"priva-mcp.compliance","event.kind":"alert","event.category":"intrusion_detection","event.action":"compliance.critical_violation","event.outcome":"blocked","tool":"get_customer_profile","user_id_mock":"attacker-probe","violation_count":1,"violations":[{"path":"$.pin","key":"pin","reason":"forbidden sensitive field present in gateway response"}],"message":"Forbidden sensitive field detected in gateway response; response blocked before reaching the client."}
   ```
4. Mencatat panggilan di `audit.log` dengan `status_compliance: "BLOCKED"`.

Error pipeline tak terduga ditangani sama: error generik ke klien, detail penuh
(termasuk `error.stack_trace`) ke stderr di bawah
`event.action: "compliance.pipeline_error"`. **stdout tidak pernah membawa
kebocoran.**

---

## Format audit log

`audit.log` adalah [JSON Lines](https://jsonlines.org/) — satu record per
panggilan. Ganti lokasinya dengan `AUDIT_LOG_PATH`.

Panggilan tersensor (normal):

```json
{"timestamp":"...","tool_called":"get_customer_profile","user_id_mock":"teller-01","status_compliance":"REDACTED","redactions":[{"category":"cif","method":"KEY_MATCH","count":1},{"category":"bank_account","method":"KEY_MATCH","count":1}],"total_redactions":6}
```

Panggilan diblokir:

```json
{"timestamp":"...","tool_called":"get_customer_profile","user_id_mock":"attacker-probe","status_compliance":"BLOCKED","redactions":[...],"total_redactions":6,"note":"critical violation: pin"}
```

| Field | Arti |
|---|---|
| `timestamp` | ISO-8601 |
| `tool_called` | nama tool |
| `user_id_mock` | pemohon (`requestedBy`, atau `mock-user-001`) |
| `status_compliance` | `CLEAN` \| `REDACTED` \| `BLOCKED` |
| `redactions[]` | `{ category, method, count }` per kategori |
| `total_redactions` | total seluruh kategori |
| `note` | opsional (error, blokir) |

---

## Uji cepat manual

Jalankan server manual dengan urutan JSON-RPC dipipa ke stdin.

**bash:**

```bash
printf '%s\n' \
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.0.0"}}}' \
'{"jsonrpc":"2.0","method":"notifications/initialized"}' \
'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_customer_profile","arguments":{"cifNumber":"CIF-7782001","requestedBy":"teller-01"}}}' \
| node dist/server.js
```

Akan tampil profil dengan field sensitif tersensor, `balance: 0` (ketat), dan
baris `REDACTED` baru di `audit.log`. Untuk melihat nominal apa adanya, awali
dengan `COMPLIANCE_STRICT=false`.

---

## Sambungkan ke Claude Desktop

1. Build agar `dist/server.js` ada: `npm run build`.
2. Buka config Claude Desktop:
   - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
   - **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
3. Tambahkan Priva-MCP di `mcpServers` (pakai **path absolut** ke `dist/server.js`):

   ```json
   {
     "mcpServers": {
       "priva-mcp": {
         "command": "node",
         "args": ["C:\\Users\\adhi0\\Projects\\Development\\priva-mcp\\dist\\server.js"],
         "env": {
           "COMPLIANCE_STRICT": "true",
           "AUDIT_LOG_PATH": "C:\\Users\\adhi0\\Projects\\Development\\priva-mcp\\audit.log"
         }
       }
     }
   }
   ```

4. **Restart penuh** Claude Desktop. Kedua tool muncul di menu tools. Minta Claude
   mis. *"ambil profil untuk CIF-7782001"* dan pastikan data yang kembali sudah
   tersensor.

---

## Pengujian

```bash
npm test
```

Memakai runner bawaan `node:test` via `tsx` (tanpa dependency tambahan). Cakupan:
masker murni, klasifikasi key (termasuk penjaga *near-miss* seperti `customerId`
/ `accountHolder`), deteksi key nominal, deteksi token terlarang, Lapis 1
`KEY_MATCH`, Lapis 2 `REGEX_MATCH`, perbaikan *false-positive* NIK, field
`cif`/`pan`/`accountNumber`, mode ketat vs longgar, dan blokir zero-trust
(beserta path pelanggaran).

---

## Cara kerja deteksi

Aturan di `src/compliance/patterns.ts` menggerakkan kedua lapis:

- **Lapis 1 (`KEY_RULES`)** memetakan token nama-key ke masker dan jalan lebih
  dulu untuk tiap field di dalam objek terstruktur. Ini jalur presisi
  berkepercayaan tinggi — melewati regex membabi buta, jadi NIK 16 digit di
  field `nik` tak akan dikira kartu kredit.
- **Lapis 2 (`REDACTION_RULES`)** adalah cadangan regex global terurut untuk teks
  mentah dan key tak spesifik. Begitu nilai disensor, digit-nya jadi `X` dan tak
  bisa dicocokkan ulang oleh aturan yang lebih lebar.

`ComplianceEngine.redactObject(input: unknown)` rekursif menelusuri objek &
array, mempersempit tipe saat runtime (tanpa `any` tak tercek), melacak path JSON
untuk pelaporan insiden, dan mengumpulkan output tersensor sekaligus pelanggaran
kritis.

Menambah kategori: tambahkan `KeyRule` ke `KEY_RULES` dan/atau `RedactionRule` ke
`REDACTION_RULES`. Mengganti gateway mock dengan internal API nyata: ganti method
di `src/gateway/gateway.ts` — lapisan compliance, audit, dan insiden tetap utuh.

---

## Alur data — apa yang sampai ke Anthropic

Server MCP berjalan **lokal** (Claude Desktop men-spawn-nya via stdio). Tapi
*model* Claude berjalan di server Anthropic, jadi apa pun yang dikembalikan tool
ke klien ikut masuk ke konteks percakapan yang dikirim ke Anthropic. Tugas
Priva-MCP: memastikan hanya data **tersensor** yang menyeberangi batas itu.

```
        ── mesinmu (lokal) ──────────────────────────┊── Anthropic (cloud) ──
  Internal API ─mentah─▶ Priva-MCP ─sensor─▶ Claude Desktop ─hanya tersensor─▶ Model Claude
   (DB/REST)            (sensor+blokir)        (klien MCP)    ┊
                            │                                 ┊
                            ▼                                 ┊ batas kepercayaan
                   audit.log + insiden ELK  ── tetap lokal 🔒 ┊
```

- **Dikirim ke Anthropic:** output tool yang tersensor (mis. `REDACTED-CIF`,
  `XXXX-…-1111`, `balance: 0`) plus prompt yang kamu ketik — model butuh itu
  untuk menjawab.
- **Tidak pernah dikirim:** PII mentah (cuma ada di RAM proses lokal), field
  terlarang yang diblokir, dan log `audit.log` / insiden stderr — semua tetap di
  mesinmu.
- **Perlu diingat:**
  - Masker sebagian (mis. 4 digit akhir) tetap keluar; rahasia penuh tidak.
  - Pesan chat-mu sendiri **tidak** disensor — Priva-MCP hanya menyaring *output
    tool*, bukan prompt-mu. Jangan tempel PII asli langsung di chat.
  - Dengan `COMPLIANCE_STRICT=false`, saldo/nominal asli ikut dikirim.
  - Cakupan = kualitas aturan — field yang tak cocok `KEY_RULES` jatuh ke regex
    Lapis 2; yang meleset bisa lolos.
  - Data yang sampai ke Anthropic tunduk pada kebijakan data Anthropic sesuai
    plan-mu; Priva-MCP meminimalkan *apa* yang dikirim, bukan retensinya.

---

## Landing page (Vercel)

Landing page statis ada di [`web/`](web/index.html) (EN) dan
[`web/id.html`](web/id.html) (ID) — pengenalan plus panduan implementasi
copy-paste. Murni HTML/CSS/JS (tanpa build step).

Opsi deploy:

- **Import zero-config:** import repo ke Vercel. [`vercel.json`](vercel.json) di
  root mengarahkan `/` ke `web/index.html` dan menyajikan sisanya sebagai aset
  statis — tanpa framework atau build command.
- **Mode root-directory:** alternatif, set *Root Directory* Vercel ke `web`,
  kosongkan build command.
- **Pratinjau lokal:** `npx serve web` (atau buka `web/index.html` langsung).

---

## Menuju produksi

- **Masking berbasis peran** — kedalaman masker bergantung clearance pemanggil.
- **NER untuk teks bebas** — ganti heuristik regex dengan model PII khusus.
- **Transport SIEM** — kirim audit + insiden via transport nyata (Kafka / HTTP);
  nama field sudah selaras ECS Elastic.
- **Kebijakan berbasis konfig** — eksternalkan `KEY_RULES`, kata terlarang, dan
  mode ketat ke file kebijakan bertanda tangan dengan hot reload.
- **Tokenisasi / FPE** — ganti masking dengan format-preserving encryption agar
  nilai tetap bisa di-join tanpa membuka plaintext.
