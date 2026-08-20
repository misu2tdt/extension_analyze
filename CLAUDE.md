# ExtAnalyze — Hệ thống phát hiện Chrome extension độc hại

## Bối cảnh dự án

Đồ án tốt nghiệp ngành CNPM, ĐH Bách Khoa TP.HCM (HCMUT-VNU).

Đây là **nghiên cứu bảo mật PHÒNG THỦ**: hệ thống phân tích động (dynamic analysis) để **phát hiện và cảnh báo** extension độc hại, phục vụ người dùng cuối, đội IT security, và reviewer của extension store.

Hệ thống KHÔNG tạo, KHÔNG phát tán, KHÔNG tối ưu malware. Các mẫu malware dùng để kiểm thử đều đã được công bố công khai bởi nhà nghiên cứu khác (chiến dịch 108-extension MaaS, Socket.dev & FPT-IS, 04/2026).

Ngôn ngữ trao đổi: **tiếng Việt**. Thuật ngữ kỹ thuật giữ nguyên tiếng Anh.

---

## Kiến trúc

Kiến trúc phân tán hướng dịch vụ (service-oriented), bất đồng bộ 2 pha:

```
User → API (FastAPI) → Redis (queue) → Worker (Celery) → Sandbox (container tạm)
          ↓                                ↓
     PostgreSQL  ←────────────────────────┘
          ↓
       MinIO (CRX, PCAP, screenshot)
```

**Pha 1 (API, <1s)**: validate CRX → hash SHA256 → lưu MinIO → tạo job → enqueue.

**Pha 2 (Worker, ~20-150s)**: tải CRX → spawn sandbox container → thu hành vi → build report → chấm risk score → lưu DB.

### 3 khối code ĐỘC LẬP — không import lẫn nhau

| Khối | Vai trò | Giao tiếp qua |
|---|---|---|
| `api/` | Tiếp nhận, validate, lưu trữ, enqueue | Redis, PostgreSQL, MinIO |
| `worker/` | Điều phối phân tích, chấm điểm | Redis, PostgreSQL, MinIO, Docker socket |
| `sandbox/` | Chạy extension, quan sát hành vi | shared volume + tham số dòng lệnh |

**QUAN TRỌNG**: `worker/` KHÔNG import code trong `sandbox/`. Thư mục `sandbox/` chỉ dùng để **build image** `extanalyze-sandbox:latest`. Worker ra lệnh Docker tạo **container mới** từ image đó cho mỗi job, chạy xong container tự hủy (`--rm`). Đây là thiết kế ephemeral sandbox — mỗi mẫu chạy trong môi trường sạch, không nhiễm chéo.

---

## Cấu trúc thư mục

```
ext_analyze/
├── api/
│   ├── main.py                 # entry point, init DB + bucket, logging
│   ├── models.py               # ORM: bảng jobs
│   ├── database.py             # engine, session, get_db()
│   ├── celery_client.py        # gửi task vào queue
│   ├── routers/jobs.py         # POST /jobs/analyze, GET /jobs/{id}
│   ├── routers/health.py       # GET /health
│   └── services/
│       ├── crx_validator.py    # check magic bytes Cr24 + version
│       └── storage.py          # MinIO: upload/download/presigned/bucket
├── worker/
│   ├── tasks.py                # task chính: spawn sandbox, thu kết quả
│   ├── risk.py                 # build report + compute risk score
│   ├── celery_app.py           # cấu hình Celery
│   └── database.py             # bản sao schema Job (worker dùng riêng)
├── sandbox/                    # NGUYÊN LIỆU BUILD IMAGE (không phải code chạy)
│   ├── Dockerfile              # Chromium + Playwright + Xvfb + tcpdump + honeypot
│   ├── entrypoint.sh           # honey server + tcpdump + chạy analyze qua Xvfb
│   ├── analyze.py              # nạp extension, quan sát hành vi
│   ├── honey_pages/            # trang mồi chứa credential giả
│   ├── batch_test.bat          # chạy nhiều mẫu
│   └── summarize.py            # tổng hợp kết quả batch
├── malware_samples/            # mẫu độc (KHÔNG commit lên git)
├── benign_samples/             # mẫu lành tính (nhóm đối chứng)
└── docker-compose.yml
```

---

## Lệnh thường dùng (Windows CMD)

### Build và chạy toàn hệ thống

```cmd
REM 1. Build sandbox image TRƯỚC (bắt buộc, worker cần image này)
cd sandbox
docker build --no-cache -t extanalyze-sandbox:latest .
cd ..

REM 2. Chạy stack
docker compose up --build

REM 3. Nếu ĐỔI SCHEMA DB thì phải xóa volume, không thì worker lỗi thiếu cột
docker compose down -v
docker compose up --build
```

### Thử pipeline end-to-end

```cmd
curl -X POST http://localhost:8000/jobs/analyze -F "file=@sandbox\test.crx"
curl http://localhost:8000/jobs/<job_id>
docker compose logs -f worker
```

### Chạy sandbox độc lập (debug nhanh, không qua API)

```cmd
docker run --rm --shm-size=2g --cap-add=NET_ADMIN --cap-add=NET_RAW ^
  -v %cd%\..\malware_samples:/samples -v %cd%\output:/work/output ^
  extanalyze-sandbox:latest ^
  /samples/MALWARE_<id>.crx /work/output 150
```

### Batch test nhiều mẫu

```cmd
cd sandbox
batch_test.bat
python summarize.py
```

### Giao diện

- API docs (Swagger): http://localhost:8000/docs
- MinIO console: http://localhost:9001 (minioadmin / minioadmin123)

---

## CÁC CÁI BẪY ĐÃ TRẢ GIÁ — đọc kỹ trước khi sửa

### 1. Sửa `sandbox/analyze.py` mà KHÔNG rebuild image thì chạy code cũ

`analyze.py` được `COPY` vào image lúc build, KHÔNG mount runtime. Sửa file trên máy mà không build lại thì container vẫn chạy bản cũ.

Sau mỗi lần sửa file trong `sandbox/`:

```cmd
docker build --no-cache -t extanalyze-sandbox:latest .
```

Kiểm chứng code mới đã vào image:

```cmd
docker run --rm extanalyze-sandbox:latest cat /sandbox/analyze.py | findstr "chuoi_moi"
```

### 2. `entrypoint.sh` PHẢI dùng line ending LF (không CRLF)

Windows lưu mặc định CRLF, container sẽ báo `$'\r': command not found`. Đã có `.gitattributes` ép LF. Trong VS Code, kiểm tra góc dưới phải hiển thị "LF".

### 3. Chuỗi timeout phải nhất quán

Shell cấp ngân sách, Python tự trừ biên an toàn. Không hard-code ở 2 nơi.

```
entrypoint.sh: timeout $TIMEOUT python3 analyze.py --timeout $TIMEOUT
analyze.py:    soft = max(30, timeout - 30)   # tự suy ra
```

Nếu soft timeout lớn hơn hard timeout thì exit 124, mất kết quả.

### 4. Shared volume giữa worker và sandbox (sibling container)

Worker spawn sandbox qua Docker socket của host nên sandbox là container **anh em**, không phải con. Đường dẫn volume resolve trên **host**. Cả hai phải trỏ cùng một host path:

```
worker volume     : /run/desktop/mnt/host/c/extanalyze_shared:/shared
env HOST_SHARED_TMP: /run/desktop/mnt/host/c/extanalyze_shared
```

Yêu cầu: tạo `C:\extanalyze_shared` và bật File Sharing ổ C: trong Docker Desktop.

### 5. Phải xóa profile Chromium giữa các lần chạy

Cảm biến đọc `chrome.storage` lấy dữ liệu từ `/tmp/chrome-profile`. Không xóa thì đọc nhầm dữ liệu mẫu TRƯỚC, dẫn tới kết luận sai. `entrypoint.sh` đã có `rm -rf /tmp/chrome-profile`.

### 6. Log không hiện không có nghĩa là code không chạy

`logger.info()` bị nuốt nếu chưa gọi `logging.basicConfig(level=INFO)`. Đã thêm ở đầu `api/main.py`. Đừng nghi ngờ logic trước khi kiểm tra logging.

### 7. Đặc thù Windows

Dùng `findstr` (không phải `grep`), `%cd%` trong CMD và `${PWD}` trong PowerShell (không dùng `$(pwd)`).

---

## Quy ước code

- Comment trong code: **tiếng Việt không dấu** (tránh lỗi encoding trong container).
- Mọi thao tác MinIO đi qua `api/services/storage.py`, không gọi boto3 rải rác.
- Worker task luôn bọc `try/except/finally`: DB phải phản ánh đúng trạng thái (`done`/`failed`), thư mục tạm luôn được dọn.
- `analyze.py` ghi `events.json` **tăng dần** sau mỗi trang, vì sandbox có thể bị kill bất cứ lúc nào, dữ liệu phải sống sót.
- Cảm biến chạy trong trang (JS injected) phải bọc `try/catch`, không được làm hỏng trang đang quan sát.
- Schema báo cáo có `schema_version`. Thêm field thì bump version, không phá cấu trúc cũ.

---

## Quy tắc an toàn khi làm việc với mẫu malware

- Mẫu độc CHỈ chạy trong sandbox container. **Không bao giờ** load vào Chrome thật.
- **Không đăng nhập tài khoản thật** khi test (malware này nhắm OAuth Google/Telegram).
- File mẫu đặt tiền tố `MALWARE_`, để trong `malware_samples/`, **không commit git**.
- Container luôn chạy với `--rm` (tự hủy).
- Không viết code làm tăng khả năng gây hại của mẫu, chỉ quan sát và phát hiện.

---

## Trạng thái hiện tại

- Phase 1 (Foundation) — xong: hạ tầng và walking skeleton.
- Phase 2 (Core Pipeline) — xong: pipeline end-to-end thật, kiểm chứng trên malware thật (~18s/job).
- Phase 3 (Enhancement) — đang làm: sandbox quan sát sâu hơn (service worker traffic qua CDP, provenance extension-vs-page cho network/DOM, MITRE mapping), risk scoring dynamic-first, đánh giá định lượng trên 354 mẫu (313 malicious + 41 benign) với nhãn đã verify tay một phần.
- Phase 4 (Polish + Benchmark) — chưa tới.

### Fix đã xong trong đợt review gần nhất (code review Codex + Claude Code)

- **SW-attribution** (`sandbox/sensors/cdp_sw.py`): chỉ coi target CDP là service worker của extension nếu `type=="service_worker"` VÀ `url` bắt đầu `chrome-extension://` — trước đây `type=="worker"` cũng bị gộp, khiến Service Worker do CHÍNH TRANG đăng ký (PWA-style, đã bắt gặp ở `msn.com`, `wayin.ai`) bị gán nhầm là SW của extension. Đã validate qua smoke_test (13/13) + full-pool re-run (354 mẫu): recall lõi không đổi (0.9298→0.9298).
- **Wildcard `host_permissions` parse** (`worker/risk.py`): `*.example.com` trước đây bị thay `*`→`x` thành host giả `x.example.com`; đã sửa dùng suffix-match đúng. `<all_urls>` cố ý KHÔNG miễn trừ host nào (đo được: coi `<all_urls>`="khai báo mọi host" làm recall injector tụt 0.938→0.600).
- **`pr_roc.py` run_status filter + verified mode**: chỉ tính AUC/FPR trên `run_status=="complete"`; thêm `--mode verified` dùng `verified_label` (tách lớp grey/unknown_verify, gộp benign_mislabel vào benign).
- **Welcome-tab discount** (`worker/risk.py`, Fix #2/#3): loại `unsolicited_tab`/`script_injection` khi đích là trang NỘI BỘ của chính extension (`chrome-extension://<own-id>/...`, id lấy từ `service_workers[].url` — id thật, không đoán theo tên/domain). CHỈ loại theo `page_host` cho script_injection (không loại theo `node_host`) — bản đầu loại theo node_host từng xóa oan bằng chứng credential-phishing thật (payload tự đóng gói chèn vào trang thứ ba), đã tự phát hiện và sửa.
- **Verified-label pipeline** (`eval/apply_verified_labels.py` + `eval/label_mapping.md`): 44/354 mẫu đã đọc tay CRX thật (14 benign FP + 26 malware FN + 4 brand-impersonation), gán `verified_label` tách biệt với `label` gốc.
- **Attribution ablation** (`eval/ablation_attribution.py`): so NAIVE (tắt provenance filter) vs PROVENANCE-AWARE — xác nhận recall lõi không tụt (chỉ 1/58 mẫu, và mẫu đó provenance loại ĐÚNG page-noise, không phải evidence thật).

### Giới hạn đã biết (đừng coi là bug)

- Stimulus còn generic nên malware kích hoạt có điều kiện có thể "ngủ yên", mẫu độc vẫn có thể ra risk MINIMAL. Đây là kết quả **trung thực**.
- Risk scoring rule-based, ngưỡng chưa có cơ sở khoa học chặt chẽ.
- **Inline script/iframe injection** (T2 dynamic, chưa bắt được): `sandbox/sensors/dom.py` CÓ ghi node inline (`src="(inline)"`) nhưng KHÔNG capture nội dung script, và dedup key `tag+src` làm mất các injection inline lặp lại trên cùng 1 trang (key là hằng số cho mọi inline). Cần sensor surgery (capture content + đổi dedup key + provenance nguồn) trước khi bắt an toàn — xem docstring `_setup_dom_sensor` và LIMITATION trong `worker/risk.py`.
- **Self-domain/self-brand**: SW gọi domain của chính vendor (vd `api.bitwarden.com`) không khai `host_permissions` vẫn bị tính `undeclared_domain_contact` — CỐ Ý không allowlist theo tên/domain (name-match evadable, malware có thể chọn domain trùng tên). Xem LIMITATION trong `worker/risk.py`.
- **Brand/trademark impersonation**: extension giả danh thương hiệu (vd clone "Grok/DeepSeek/Perplexity" cùng 1 factory `*.easytool.dev`) có thể hoàn toàn "sạch" về dynamic-behavior nếu không có `content_scripts`/`host_permissions` — ngoài phạm vi detector hành vi runtime, cần tín hiệu metadata riêng (future work).
- **Top-level API call trong service worker** (sensor #7 GD1): chỉ chắc chắn bắt được API gọi từ event handler (message/alarm/webRequest callback); API gọi đồng bộ ngay top-level lúc SW vừa khởi động có thể chạy trước khi hook kịp patch — xem comment đầu `sandbox/sensors/cdp_sw.py`.
- 13/354 mẫu (~3.7%, chủ yếu ad-blocker nặng như ublock/adguard/privacybadger) có `run_status="unknown"` do sát/vượt timeout 180s — bị các script metric loại đúng, chưa chạy lại.

---

## Khi làm việc với Claude Code

- Trước khi sửa `sandbox/`, nhắc lại quy trình rebuild image.
- Khi đổi schema DB, nhắc `docker compose down -v`.
- Ưu tiên giải pháp đơn giản chạy được, **đo rồi mới leo thang** kỹ thuật (ví dụ: dùng `context.on("request")` trước, chỉ dùng CDP attach khi đo được là không đủ).
- Giải thích tư duy thiết kế trước khi đưa code: bước này làm gì, vì lý do gì.