# Label mapping — nhan goc -> verified_label

**Tracked o day (`eval/label_mapping.md`) de dam bao reproducibility**: file nay la
NGUON SU THAT cho VERDICT dict trong `eval/apply_verified_labels.py`. Cac file bang
chung CHI TIET (doc CRX that, grep own-code, doi chieu events.json) van nam o
`eval/_verify/*.md` (`benign_fp/verdict.md`, `fn/fn_verdict.md`,
`fn/brand_impersonation_verdict.md`) — thu muc nay GITIGNORED (chua unpacked extension
code cua ben thu 3, khong nen commit) nen KHONG co trong git history. Neu can xem lai
bang chung goc, phai chay lai qua trinh giai nen CRX + doc code (da mo ta trong tung
file verdict) tren may co du lieu `sample/`.

Ap dung boi `eval/apply_verified_labels.py`, ghi cot `verified_label` + `verified`
(yes/no) vao `eval/results/summary.csv`. Mau KHONG co verdict giu nguyen `label` goc,
`verified=no` — KHONG doan.

## Quy tac chuyen doi

| Nhan goc | Verdict (verdict.md / fn_verdict.md) | verified_label |
|---|---|---|
| benign | grey_pup | grey |
| benign | verified_benign / attribution_error | benign |
| malicious | benign_mislabel | benign_mislabel |
| malicious | adware_pup | grey |
| malicious | obfuscated_unknown | unknown_verify |
| malicious | malware_missed | malicious |

Ghi chu: `attribution_error` trong verdict.md luon di kem `verified_benign` hoac
`grey_pup` (chua bao gio dung mot minh) — dung nhan chinh (`verified_benign`/
`grey_pup`) de map, `attribution_error` chi la giai thich nguyen nhan risk bi
thoi phong, khong phai mot lop rieng.

`benign_mislabel` (tu malware set) va `benign` (tu benign set) la 2 gia tri
KHAC NHAU trong `verified_label` — giu tach biet de truy vet: mau nao von
duoc gan nhan malicious roi verify ra la lanh (benign_mislabel) khac voi mau
von da la benign that (benign). `eval/pr_roc.py --mode verified` gop ca hai
vao lop benign khi tinh duong cong, nhung cot `verified_label` trong CSV giu
nguyen phan biet.

## 14 mau benign (tu eval/_verify/benign_fp/verdict.md)

verified_benign (11) -> verified_label=benign:
dashlane, ghostery, videodownloadhelper, grammarly, languagetool,
awesomescreenshot, nordpass, momentum, evernotewebclipper, sponsorblock,
editthiscookie

grey_pup (3) -> verified_label=grey:
capitaloneshopping, rakuten, honey

## 26 mau malware (tu eval/_verify/fn/fn_verdict.md)

benign_mislabel (17) -> verified_label=benign_mislabel:
ajfokipknlmjhcioemgnofkpmdnbaldi, beifiidafjobphnbhbbgmgnndjolfcho,
eheagnmidghfknkcaehacggccfiidhik, gddonialdhbldcdbnbloangmjnpcnhhd,
goiffchdhlcehhgdpdbocefkohlhmlom, hhlcpmdhlcoghhfgiiopcjbkfmdliknc,
hodafefeincjlgijbiabbmaffambjeaa, pgejmpeimhjncennkkddmdknpgfblbcl,
acmfnomgphggonodopogfbmkneepfgnh, apdfllckaahabafndbhieahigkjlhalf,
ccgdboldgdlngcgfdolahmiilojmfndl, cdiohdbijdajffgccjmbblbikpnnnkeg,
cimpffimgeipdhnhjohpbehjkcdpjolg, codgofkgobbmgglciccjabipdlgefnch,
eggegjdejilddmnlglakcaigefefcdaf, abbngaojehjekanfdipifimgmppiojpl,
adjiljljjoeielcjmafljkicjncjpbha

adware_pup (7) -> verified_label=grey:
dnmfcojgjchpjcmjgpgonmhccibjopnb, nfijbcmjagdmmkchgicfdidblofopkdp,
pfgpfmdiepmhhhkpnciogjhccppbcfhk, ecocgofdjmiomgmgnchijbghkikolkkl,
aecccajigpipkpioaidignbgbeekglkd, aikflfpejipbpjdlfabpgclhblkpaafo,
ajfanjhcdgaohcbphpaceglgpgaaohod

obfuscated_unknown (2) -> verified_label=unknown_verify:
bajoeadpdidoahbhphmhejmbdmgnbdci, glckmpfajbjppappjlnhhlofhdhlcgaj

malware_missed (0): khong mau nao — 26/26 mau doc dai dien deu la
benign_mislabel/adware_pup/obfuscated_unknown, khong mau nao xac nhan la
malware that bi bo sot (xem "Nhan xet quan trong #1" trong fn_verdict.md).

## 4 mau brand_impersonation (tu eval/_verify/fn/brand_impersonation_verdict.md, dot fix #2/#3)

Phat hien trong luc do luong recall sau Fix #2 (`detect_unsolicited_tabs`) + Fix #3
(`detect_script_injection`, ban page_host-only, an toan) trong `worker/risk.py`: 4 mau
nay "rung" khoi flag (risk 45->15) vi ca 3 tin hieu dynamic deu bat nguon tu CUNG MOT
trang welcome noi bo cua chinh no. Kiem tra: KHONG co content_scripts, KHONG
host_permissions (permissions=["storage","sidePanel"]) -> ve mat ky thuat KHONG the
inject/doc trang nao nguoi dung dang xem. La 4 clone gia danh thuong hieu AI (Grok/
DeepSeek/Perplexity) tu CUNG mot factory (`*.easytool.dev`, cung bundle JS). Ban chat
la BRAND IMPERSONATION (danh lua bang ten goi), khong phai injection/exfil runtime ->
verified_label=benign_mislabel:

aoemlgniakbojcecmjefonjkgnceklpg, fgbieegonkgdlkmeaapmkejdlfalonkb,
hafhkoalnlpoifpidohfjlmeemfifndi, ifhigdhiifbnjanhacoedbadhmlkjgae

## Tong ket

44/44 mau co verdict duoc doi verified_label + verified=yes (14 benign_fp + 26 fn +
4 brand_impersonation). Toan bo cac mau con lai trong summary.csv (khong nam trong
3 file verdict) giu nguyen `label` goc, `verified_label = label`, `verified=no`.
