// Hash Check - drop a file, get MD5 / SHA-1 / SHA-256 / SHA-512, compare with an expected hash.
#include "../common/ui.h"
#include <bcrypt.h>
#include <thread>
#include <atomic>
using namespace ui;

enum { ID_BROWSE = 100, ID_COPY0, ID_COPY1, ID_COPY2, ID_COPY3, ID_EXPECT, ID_PASTE };
enum { WM_PROGRESS = WM_APP + 1, WM_DONE = WM_APP + 2 };
static const wchar_t* NAMES[4] = {L"MD5", L"SHA-1", L"SHA-256", L"SHA-512"};
static const wchar_t* ALGS[4] = {BCRYPT_MD5_ALGORITHM, BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA512_ALGORITHM};

static HWND gWnd, gExpect, gCopy[4], gBrowse;
static std::wstring gFile, gInfo = L"Drop any file onto this window, or click Browse";
static std::wstring gHash[4];
static int gProgress = -1;  // per mille, -1 = idle
static std::atomic<int> gGen{0};
static std::wstring gStatus = L"Ready  \x00B7  drag & drop works anywhere on the window";
static COLORREF gStatusColor = MUTED;
static std::wstring gMatch; static COLORREF gMatchColor = MUTED;

struct Result { int gen; bool ok; std::wstring err; std::wstring hash[4]; unsigned long long bytes; double ms; };

static void hashWorker(std::wstring path, int gen) {
    auto* res = new Result{gen, false, L"", {}, 0, 0};
    double t0 = nowMs();
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (f == INVALID_HANDLE_VALUE) { res->err = L"Could not open the file"; PostMessageW(gWnd, WM_DONE, 0, (LPARAM)res); return; }
    LARGE_INTEGER sz; GetFileSizeEx(f, &sz);
    BCRYPT_ALG_HANDLE alg[4] = {}; BCRYPT_HASH_HANDLE hh[4] = {};
    for (int i = 0; i < 4; i++) {
        BCryptOpenAlgorithmProvider(&alg[i], ALGS[i], nullptr, 0);
        BCryptCreateHash(alg[i], &hh[i], nullptr, 0, nullptr, 0, 0);
    }
    const DWORD CH = 8 << 20;
    std::vector<uint8_t> buf(CH);
    unsigned long long done = 0; double lastPost = 0; bool cancelled = false;
    for (;;) {
        if (gGen != gen) { cancelled = true; break; }
        DWORD got = 0;
        if (!ReadFile(f, buf.data(), CH, &got, nullptr)) { res->err = L"Read error"; break; }
        if (!got) break;
        std::thread th[3];
        for (int i = 0; i < 3; i++) th[i] = std::thread([&, i] { BCryptHashData(hh[i == 2 ? 3 : i], buf.data(), got, 0); });
        BCryptHashData(hh[2], buf.data(), got, 0);
        for (auto& t : th) t.join();
        done += got;
        double now = nowMs();
        if (now - lastPost > 40 && sz.QuadPart > 0) {
            lastPost = now; PostMessageW(gWnd, WM_PROGRESS, gen, (LPARAM)(done * 1000 / sz.QuadPart));
        }
    }
    CloseHandle(f);
    for (int i = 0; i < 4; i++) {
        if (!cancelled && res->err.empty()) {
            DWORD len = 0, cb = 0;
            BCryptGetProperty(alg[i], BCRYPT_HASH_LENGTH, (PUCHAR)&len, sizeof(len), &cb, 0);
            std::vector<uint8_t> out(len);
            BCryptFinishHash(hh[i], out.data(), len, 0);
            static const wchar_t* hx = L"0123456789abcdef";
            for (uint8_t b : out) { res->hash[i] += hx[b >> 4]; res->hash[i] += hx[b & 15]; }
        }
        BCryptDestroyHash(hh[i]); BCryptCloseAlgorithmProvider(alg[i], 0);
    }
    res->ok = !cancelled && res->err.empty();
    res->bytes = done; res->ms = nowMs() - t0;
    if (cancelled) { delete res; return; }
    PostMessageW(gWnd, WM_DONE, 0, (LPARAM)res);
}

static void setStatus(const std::wstring& s, COLORREF c) { gStatus = s; gStatusColor = c; InvalidateRect(gWnd, nullptr, FALSE); }

static std::wstring extractHex(const std::wstring& s) {
    std::wstring best, cur;
    auto flush = [&] { size_t n = cur.size(); if ((n == 32 || n == 40 || n == 64 || n == 128) && best.empty()) best = cur; cur.clear(); };
    for (wchar_t c : s) { if (iswxdigit(c)) cur += (wchar_t)towlower(c); else flush(); }
    flush();
    return best;
}
static void updateMatch() {
    std::wstring raw = getText(gExpect);
    if (raw.find_first_not_of(L" \t\r\n") == std::wstring::npos) { gMatch = L"Paste a hash to compare"; gMatchColor = MUTED; }
    else {
        std::wstring hx = extractHex(raw);
        if (hx.empty()) { gMatch = L"Not a valid hash"; gMatchColor = WARN; }
        else if (gHash[0].empty()) { gMatch = L"Waiting for a file\x2026"; gMatchColor = MUTED; }
        else {
            gMatch = L"\x2717  No match \x2014 file differs!"; gMatchColor = ERR;
            for (int i = 0; i < 4; i++) if (gHash[i] == hx) { gMatch = L"\x2713  " + std::wstring(NAMES[i]) + L" matches"; gMatchColor = OK; }
        }
    }
    InvalidateRect(gWnd, nullptr, FALSE);
}

static void startHash(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) { setStatus(L"That is not a file", WARN); return; }
    gFile = path;
    WIN32_FILE_ATTRIBUTE_DATA fa; GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fa);
    unsigned long long size = ((unsigned long long)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
    gInfo = sizeStr(size) + L"  \x00B7  " + path;
    for (auto& h : gHash) h.clear();
    gProgress = 0;
    int gen = ++gGen;
    for (auto b : gCopy) EnableWindow(b, FALSE);
    setStatus(L"Hashing\x2026", MUTED);
    updateMatch();
    std::thread(hashWorker, path, gen).detach();
}

static void paint(HDC dc, RECT) {
    header(dc, L"Hash Check", L"drop a file   \x2192   MD5  \x00B7  SHA-1  \x00B7  SHA-256  \x00B7  SHA-512", 192);
    // file card
    fillRound(dc, R(24, 70, 772, 100), S(20), CARD);
    text(dc, gFile.empty() ? L"No file yet" : baseName(gFile), R(44, 84, 590, 26), fBtnBold, TEXT, LEFT1);
    text(dc, gInfo, R(44, 112, 590, 22), fSmall, MUTED, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_PATH_ELLIPSIS);
    fillRound(dc, R(44, 146, 732, 8), S(8), FIELD);
    if (gProgress >= 0) {
        RECT p = R(44, 146, 732, 8); p.right = p.left + (p.right - p.left) * gProgress / 1000;
        if (p.right - p.left > S(8)) fillRound(dc, p, S(8), gProgress >= 1000 ? OK : ACCENT);
    }
    // hashes
    fillRound(dc, R(24, 184, 772, 248), S(20), CARD);
    for (int i = 0; i < 4; i++) {
        int y = 198 + i * 56;
        text(dc, NAMES[i], R(44, y, 80, 40), fBtn, MUTED, LEFT1);
        fillRound(dc, R(126, y, 560, 40), S(12), FIELD, BORDER);
        std::wstring v = gHash[i].empty() ? (gProgress >= 0 && gProgress < 1000 ? L"\x2026" : L"\x2014") : gHash[i];
        text(dc, v, R(140, y, 536, 40), fMono, gHash[i].empty() ? MUTED : TEXT, LEFT1);
    }
    // compare
    fillRound(dc, R(24, 446, 772, 80), S(20), CARD);
    text(dc, L"Expected hash (from the download page)", R(44, 454, 400, 20), fSmall, MUTED, LEFT1);
    fillRound(dc, R(44, 476, 470, 38), S(12), FIELD, BORDER);
    text(dc, gMatch, R(612, 476, 170, 38), fBtn, gMatchColor, LEFT1);
    text(dc, gStatus, R(26, 532, 770, 22), fSmall, gStatusColor, LEFT1);
}

static LRESULT CALLBACK wndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_CREATE:
        gWnd = h;
        gBrowse = button(h, ID_BROWSE, L"Browse\x2026", R(656, 92, 120, 40), PRIMARY);
        for (int i = 0; i < 4; i++) { gCopy[i] = button(h, ID_COPY0 + i, L"Copy", R(696, 198 + i * 56, 80, 40)); EnableWindow(gCopy[i], FALSE); }
        gExpect = edit(h, ID_EXPECT, R(56, 485, 450, 22), ES_AUTOHSCROLL, fMono);
        SendMessageW(gExpect, EM_SETCUEBANNER, TRUE, (LPARAM)L"paste hash here");
        button(h, ID_PASTE, L"Paste", R(522, 476, 80, 38));
        DragAcceptFiles(h, TRUE);
        updateMatch();
        return 0;
    case WM_DROPFILES: { auto f = dropped((HDROP)w); if (!f.empty()) startHash(f[0]); return 0; }
    case WM_COMMAND: {
        int id = LOWORD(w);
        if (id == ID_BROWSE) { auto f = openFiles(h, L"All files (*.*)\0*.*\0", false); if (!f.empty()) startHash(f[0]); }
        else if (id >= ID_COPY0 && id <= ID_COPY3) {
            int i = id - ID_COPY0;
            if (setClipText(h, gHash[i])) { flash(gCopy[i], L"\x2713"); setStatus(std::wstring(NAMES[i]) + L" copied to clipboard", OK); }
        } else if (id == ID_EXPECT && HIWORD(w) == EN_CHANGE) updateMatch();
        else if (id == ID_PASTE) { SetWindowTextW(gExpect, getClipText(h).c_str()); updateMatch(); }
        return 0;
    }
    case WM_PROGRESS: if ((int)w == gGen) { gProgress = (int)l; InvalidateRect(h, nullptr, FALSE); } return 0;
    case WM_DONE: {
        auto* r = (Result*)l;
        if (r->gen == gGen) {
            if (r->ok) {
                for (int i = 0; i < 4; i++) gHash[i] = r->hash[i];
                gProgress = 1000;
                for (auto b : gCopy) EnableWindow(b, TRUE);
                double mbs = r->ms > 0 ? r->bytes / 1048576.0 / (r->ms / 1000) : 0;
                setStatus(fmt(L"\x2713 Hashed %ls in %.0f ms", sizeStr(r->bytes).c_str(), r->ms) + (r->bytes > (8 << 20) ? fmt(L"  (%.0f MB/s)", mbs) : L""), OK);
            } else { gProgress = -1; setStatus(r->err, ERR); }
            updateMatch();
        }
        delete r; return 0;
    }
    case WM_CTLCOLOREDIT: return ctlColor(w);
    case WM_DRAWITEM: drawButton((DRAWITEMSTRUCT*)l); return TRUE;
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: paintBuffered(h, paint); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int show) {
    init(inst);
    HWND h = createMain(L"HashCheckWnd", L"Hash Check", 820, 560, wndProc);
    ShowWindow(h, show); UpdateWindow(h);
    int argc; LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc > 1) startHash(argv[1]);
    return loop([&](MSG& m) {
        if (ctrlKey(m, 'O')) { SendMessageW(h, WM_COMMAND, ID_BROWSE, 0); return true; }
        return false;
    });
}
