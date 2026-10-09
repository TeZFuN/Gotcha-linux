// main.cpp — Gotcha Linux (Qt6 + libpcap): однофайловый порт 3main.py
#include <QApplication>
#include <QMainWindow>
#include <QTabWidget>
#include <QTextEdit>
#include <QTableWidget>
#include <QHeaderView>
#include <QProcess>
#include <QThread>
#include <QTimer>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QSplitter>
#include <QScrollArea>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QPushButton>
#include <QMessageBox>
#include <QFileDialog>
#include <QDialog>
#include <QGuiApplication>
#include <QScreen>
#include <QFont>
#include <QScrollBar>
#include <QNetworkInterface>
#include <QDateTime>
#include <QRegularExpression>
#include <QCloseEvent>
#include <QCursor>
#include <QFileInfo>
#include <QDir>
#include <QTextOption>
#include <QMap>
#include <QVector>
#include <QPair>
#include <QStringList>
#include <QByteArray>
#include <QSettings>
#include <QPalette>
#include <QStyleFactory>

#include <pcap/pcap.h>

#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <set>
#include <atomic>
#include <thread>
#include <chrono>
#include <functional>

// ==================== ROOT-ПЕРЕЗАПУСК ====================
// Как в Python-первоисточнике: сначала pkexec (GUI-friendly),
// при неудаче — sudo env VAR=... app.
static bool relaunchAsRoot(int argc, char *argv[]) {
    if (::geteuid() == 0) return true;

    char exePath[4096] = {0};
    const ssize_t n = ::readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
    const std::string appPath = (n > 0)
        ? std::string(exePath, static_cast<size_t>(n))
        : std::string(argv[0]);

    static const char *keepKeys[] = {
        "DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE", "DBUS_SESSION_BUS_ADDRESS",
        "GDK_SCALE", "GDK_DPI_SCALE", "GDK_BACKEND",
        "QT_SCALE_FACTOR", "QT_AUTO_SCREEN_SCALE_FACTOR", "QT_QPA_PLATFORM",
    };

    std::vector<std::string> envPairs;
    for (const char *k : keepKeys)
        if (const char *v = ::getenv(k); v && *v)
            envPairs.push_back(std::string(k) + "=" + v);

    // ---- Попытка 1: pkexec env VAR=... app (как в Python) ----
    if (::access("/usr/bin/pkexec", X_OK) == 0 || ::access("/bin/pkexec", X_OK) == 0) {
        std::vector<std::string> cmd;
        cmd.push_back("pkexec");
        cmd.push_back("env");
        for (auto &kv : envPairs) cmd.push_back(kv);
        cmd.push_back(appPath);
        for (int i = 1; i < argc; ++i) cmd.push_back(argv[i]);

        std::vector<char *> cargv;
        cargv.reserve(cmd.size() + 1);
        for (auto &s : cmd) cargv.push_back(s.data());
        cargv.push_back(nullptr);

        std::fprintf(stderr, "[i] Требуются права администратора. Запрашиваю pkexec...\n");
        std::fflush(stderr);
        ::execvp("pkexec", cargv.data());
        std::fprintf(stderr, "[!] pkexec не сработал: %s\n", std::strerror(errno));
    }

    // ---- Попытка 2: sudo env VAR=... app ----
    {
        std::vector<std::string> cmd;
        cmd.push_back("sudo");
        cmd.push_back("env");
        for (auto &kv : envPairs) cmd.push_back(kv);
        cmd.push_back(appPath);
        for (int i = 1; i < argc; ++i) cmd.push_back(argv[i]);

        std::vector<char *> cargv;
        cargv.reserve(cmd.size() + 1);
        for (auto &s : cmd) cargv.push_back(s.data());
        cargv.push_back(nullptr);

        std::fprintf(stderr, "[i] Требуются права администратора. Запускаю sudo...\n");
        std::fflush(stderr);
        ::execvp("sudo", cargv.data());
        std::fprintf(stderr, "[!] sudo не сработал: %s\n", std::strerror(errno));
    }

    std::fprintf(stderr, "[x] Нет pkexec/sudo. Запусти вручную: sudo -E %s\n", appPath.c_str());
    return false;
}

static void restoreUserHome() {
    if (::geteuid() != 0) return;
    struct passwd *pw = nullptr;
    if (const char *su = ::getenv("SUDO_USER")) pw = ::getpwnam(su);
    else if (const char *uid = ::getenv("PKEXEC_UID")) pw = ::getpwuid(static_cast<uid_t>(std::atoi(uid)));
    if (!pw || !pw->pw_dir) return;
    const std::string home = pw->pw_dir;
    ::setenv("HOME", home.c_str(), 1);
    if (!::getenv("XDG_CONFIG_HOME")) ::setenv("XDG_CONFIG_HOME", (home + "/.config").c_str(), 1);
    if (!::getenv("XDG_DATA_HOME"))   ::setenv("XDG_DATA_HOME",   (home + "/.local/share").c_str(), 1);
    if (!::getenv("XDG_CACHE_HOME"))  ::setenv("XDG_CACHE_HOME",  (home + "/.cache").c_str(), 1);
}

static void recoverSessionEnv() {
    if (::getenv("DISPLAY") || ::getenv("WAYLAND_DISPLAY")) return;
    const char *su = ::getenv("SUDO_USER");
    if (!su || !*su) return;
    struct passwd *pw = ::getpwnam(su);
    if (!pw) return;

    DIR *d = ::opendir("/proc");
    if (!d) return;
    struct dirent *de;
    while ((de = ::readdir(d)) != nullptr) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        const pid_t pid = static_cast<pid_t>(std::atoi(de->d_name));
        if (pid <= 0) continue;

        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%d", pid);
        struct stat st{};
        if (::stat(path, &st) != 0) continue;
        if (st.st_uid != pw->pw_uid) continue;

        std::snprintf(path, sizeof(path), "/proc/%d/environ", pid);
        FILE *f = std::fopen(path, "r");
        if (!f) continue;
        std::vector<char> buf(65536);
        const size_t got = std::fread(buf.data(), 1, buf.size() - 1, f);
        std::fclose(f);
        if (got == 0) continue;
        buf[got] = '\0';

        for (size_t i = 0; i < got; ) {
            const char *entry = buf.data() + i;
            const size_t len = std::strlen(entry);
            if (len > 8 && std::strncmp(entry, "DISPLAY=", 8) == 0) {
                if (!::getenv("DISPLAY")) ::setenv("DISPLAY", entry + 8, 0);
            } else if (len > 16 && std::strncmp(entry, "WAYLAND_DISPLAY=", 16) == 0) {
                if (!::getenv("WAYLAND_DISPLAY")) ::setenv("WAYLAND_DISPLAY", entry + 16, 0);
            } else if (len > 11 && std::strncmp(entry, "XAUTHORITY=", 11) == 0) {
                if (!::getenv("XAUTHORITY")) ::setenv("XAUTHORITY", entry + 11, 0);
            } else if (len > 15 && std::strncmp(entry, "XDG_RUNTIME_DIR=", 15) == 0) {
                if (!::getenv("XDG_RUNTIME_DIR")) ::setenv("XDG_RUNTIME_DIR", entry + 15, 0);
            } else if (len > 25 && std::strncmp(entry, "DBUS_SESSION_BUS_ADDRESS=", 25) == 0) {
                if (!::getenv("DBUS_SESSION_BUS_ADDRESS"))
                    ::setenv("DBUS_SESSION_BUS_ADDRESS", entry + 25, 0);
            }
            i += len + 1;
        }
        if (::getenv("DISPLAY") || ::getenv("WAYLAND_DISPLAY")) break;
    }
    ::closedir(d);
}

static bool haveDisplay() {
    return ::getenv("DISPLAY") || ::getenv("WAYLAND_DISPLAY") || ::getenv("QT_QPA_PLATFORM");
}

// ==================== Применение GTK-темы (аналог apply_global_gtk_theme) ====================
static void applyGlobalTheme(QApplication &app) {
    QStringList paths;
    if (const char *xdg = ::getenv("XDG_CONFIG_HOME"))
        paths << QString::fromUtf8(xdg) + QStringLiteral("/gtk-3.0/settings.ini");
    if (const char *home = ::getenv("HOME"))
        paths << QString::fromUtf8(home) + QStringLiteral("/.config/gtk-3.0/settings.ini");
    paths << QStringLiteral("/etc/gtk-3.0/settings.ini");

    QString chosen;
    for (const QString &p : paths) {
        if (QFile::exists(p)) { chosen = p; break; }
    }
    if (chosen.isEmpty()) return;

    QSettings s(chosen, QSettings::IniFormat);
    s.beginGroup(QStringLiteral("Settings"));

    const QString fontStr = s.value(QStringLiteral("gtk-font-name")).toString();
    if (!fontStr.isEmpty()) {
        const int lastSpace = fontStr.lastIndexOf(QLatin1Char(' '));
        if (lastSpace > 0) {
            bool ok = false;
            const int size = fontStr.mid(lastSpace + 1).toInt(&ok);
            if (ok && size > 0) {
                QFont f(fontStr.left(lastSpace), size);
                app.setFont(f);
            }
        }
    }

    bool dark = s.value(QStringLiteral("gtk-application-prefer-dark-theme"), false).toBool();
    const QString themeName = s.value(QStringLiteral("gtk-theme-name")).toString();
    if (themeName.contains(QLatin1String("dark"), Qt::CaseInsensitive))
        dark = true;

    s.endGroup();

    if (dark) {
        app.setStyle(QStringLiteral("Fusion"));
        QPalette pal;
        pal.setColor(QPalette::Window,          QColor(53, 53, 53));
        pal.setColor(QPalette::WindowText,      Qt::white);
        pal.setColor(QPalette::Base,            QColor(42, 42, 42));
        pal.setColor(QPalette::AlternateBase,   QColor(66, 66, 66));
        pal.setColor(QPalette::ToolTipBase,     QColor(53, 53, 53));
        pal.setColor(QPalette::ToolTipText,     Qt::white);
        pal.setColor(QPalette::Text,            Qt::white);
        pal.setColor(QPalette::Button,          QColor(53, 53, 53));
        pal.setColor(QPalette::ButtonText,      Qt::white);
        pal.setColor(QPalette::BrightText,      Qt::red);
        pal.setColor(QPalette::Link,            QColor(42, 130, 218));
        pal.setColor(QPalette::Highlight,       QColor(42, 130, 218));
        pal.setColor(QPalette::HighlightedText, Qt::black);
        pal.setColor(QPalette::Disabled, QPalette::Text,       QColor(127, 127, 127));
        pal.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(127, 127, 127));
        app.setPalette(pal);
    }
}

// ==================== FlowLayout (аналог Gtk.FlowBox) ====================
class FlowLayout : public QLayout {
public:
    explicit FlowLayout(QWidget *parent = nullptr, int hSpace = 5, int vSpace = 5)
        : QLayout(parent), m_h(hSpace), m_v(vSpace) { setContentsMargins(5, 5, 5, 5); }
    ~FlowLayout() override { while (QLayoutItem *it = takeAt(0)) delete it; }
    void addItem(QLayoutItem *item) override { m_items.append(item); }
    int count() const override { return m_items.size(); }
    QLayoutItem *itemAt(int i) const override { return m_items.value(i); }
    QLayoutItem *takeAt(int i) override { return m_items.takeAt(i); }
    Qt::Orientations expandingDirections() const override { return {}; }
    bool hasHeightForWidth() const override { return true; }
    int heightForWidth(int w) const override { return doLayout(QRect(0, 0, w, 0), true); }
    QSize sizeHint() const override { return minimumSize(); }
    QSize minimumSize() const override {
        QSize s;
        for (const QLayoutItem *it : m_items) s = s.expandedTo(it->minimumSize());
        int l, t, r, b; getContentsMargins(&l, &t, &r, &b);
        return s + QSize(l + r, t + b);
    }
    void setGeometry(const QRect &rect) override { QLayout::setGeometry(rect); doLayout(rect, false); }
private:
    int doLayout(const QRect &rect, bool testOnly) const {
        int l, t, r, b; getContentsMargins(&l, &t, &r, &b);
        const QRect eff = rect.adjusted(l, t, -r, -b);
        int x = eff.x(), y = eff.y(), lineH = 0;
        for (QLayoutItem *it : m_items) {
            const QSize sz = it->sizeHint();
            int nextX = x + sz.width() + m_h;
            if (nextX - m_h > eff.right() && lineH > 0) {
                x = eff.x(); y = y + lineH + m_v; lineH = 0;
                nextX = x + sz.width() + m_h;
            }
            if (!testOnly) it->setGeometry(QRect(QPoint(x, y), sz));
            x = nextX; lineH = qMax(lineH, sz.height());
        }
        return y + lineH - rect.y() + b;
    }
    QList<QLayoutItem *> m_items;
    int m_h, m_v;
};

// ==================== LogView ====================
class LogView : public QTextEdit {
    Q_OBJECT
public:
    explicit LogView(QWidget *parent = nullptr) : QTextEdit(parent) {
        setReadOnly(true);
        setWordWrapMode(QTextOption::WrapAnywhere);
        QFont f(QStringLiteral("Monospace"), 9);
        f.setStyleHint(QFont::Monospace);
        setFont(f);
    }
    void append(const QString &msg, const QString &level = QStringLiteral("info")) {
        if (thread() != QThread::currentThread()) {
            QMetaObject::invokeMethod(this, [this, msg, level] { appendImpl(msg, level); },
                                      Qt::QueuedConnection);
            return;
        }
        appendImpl(msg, level);
    }
    void appendImpl(const QString &msg, const QString &level) {
        const QString ts = QDateTime::currentDateTime().toString("hh:mm:ss");
        moveCursor(QTextCursor::End);
        insertHtml(QStringLiteral("<span style=\"color:#888888\">[%1] </span>"
                                  "<span style=\"color:%2\">%3</span><br>")
                       .arg(ts, colorFor(level), msg.toHtmlEscaped()));
        verticalScrollBar()->setValue(verticalScrollBar()->maximum());
    }
private:
    static QString colorFor(const QString &lvl) {
        if (lvl == QLatin1String("success")) return QStringLiteral("#4ade80");
        if (lvl == QLatin1String("warning")) return QStringLiteral("#fbbf24");
        if (lvl == QLatin1String("error"))   return QStringLiteral("#ef4444");
        return QStringLiteral("#60a5fa");
    }
};

// ==================== Разбор пакетов (расширенный) ====================
struct PktFields {
    bool ok = false;

    // Ethernet
    uchar ethDst[6] = {0}, ethSrc[6] = {0};
    quint16 ethType = 0;

    // VLAN 802.1Q (optional)
    bool hasVlan = false;
    quint16 vlanId = 0, vlanInnerType = 0;

    // ARP
    bool hasArp = false;
    quint16 arpOp = 0;
    uchar arpSha[6] = {0};
    quint32 arpSpa = 0;
    uchar arpTha[6] = {0};
    quint32 arpTpa = 0;

    // IPv4
    bool hasIp = false;
    quint8 ipVersion = 4;
    quint8 ihl = 5;
    quint8 dscp = 0, ecn = 0;
    quint16 ipTotalLen = 0, ipId = 0;
    quint8 ipFlags = 0;
    quint16 ipFragOff = 0;
    quint8 ttl = 64, ipProto = 0;
    quint32 ipSrc = 0, ipDst = 0;

    // IPv6
    bool hasIp6 = false;
    quint8 hopLimit = 64, nextHeader = 0;
    QByteArray ip6Src, ip6Dst;

    // L4
    bool hasTcp = false, hasUdp = false, hasIcmp = false, hasIcmp6 = false;
    quint16 srcPort = 0, dstPort = 0, tcpFlags = 0, tcpWin = 0;
    quint32 tcpSeq = 0, tcpAck = 0;
    QByteArray tcpOptions;
    quint16 udpLen = 0;
    quint8 icmpType = 0, icmpCode = 0;
    QByteArray payload;
};

static PktFields parsePacket(const QByteArray &raw) {
    PktFields f;
    const int n = raw.size();
    if (n < 14) return f;
    const uchar *p = reinterpret_cast<const uchar *>(raw.constData());
    std::memcpy(f.ethDst, p, 6);
    std::memcpy(f.ethSrc, p + 6, 6);
    f.ethType = quint16(p[12] << 8 | p[13]);
    f.ok = true;

    int off = 14;
    quint16 ethType = f.ethType;

    if (ethType == 0x8100 && n >= 18) {
        f.hasVlan = true;
        f.vlanId = quint16(((p[14] & 0x0f) << 8) | p[15]);
        f.vlanInnerType = quint16(p[16] << 8 | p[17]);
        off = 18;
        ethType = f.vlanInnerType;
    }

    if (ethType == 0x0806 && n >= off + 28) {
        f.hasArp = true;
        f.arpOp = quint16(p[off + 6] << 8 | p[off + 7]);
        std::memcpy(f.arpSha, p + off + 8, 6);
        f.arpSpa = quint32(p[off+14]<<24 | p[off+15]<<16 | p[off+16]<<8 | p[off+17]);
        std::memcpy(f.arpTha, p + off + 18, 6);
        f.arpTpa = quint32(p[off+24]<<24 | p[off+25]<<16 | p[off+26]<<8 | p[off+27]);
        return f;
    }

    if (ethType == 0x0800 && n >= off + 20) {
        f.hasIp = true;
        f.ipVersion = 4;
        f.ihl = p[off] & 0x0f;
        f.dscp = (p[off+1] >> 2) & 0x3f;
        f.ecn  = p[off+1] & 0x03;
        f.ipTotalLen = quint16(p[off+2] << 8 | p[off+3]);
        f.ipId = quint16(p[off+4] << 8 | p[off+5]);
        f.ipFlags = (p[off+6] >> 5) & 0x07;
        f.ipFragOff = quint16(((p[off+6] & 0x1f) << 8) | p[off+7]);
        f.ttl = p[off+8];
        f.ipProto = p[off+9];
        f.ipSrc = quint32(p[off+12]<<24 | p[off+13]<<16 | p[off+14]<<8 | p[off+15]);
        f.ipDst = quint32(p[off+16]<<24 | p[off+17]<<16 | p[off+18]<<8 | p[off+19]);
        const int l4 = off + f.ihl * 4;
        if (l4 >= n) return f;
        if (f.ipProto == 6 && l4 + 20 <= n) {
            f.hasTcp = true;
            f.srcPort = quint16(p[l4] << 8 | p[l4+1]);
            f.dstPort = quint16(p[l4+2] << 8 | p[l4+3]);
            f.tcpSeq = quint32(p[l4+4]<<24 | p[l4+5]<<16 | p[l4+6]<<8 | p[l4+7]);
            f.tcpAck = quint32(p[l4+8]<<24 | p[l4+9]<<16 | p[l4+10]<<8 | p[l4+11]);
            const int doff = ((p[l4+12] >> 4) & 0x0f) * 4;
            f.tcpFlags = quint16(((p[l4+12] & 0x01) << 8) | p[l4+13]);
            f.tcpWin = quint16(p[l4+14] << 8 | p[l4+15]);
            if (doff > 20 && l4 + doff <= n)
                f.tcpOptions = raw.mid(l4 + 20, doff - 20);
            if (doff > 0 && l4 + doff <= n) f.payload = raw.mid(l4 + doff);
        } else if (f.ipProto == 17 && l4 + 8 <= n) {
            f.hasUdp = true;
            f.srcPort = quint16(p[l4] << 8 | p[l4+1]);
            f.dstPort = quint16(p[l4+2] << 8 | p[l4+3]);
            f.udpLen = quint16(p[l4+4] << 8 | p[l4+5]);
            f.payload = raw.mid(l4 + 8);
        } else if (f.ipProto == 1 && l4 + 8 <= n) {
            f.hasIcmp = true;
            f.icmpType = p[l4];
            f.icmpCode = p[l4+1];
            f.payload = raw.mid(l4 + 8);
        }
        return f;
    }

    if (ethType == 0x86DD && n >= off + 40) {
        f.hasIp6 = true;
        f.ipVersion = 6;
        f.dscp = (p[off] >> 2) & 0x3f;
        f.ecn  = ((p[off] & 0x03) << 2) | (p[off+1] >> 6);
        f.nextHeader = p[off+6];
        f.hopLimit = p[off+7];
        f.ip6Src = raw.mid(off + 8, 16);
        f.ip6Dst = raw.mid(off + 24, 16);
        const int l4 = off + 40;
        if (l4 >= n) return f;
        if (f.nextHeader == 6 && l4 + 20 <= n) {
            f.hasTcp = true;
            f.srcPort = quint16(p[l4] << 8 | p[l4+1]);
            f.dstPort = quint16(p[l4+2] << 8 | p[l4+3]);
            f.tcpSeq = quint32(p[l4+4]<<24 | p[l4+5]<<16 | p[l4+6]<<8 | p[l4+7]);
            f.tcpAck = quint32(p[l4+8]<<24 | p[l4+9]<<16 | p[l4+10]<<8 | p[l4+11]);
            const int doff = ((p[l4+12] >> 4) & 0x0f) * 4;
            f.tcpFlags = quint16(((p[l4+12] & 0x01) << 8) | p[l4+13]);
            f.tcpWin = quint16(p[l4+14] << 8 | p[l4+15]);
            if (doff > 20 && l4 + doff <= n)
                f.tcpOptions = raw.mid(l4 + 20, doff - 20);
            if (doff > 0 && l4 + doff <= n) f.payload = raw.mid(l4 + doff);
        } else if (f.nextHeader == 17 && l4 + 8 <= n) {
            f.hasUdp = true;
            f.srcPort = quint16(p[l4] << 8 | p[l4+1]);
            f.dstPort = quint16(p[l4+2] << 8 | p[l4+3]);
            f.udpLen = quint16(p[l4+4] << 8 | p[l4+5]);
            f.payload = raw.mid(l4 + 8);
        } else if (f.nextHeader == 58 && l4 + 8 <= n) {
            f.hasIcmp6 = true;
            f.icmpType = p[l4];
            f.icmpCode = p[l4+1];
            f.payload = raw.mid(l4 + 8);
        }
        return f;
    }

    return f;
}

static quint16 checksum16(const QByteArray &d) {
    quint32 sum = 0;
    const uchar *p = reinterpret_cast<const uchar *>(d.constData());
    int i = 0;
    for (; i + 1 < d.size(); i += 2) sum += quint16(quint16(p[i]) << 8 | p[i + 1]);
    if (i < d.size()) sum += quint16(quint16(p[i]) << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return quint16(~sum);
}

static QString macToStr(const uchar *m) {
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(m[0], 2, 16, QLatin1Char('0')).arg(m[1], 2, 16, QLatin1Char('0'))
        .arg(m[2], 2, 16, QLatin1Char('0')).arg(m[3], 2, 16, QLatin1Char('0'))
        .arg(m[4], 2, 16, QLatin1Char('0')).arg(m[5], 2, 16, QLatin1Char('0'));
}

static void macFromStr(const QString &s, uchar *out) {
    std::memset(out, 0, 6);
    const QStringList parts = s.split(':');
    for (int i = 0; i < qMin(6, parts.size()); ++i)
        out[i] = static_cast<uchar>(parts[i].toUShort(nullptr, 16) & 0xff);
}

static quint32 ipFromStr(const QString &s) {
    in_addr a{};
    if (::inet_pton(AF_INET, s.toUtf8().constData(), &a) != 1) return 0;
    return ntohl(a.s_addr);
}

static QString ipToStr(quint32 ip) {
    return QString("%1.%2.%3.%4")
        .arg(ip >> 24).arg((ip >> 16) & 0xff).arg((ip >> 8) & 0xff).arg(ip & 0xff);
}

static QString ipv6ToStr(const QByteArray &b) {
    if (b.size() != 16) return QStringLiteral("::");
    char buf[INET6_ADDRSTRLEN] = {0};
    if (!::inet_ntop(AF_INET6, b.constData(), buf, sizeof(buf)))
        return QStringLiteral("::");
    return QString::fromUtf8(buf);
}

static QByteArray ipv6FromStr(const QString &s) {
    QByteArray out(16, char(0));
    if (::inet_pton(AF_INET6, s.toUtf8().constData(), out.data()) != 1)
        return QByteArray(16, char(0));
    return out;
}

static QString tcpFlagsToStr(quint16 f) {
    QString s;
    if (f & 0x100) s += 'N';
    if (f & 0x080) s += 'C';
    if (f & 0x040) s += 'E';
    if (f & 0x020) s += 'U';
    if (f & 0x010) s += 'A';
    if (f & 0x008) s += 'P';
    if (f & 0x004) s += 'R';
    if (f & 0x002) s += 'S';
    if (f & 0x001) s += 'F';
    return s.isEmpty() ? QStringLiteral("-") : s;
}

// ==================== Перехват пакетов ====================
struct CapturedInfo {
    int num = 0;
    QString time, src, dst, proto;
    bool isResp = false;
    QByteArray raw;
};
Q_DECLARE_METATYPE(CapturedInfo)

class SnifferThread : public QThread {
    Q_OBJECT
public:
    SnifferThread(QString iface, QString bpf, QObject *parent = nullptr)
        : QThread(parent), m_iface(std::move(iface)), m_bpf(std::move(bpf)) {}
    void stop() { m_stop = true; }
signals:
    void packet(const CapturedInfo &info);
protected:
    void run() override {
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_t *h = pcap_open_live(m_iface.toUtf8().constData(), 65535, 1, 200, errbuf);
        if (!h) return;
        if (!m_bpf.isEmpty()) {
            bpf_program fp{};
            if (pcap_compile(h, &fp, m_bpf.toUtf8().constData(), 0, PCAP_NETMASK_UNKNOWN) == 0) {
                (void)pcap_setfilter(h, &fp);
                pcap_freecode(&fp);
            }
        }
        int num = 0;
        pcap_pkthdr *hdr = nullptr;
        const u_char *data = nullptr;
        while (!m_stop) {
            const int r = pcap_next_ex(h, &hdr, &data);
            if (r == 1) {
                CapturedInfo ci;
                ci.num = ++num;
                ci.time = QDateTime::fromMSecsSinceEpoch(
                              qint64(hdr->ts.tv_sec) * 1000 + hdr->ts.tv_usec / 1000)
                              .toString("hh:mm:ss.zzz");
                ci.raw = QByteArray(reinterpret_cast<const char *>(data), hdr->caplen);
                const PktFields f = parsePacket(ci.raw);
                ci.src = ci.dst = QStringLiteral("N/A");
                ci.proto = QStringLiteral("N/A");

                if (f.hasIp)        { ci.src = ipToStr(f.ipSrc);  ci.dst = ipToStr(f.ipDst); }
                else if (f.hasIp6)  { ci.src = ipv6ToStr(f.ip6Src); ci.dst = ipv6ToStr(f.ip6Dst); }

                if (f.hasTcp)        { ci.proto = QStringLiteral("TCP");  ci.isResp = (f.tcpFlags & 0x10) != 0; }
                else if (f.hasUdp)   { ci.proto = QStringLiteral("UDP");  ci.isResp = true; }
                else if (f.hasIcmp)  { ci.proto = QStringLiteral("ICMP"); ci.isResp = true; }
                else if (f.hasIcmp6) { ci.proto = QStringLiteral("ICMPv6"); ci.isResp = true; }
                else if (f.hasArp)   { ci.proto = QStringLiteral("ARP");  ci.isResp = (f.arpOp == 2); }
                else if (f.ok)       { ci.proto = QStringLiteral("0x%1").arg(f.ethType, 4, 16, QLatin1Char('0')); }

                emit packet(ci);
            } else if (r == -1) {
                break;
            }
        }
        pcap_close(h);
    }
private:
    QString m_iface, m_bpf;
    std::atomic<bool> m_stop{false};
};

// ==================== Полный scapy-подобный дамп ====================
static QString dumpPacket(const QByteArray &raw) {
    const PktFields f = parsePacket(raw);
    QStringList out;

    auto hexline = [](const QByteArray &b) {
        QString s;
        for (int i = 0; i < b.size(); ++i)
            s += QString("%1 ").arg(quint8(b[i]), 2, 16, QLatin1Char('0'));
        return s.trimmed();
    };

    const QString etherTypeName =
        f.ethType == 0x0800 ? QStringLiteral("IPv4") :
        f.ethType == 0x0806 ? QStringLiteral("ARP")  :
        f.ethType == 0x86DD ? QStringLiteral("IPv6") :
        f.ethType == 0x8100 ? QStringLiteral("802.1Q") :
        QString("0x%1").arg(f.ethType, 4, 16, QLatin1Char('0'));

    out << QStringLiteral("###[ Ethernet ]###");
    out << QStringLiteral("  dst       = %1").arg(macToStr(f.ethDst));
    out << QStringLiteral("  src       = %1").arg(macToStr(f.ethSrc));
    out << QStringLiteral("  type      = %1").arg(etherTypeName);

    if (f.hasVlan) {
        out << QStringLiteral("###[ 802.1Q ]###");
        out << QStringLiteral("     prio      = 0");
        out << QStringLiteral("     dei       = 0");
        out << QStringLiteral("     vlan      = %1").arg(f.vlanId);
        out << QStringLiteral("     type      = 0x%1")
                   .arg(f.vlanInnerType, 4, 16, QLatin1Char('0'));
    }

    if (f.hasArp) {
        out << QStringLiteral("###[ ARP ]###");
        out << QStringLiteral("     hwtype    = 0x1");
        out << QStringLiteral("     ptype     = IPv4");
        out << QStringLiteral("     hwlen     = 6");
        out << QStringLiteral("     plen      = 4");
        out << QStringLiteral("     op        = %1").arg(f.arpOp == 1 ? QStringLiteral("who-has")
                                        : f.arpOp == 2 ? QStringLiteral("is-at")
                                        : QString::number(f.arpOp));
        out << QStringLiteral("     hwsrc     = %1").arg(macToStr(f.arpSha));
        out << QStringLiteral("     psrc      = %1").arg(ipToStr(f.arpSpa));
        out << QStringLiteral("     hwdst     = %1").arg(macToStr(f.arpTha));
        out << QStringLiteral("     pdst      = %1").arg(ipToStr(f.arpTpa));
        return out.join('\n');
    }

    if (f.hasIp) {
        const QString protoName =
            f.ipProto == 6  ? QStringLiteral("tcp")  :
            f.ipProto == 17 ? QStringLiteral("udp")  :
            f.ipProto == 1  ? QStringLiteral("icmp") :
            QString::number(f.ipProto);

        out << QStringLiteral("###[ IP ]###");
        out << QStringLiteral("     version   = 4");
        out << QStringLiteral("     ihl       = %1").arg(f.ihl);
        out << QStringLiteral("     tos       = 0x%1").arg(f.dscp, 2, 16, QLatin1Char('0'));
        out << QStringLiteral("     len       = %1").arg(f.ipTotalLen);
        out << QStringLiteral("     id        = %1").arg(f.ipId);
        out << QStringLiteral("     flags     = %1")
                   .arg((f.ipFlags & 0x02) ? QStringLiteral("DF")
                      : (f.ipFlags & 0x01) ? QStringLiteral("MF") : QString());
        out << QStringLiteral("     frag      = %1").arg(f.ipFragOff);
        out << QStringLiteral("     ttl       = %1").arg(f.ttl);
        out << QStringLiteral("     proto     = %1").arg(protoName);
        out << QStringLiteral("     chksum    = 0x%1")
                   .arg(quint16(quint8(raw.size() > 24 ? raw[24] : 0) << 8 |
                                quint8(raw.size() > 25 ? raw[25] : 0)), 4, 16, QLatin1Char('0'));
        out << QStringLiteral("     src       = %1").arg(ipToStr(f.ipSrc));
        out << QStringLiteral("     dst       = %1").arg(ipToStr(f.ipDst));
    }

    if (f.hasIp6) {
        const QString nhName =
            f.nextHeader == 6  ? QStringLiteral("tcp")    :
            f.nextHeader == 17 ? QStringLiteral("udp")    :
            f.nextHeader == 58 ? QStringLiteral("icmpv6") :
            QString::number(f.nextHeader);
        out << QStringLiteral("###[ IPv6 ]###");
        out << QStringLiteral("     version   = 6");
        out << QStringLiteral("     tc        = 0x%1").arg(f.dscp, 2, 16, QLatin1Char('0'));
        out << QStringLiteral("     fl        = 0x0");
        out << QStringLiteral("     plen      = %1").arg(
                   quint16(quint8(raw.size() > 18 ? raw[18] : 0) << 8 |
                           quint8(raw.size() > 19 ? raw[19] : 0)));
        out << QStringLiteral("     nh        = %1").arg(nhName);
        out << QStringLiteral("     hlim      = %1").arg(f.hopLimit);
        out << QStringLiteral("     src       = %1").arg(ipv6ToStr(f.ip6Src));
        out << QStringLiteral("     dst       = %1").arg(ipv6ToStr(f.ip6Dst));
    }

    if (f.hasTcp) {
        out << QStringLiteral("###[ TCP ]###");
        out << QStringLiteral("        sport     = %1").arg(f.srcPort);
        out << QStringLiteral("        dport     = %1").arg(f.dstPort);
        out << QStringLiteral("        seq       = %1").arg(f.tcpSeq);
        out << QStringLiteral("        ack       = %1").arg(f.tcpAck);
        out << QStringLiteral("        dataofs   = %1").arg(f.tcpOptions.isEmpty() ? 5 : 5 + f.tcpOptions.size() / 4);
        out << QStringLiteral("        reserved  = 0");
        out << QStringLiteral("        flags     = %1").arg(tcpFlagsToStr(f.tcpFlags));
        out << QStringLiteral("        window    = %1").arg(f.tcpWin);
        out << QStringLiteral("        urgptr    = 0");
        if (!f.tcpOptions.isEmpty())
            out << QStringLiteral("        options   = %1").arg(hexline(f.tcpOptions));
    }

    if (f.hasUdp) {
        out << QStringLiteral("###[ UDP ]###");
        out << QStringLiteral("           sport     = %1").arg(f.srcPort);
        out << QStringLiteral("           dport     = %1").arg(f.dstPort);
        out << QStringLiteral("           len       = %1").arg(f.udpLen);
    }

    if (f.hasIcmp) {
        static const QMap<quint8, QString> types = {
            {0, QStringLiteral("echo-reply")},
            {3, QStringLiteral("dest-unreach")},
            {5, QStringLiteral("redirect")},
            {8, QStringLiteral("echo-request")},
            {11, QStringLiteral("time-exceeded")},
        };
        out << QStringLiteral("###[ ICMP ]###");
        out << QStringLiteral("           type      = %1").arg(types.value(f.icmpType, QString::number(f.icmpType)));
        out << QStringLiteral("           code      = %1").arg(f.icmpCode);
    }

    if (f.hasIcmp6) {
        out << QStringLiteral("###[ ICMPv6 ]###");
        out << QStringLiteral("           type      = %1").arg(f.icmpType);
        out << QStringLiteral("           code      = %1").arg(f.icmpCode);
    }

    if (!f.payload.isEmpty()) {
        out << QStringLiteral("###[ Raw ]###");
        out << QStringLiteral("           load      = %1").arg(hexline(f.payload));
    }

    out << QStringLiteral("");
    out << QStringLiteral("=== Hex dump ===");
    for (int i = 0; i < raw.size(); i += 16)
        out << QString::number(i, 16).rightJustified(4, QLatin1Char('0')) + QStringLiteral("  ") +
                 QString(raw.mid(i, 16).toHex(' '));

    return out.join('\n');
}

// ==================== Редактор пакета (IPv4 + IPv6) ====================
class PacketEditor : public QDialog {
    Q_OBJECT
public:
    explicit PacketEditor(const QByteArray &raw, QWidget *parent = nullptr)
        : QDialog(parent), m_raw(raw) {
        setWindowTitle(QStringLiteral("Редактор пакета"));
        resize(680, 640);
        QVBoxLayout *v = new QVBoxLayout(this);
        v->setContentsMargins(10, 10, 10, 10);
        v->setSpacing(5);

        auto frame = [&v](const QString &title) {
            QGroupBox *g = new QGroupBox(title);
            QGridLayout *gr = new QGridLayout(g);
            gr->setContentsMargins(5, 5, 5, 5);
            gr->setHorizontalSpacing(10);
            gr->setVerticalSpacing(5);
            v->addWidget(g);
            return gr;
        };
        auto row = [](QGridLayout *g, int r, const QString &lbl, QWidget *w) {
            g->addWidget(new QLabel(lbl), r, 0);
            g->addWidget(w, r, 1);
        };

        QGridLayout *g = frame(QStringLiteral("Ethernet"));
        m_ethSrc = new QLineEdit; m_ethDst = new QLineEdit;
        row(g, 0, QStringLiteral("Source MAC:"), m_ethSrc);
        row(g, 1, QStringLiteral("Dest MAC:"), m_ethDst);

        g = frame(QStringLiteral("IP"));
        m_ipVersion = new QComboBox;
        m_ipVersion->addItems({QStringLiteral("IPv4"), QStringLiteral("IPv6")});
        m_ipSrc = new QLineEdit; m_ipDst = new QLineEdit; m_ttl = new QLineEdit;
        row(g, 0, QStringLiteral("Version:"), m_ipVersion);
        row(g, 1, QStringLiteral("Source IP:"), m_ipSrc);
        row(g, 2, QStringLiteral("Dest IP:"), m_ipDst);
        row(g, 3, QStringLiteral("TTL / HopLimit:"), m_ttl);

        g = frame(QStringLiteral("Transport"));
        m_proto = new QComboBox;
        m_proto->addItems({QStringLiteral("TCP"), QStringLiteral("UDP"),
                           QStringLiteral("ICMP"), QStringLiteral("RAW")});
        m_srcPort = new QLineEdit; m_dstPort = new QLineEdit;
        row(g, 0, QStringLiteral("Protocol:"), m_proto);
        row(g, 1, QStringLiteral("Source Port:"), m_srcPort);
        row(g, 2, QStringLiteral("Dest Port:"), m_dstPort);

        QGroupBox *fb = new QGroupBox(QStringLiteral("TCP Flags"));
        FlowLayout *fl = new FlowLayout(fb);
        for (const QString &n : {QStringLiteral("FIN"), QStringLiteral("SYN"), QStringLiteral("RST"),
                                 QStringLiteral("PSH"), QStringLiteral("ACK"), QStringLiteral("URG"),
                                 QStringLiteral("ECE"), QStringLiteral("CWR")}) {
            QCheckBox *cb = new QCheckBox(n);
            m_flags.insert(n, cb);
            fl->addWidget(cb);
        }
        v->addWidget(fb);

        QGroupBox *pb = new QGroupBox(QStringLiteral("Payload (hex)"));
        QVBoxLayout *pv = new QVBoxLayout(pb);
        m_payload = new QTextEdit;
        m_payload->setFont(QFont(QStringLiteral("Monospace"), 9));
        pv->addWidget(m_payload);
        v->addWidget(pb, 1);

        QHBoxLayout *hb = new QHBoxLayout;
        hb->setSpacing(10);
        QPushButton *ok = new QPushButton(QStringLiteral("Применить"));
        QPushButton *no = new QPushButton(QStringLiteral("Отмена"));
        connect(ok, &QPushButton::clicked, this, &QDialog::accept);
        connect(no, &QPushButton::clicked, this, &QDialog::reject);
        hb->addWidget(ok); hb->addWidget(no);
        v->addLayout(hb);

        prefill();
    }

    QByteArray buildPacket() const {
        QByteArray out(14, char(0));
        uchar *e = reinterpret_cast<uchar *>(out.data());
        macFromStr(m_ethDst->text(), e);
        macFromStr(m_ethSrc->text(), e + 6);
        const QString proto = m_proto->currentText();
        const QByteArray pay = QByteArray::fromHex(
            m_payload->toPlainText().remove(QLatin1Char(' ')).remove(QLatin1Char('\n')).toLatin1());
        if (proto == QLatin1String("RAW")) {
            e[12] = 0x90; e[13] = 0x00;
            out.append(pay);
            return out;
        }

        const bool v6 = (m_ipVersion->currentIndex() == 1);
        e[12] = v6 ? 0x86 : 0x08;
        e[13] = v6 ? 0xDD : 0x00;

        const quint8 ipProto = proto == QLatin1String("TCP") ? 6
                             : proto == QLatin1String("UDP") ? 17 : 1;
        QByteArray l4;
        if (ipProto == 6) {
            l4.append(20, char(0));
            uchar *t = reinterpret_cast<uchar *>(l4.data());
            const quint16 sp = m_srcPort->text().toUShort(), dp = m_dstPort->text().toUShort();
            t[0] = uchar(sp >> 8); t[1] = uchar(sp & 0xff);
            t[2] = uchar(dp >> 8); t[3] = uchar(dp & 0xff);
            t[12] = uchar(5 << 4);
            quint8 fl = 0;
            auto on = [this](const QString &n) {
                auto it = m_flags.find(n);
                return it != m_flags.end() && it.value()->isChecked();
            };
            if (on(QStringLiteral("FIN"))) fl |= 0x01;
            if (on(QStringLiteral("SYN"))) fl |= 0x02;
            if (on(QStringLiteral("RST"))) fl |= 0x04;
            if (on(QStringLiteral("PSH"))) fl |= 0x08;
            if (on(QStringLiteral("ACK"))) fl |= 0x10;
            if (on(QStringLiteral("URG"))) fl |= 0x20;
            if (on(QStringLiteral("ECE"))) fl |= 0x40;
            if (on(QStringLiteral("CWR"))) fl |= 0x80;
            t[13] = fl;
            t[14] = 0xff; t[15] = 0xff;
            l4.append(pay);
        } else if (ipProto == 17) {
            l4.append(8, char(0));
            uchar *u = reinterpret_cast<uchar *>(l4.data());
            const quint16 sp = m_srcPort->text().toUShort(), dp = m_dstPort->text().toUShort();
            u[0] = uchar(sp >> 8); u[1] = uchar(sp & 0xff);
            u[2] = uchar(dp >> 8); u[3] = uchar(dp & 0xff);
            const quint16 ln = quint16(8 + pay.size());
            u[4] = uchar(ln >> 8); u[5] = uchar(ln & 0xff);
            l4.append(pay);
        } else {
            l4.append(8, char(0));
            l4.append(pay);
        }

        if (v6) {
            QByteArray ip6(40, char(0));
            uchar *ih = reinterpret_cast<uchar *>(ip6.data());
            ih[0] = 0x60;
            const quint16 plen = quint16(l4.size());
            ih[4] = uchar(plen >> 8); ih[5] = uchar(plen & 0xff);
            ih[6] = ipProto;
            ih[7] = uchar(m_ttl->text().toUShort() & 0xff);
            const QByteArray s = ipv6FromStr(m_ipSrc->text());
            const QByteArray d = ipv6FromStr(m_ipDst->text());
            std::memcpy(ip6.data() + 8,  s.constData(), 16);
            std::memcpy(ip6.data() + 24, d.constData(), 16);
            out.append(ip6);
            out.append(l4);
            return out;
        }

        QByteArray ip(20, char(0));
        uchar *ih = reinterpret_cast<uchar *>(ip.data());
        ih[0] = 0x45;
        const quint16 total = quint16(20 + l4.size());
        ih[2] = uchar(total >> 8); ih[3] = uchar(total & 0xff);
        ih[8] = uchar(m_ttl->text().toUShort() & 0xff);
        ih[9] = ipProto;
        const quint32 s = ipFromStr(m_ipSrc->text()), d = ipFromStr(m_ipDst->text());
        ih[12] = uchar(s >> 24); ih[13] = uchar(s >> 16); ih[14] = uchar(s >> 8); ih[15] = uchar(s);
        ih[16] = uchar(d >> 24); ih[17] = uchar(d >> 16); ih[18] = uchar(d >> 8); ih[19] = uchar(d);
        const quint16 cs = checksum16(ip);
        ih[10] = uchar(cs >> 8); ih[11] = uchar(cs & 0xff);

        QByteArray pseudo(12, char(0));
        uchar *ps = reinterpret_cast<uchar *>(pseudo.data());
        ps[0] = uchar(s >> 24); ps[1] = uchar(s >> 16); ps[2] = uchar(s >> 8); ps[3] = uchar(s);
        ps[4] = uchar(d >> 24); ps[5] = uchar(d >> 16); ps[6] = uchar(d >> 8); ps[7] = uchar(d);
        ps[9] = ipProto;
        const quint16 l4len = quint16(l4.size());
        ps[10] = uchar(l4len >> 8); ps[11] = uchar(l4len & 0xff);
        const quint16 lc = checksum16(pseudo + l4);
        if (ipProto == 6) {
            uchar *t = reinterpret_cast<uchar *>(l4.data());
            t[16] = uchar(lc >> 8); t[17] = uchar(lc & 0xff);
        } else if (ipProto == 17) {
            uchar *u = reinterpret_cast<uchar *>(l4.data());
            u[6] = uchar(lc >> 8); u[7] = uchar(lc & 0xff);
        } else {
            uchar *ic = reinterpret_cast<uchar *>(l4.data());
            ic[0] = 8; ic[1] = 0;
            const quint16 cc = checksum16(l4);
            ic[2] = uchar(cc >> 8); ic[3] = uchar(cc & 0xff);
        }
        out.append(ip);
        out.append(l4);
        return out;
    }

private:
    void prefill() {
        const PktFields f = parsePacket(m_raw);
        if (!f.ok) return;
        m_ethSrc->setText(macToStr(f.ethSrc));
        m_ethDst->setText(macToStr(f.ethDst));
        if (f.hasIp) {
            m_ipVersion->setCurrentIndex(0);
            m_ipSrc->setText(ipToStr(f.ipSrc));
            m_ipDst->setText(ipToStr(f.ipDst));
            m_ttl->setText(QString::number(f.ttl));
        } else if (f.hasIp6) {
            m_ipVersion->setCurrentIndex(1);
            m_ipSrc->setText(ipv6ToStr(f.ip6Src));
            m_ipDst->setText(ipv6ToStr(f.ip6Dst));
            m_ttl->setText(QString::number(f.hopLimit));
        }
        if (f.hasTcp) {
            m_proto->setCurrentIndex(0);
            m_srcPort->setText(QString::number(f.srcPort));
            m_dstPort->setText(QString::number(f.dstPort));
            const quint8 fl = quint8(f.tcpFlags & 0xff);
            m_flags[QStringLiteral("FIN")]->setChecked(fl & 0x01);
            m_flags[QStringLiteral("SYN")]->setChecked(fl & 0x02);
            m_flags[QStringLiteral("RST")]->setChecked(fl & 0x04);
            m_flags[QStringLiteral("PSH")]->setChecked(fl & 0x08);
            m_flags[QStringLiteral("ACK")]->setChecked(fl & 0x10);
            m_flags[QStringLiteral("URG")]->setChecked(fl & 0x20);
            m_flags[QStringLiteral("ECE")]->setChecked(fl & 0x40);
            m_flags[QStringLiteral("CWR")]->setChecked(fl & 0x80);
        } else if (f.hasUdp) {
            m_proto->setCurrentIndex(1);
            m_srcPort->setText(QString::number(f.srcPort));
            m_dstPort->setText(QString::number(f.dstPort));
        } else if (f.hasIcmp || f.hasIcmp6) {
            m_proto->setCurrentIndex(2);
        }
        m_payload->setPlainText(QString(f.payload.toHex(' ')));
    }

    QByteArray m_raw;
    QLineEdit *m_ethSrc = nullptr, *m_ethDst = nullptr;
    QComboBox *m_ipVersion = nullptr;
    QLineEdit *m_ipSrc = nullptr, *m_ipDst = nullptr, *m_ttl = nullptr;
    QLineEdit *m_srcPort = nullptr, *m_dstPort = nullptr;
    QComboBox *m_proto = nullptr;
    QMap<QString, QCheckBox *> m_flags;
    QTextEdit *m_payload = nullptr;
};

// ==================== Пасхалка ====================
static const QStringList &smileyArt() {
    static const QStringList art = {
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠛⠛⢉⣉⣉⣉⣉⡙⠛⠛⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿",
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⣤⣶⣿⣿⣿⠿⠿⠿⠷⠶⢤⣄⡉⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿",
        "⣿⣿⣿⣿⣿⡿⢀⣴⣾⣿⣿⣿⣿⣉⣤⡴⠶⠶⣶⣶⣶⣾⣿⣷⣄⡈⠛⣿⣿⣿⣿⣿⣿⣿⣿",
        "⣿⣿⣿⣿⣿⣿⣿⠋⣴⣿⣿⣿⣿⣿⣿⢀⣶⣶⣬⣉⠻⣿⣿⣦⡀⣿⣿⣿⣿⣿⣿⣿⣿⣿",
        "⣿⣿⣿⣿⣿⡿⣠⠟⢋⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⣿⡿⣿⣷⢿⣿⣿⣿⣆⠈⣿⣿⣿⣿⣿⣿⣿",
        "⣿⣿⣿⠃⣰⡟⣴⣿⣿⣿⣿⣿⣿⣿⣿⡀⣿⣿⣇⣀⣼⣿⣿⡗⢸⣿⣿⣿⣿⣿⣷⡄⢿⣿⣿⣿⣿⣿",
        "⣿⣿⣿⣿⠇⣟⣴⣿⠥⠉⠻⣿⣿⣿⣿⣷⣜⢿⣿⣿⣿⣡⣾⣿⣿⣿⣿⣿⣿⣿⣆⠀⢻⣿⣿⣿",
        "⣿⣿⣿⣿⡿⠀⣾⣿⡟⣶⣿⣿⢿⣿⣷⣌⣿⣿⣿⣿⣿⣿⣿⣷⣬⣉⣉⣭⣴⣿⠟⣽⣿⣿⣿⣿⣿⣿⡄⠀⢻⣿⣿⣿",
        "⣿⣿⣿⠇⢀⣿⣿⣿⣀⣿⠀⢻⣿⣿⣿⣷⣍⢿⠟⣼⣿⣿⣿⣿⣿⡀⣿⣿",
        "⣿⣿⣿⠀⣿⣌⢿⣿⡿⢃⣴⡀⣿⣿⣿⣿⡻⣤⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⣿⣿⣿",
        "⣿⣿⠀⢸⣿⣿⣿⣿⣶⣶⣶⠶⣿⣷⠻⣿⣿⣿⣿⣶⣭⣶⣿⣿⣿⣿⣿⣿⣿⣿⠀⢸⣿⣿⣿",
        "⣿⣿⣿⠀⢸⣿⣿⣿⠿⣷⣦⣴⣶⣿⣿⣿⣿⣿⣷⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢛⣉⣴⣿⣿⠀⣿⣿",
        "⣿⣿⣿⠀⢸⣿⣿⣿⣷⣤⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⢛⣥⣾⣿⣿⣿⣿⠀⣿⣿",
        "⣿⣿⣿⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⣩⣶⣿⣿⣿⣿⣿⣿⣿⣿⠀⣿⣿⣿⣿⡟⣿⣿",
        "⣿⣿⣿⣿⡇⠈⣿⣿⣿⣿⣿⣿⣿⣿⠿⣛⣋⣭⣴⣶⣿⣿⣿⣿⣿⣿⠋⣿⣿⣿⣿⠃⣼⣿⣿⣿",
        "⣿⣿⣿⠀⢻⠿⠛⣛⣭⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⣥⠀⣿⣿⣿⡏⣿⣿⣿⣿⣿",
        "⣿⣿⣿⡄⣿⣧⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣫⣴⣿⣿⡟⣿⣿⣿⠀⣾⣿⣿⣿⣿",
        "⣿⣿⣿⣿⣧⠀⢻⣧⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣛⣫⣵⣿⣿⣿⡿⢀⣿⣿⠁⣿⣿⣿⣿",
        "⣿⣿⣿⣿⣿⣆⢿⣷⠛⠿⠿⠿⠟⣋⣭⣴⣿⣿⣿⣿⡿⣼⣿⣿⢠⣿⣿⣿⣿",
        "⣿⣿⣿⣿⣿⣿⠈⢿⣿⣿⣆⣿⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⠟⢀⣾⣿⣿⣿⢀⣿⣿⣿⣿⣿⣿⣿",
        "⣿⣿⣿⣿⣆⠈⠻⣿⡌⢿⣿⣿⣿⣿⣿⣿⣿⣿⠟⣴⣿⣿⣿⢀⣾⣿⣿⣿⣿",
        "⣿⣿⣿⣿⣿⣿⣦⠙⣿⣿⣷⣄⠻⣿⣿⣿⣿⠿⠛⣡⣴⣿⣿⠃⣾⣿⣿⣿⣿",
        "⣿⣿⣿⣿⣿⣿⣿⣦⠙⠿⣿⣿⣿⣶⣬⣉⣛⠛⢛⣥⣾⣿⣿⣿⠟⠁⣰⣿⣿⣿⣿⣿⣿⣿",
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣈⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⣾⣿⣿⣿⣿⣿⣿",
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣄⣉⣉⣛⣛⣛⣛⣛⣉⣉⣤⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿",
    };
    return art;
}

// ==================== Главное окно ====================
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow() {
        setWindowTitle(QStringLiteral("Gotcha Linux"));
        setMinimumSize(640, 480);

        QScreen *scr = QGuiApplication::primaryScreen();
        if (QGuiApplication::screens().size() > 1) {
            if (QScreen *at = QGuiApplication::screenAt(QCursor::pos())) scr = at;
        }
        QRect geo(0, 0, 1280, 800);
        if (scr) geo = scr->availableGeometry();

        int w = qBound(900, int(geo.width() * 0.85), 1400);
        int h = qBound(600, int(geo.height() * 0.85), 900);
        w = qMin(w, qMax(640, geo.width() - 40));
        h = qMin(h, qMax(480, geo.height() - 80));
        resize(w, h);
        m_shouldMaximize = geo.height() < 820;
        move(geo.center() - QPoint(w / 2, h / 2));

        QWidget *central = new QWidget(this);
        QVBoxLayout *main = new QVBoxLayout(central);
        main->setContentsMargins(10, 10, 10, 10);
        main->setSpacing(10);

        QLabel *header = new QLabel(QStringLiteral("Gotcha Linux"));
        QFont hf = header->font();
        hf.setPointSize(hf.pointSize() + 6);
        hf.setBold(true);
        header->setFont(hf);
        main->addWidget(header);

        m_tabs = new QTabWidget;
        m_tabs->setUsesScrollButtons(true);
        main->addWidget(m_tabs, 1);

        createAccessTab();
        createInterceptTab();
        createDhcpTab();
        createArpTab();
        createDosTab();
        createDnsTab();
        createMacTab();
        createHelpTab();

        QHBoxLayout *sbox = new QHBoxLayout;
        sbox->setSpacing(5);
        m_statusVar = new QLabel(QStringLiteral("Готов к работе"));
        m_statusVar->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        sbox->addWidget(m_statusVar, 1);
        QPushButton *stopAllBtn = new QPushButton(QStringLiteral("Остановить все"));
        connect(stopAllBtn, &QPushButton::clicked, this, [this] { stopAll(); });
        QPushButton *quitBtn = new QPushButton(QStringLiteral("Выход"));
        connect(quitBtn, &QPushButton::clicked, this, [this] { stopAll(); close(); });
        sbox->addWidget(stopAllBtn);
        sbox->addWidget(quitBtn);
        main->addLayout(sbox);

        setCentralWidget(central);
    }

    void present() { m_shouldMaximize ? showMaximized() : show(); }

protected:
    void closeEvent(QCloseEvent *ev) override { stopAll(); ev->accept(); }

private:
    struct AttackCtx {
        enum class Kind { Dhcp, Arp, Dos, Dns, Mac } kind = Kind::Dhcp;
        bool running = false;
        QProcess *proc = nullptr;
        QTimer *timer = nullptr;
        qint64 startMs = 0, lastUpdateMs = 0, lastSent = 0;
        qint64 sent = 0, uniqueMacs = 0, intercepted = 0, spoofed = 0, frames = 0;
        std::set<QString> offeredIps;
        LogView *log = nullptr;
        QLabel *status = nullptr;
        QLabel *sentLbl = nullptr, *uniqueLbl = nullptr, *ipsLbl = nullptr;
        QLabel *rateLbl = nullptr, *timeLbl = nullptr;
        QLabel *intLbl = nullptr, *spoofLbl = nullptr;
        QPushButton *startBtn = nullptr, *stopBtn = nullptr;
    };

    static QComboBox *ifaceCombo() {
        QComboBox *c = new QComboBox;
        for (const QNetworkInterface &i : QNetworkInterface::allInterfaces())
            if (i.flags().testFlag(QNetworkInterface::IsUp) &&
                !i.flags().testFlag(QNetworkInterface::IsLoopBack))
                c->addItem(i.name());
        if (c->count() == 0) c->addItems({QStringLiteral("eth0"), QStringLiteral("wlan0")});
        return c;
    }

    static QWidget *scrollWrap(QWidget *content) {
        QScrollArea *s = new QScrollArea;
        s->setWidgetResizable(true);
        s->setWidget(content);
        return s;
    }

    static QVBoxLayout *tabBox(QWidget *content) {
        QVBoxLayout *v = new QVBoxLayout(content);
        v->setContentsMargins(10, 10, 10, 10);
        v->setSpacing(5);
        return v;
    }

    void addSaveLogButton(QVBoxLayout *v, LogView *log) {
        QPushButton *b = new QPushButton(QStringLiteral("Сохранить лог"));
        connect(b, &QPushButton::clicked, this, [this, log] { saveLog(log); });
        v->addWidget(b, 0, Qt::AlignLeft);
    }

    void saveLog(LogView *log) {
        const QString fn = QFileDialog::getSaveFileName(
            this, QStringLiteral("Сохранить лог"),
            QDir::homePath() + QDir::separator() + QStringLiteral("log.txt"),
            QStringLiteral("Text (*.txt)"));
        if (fn.isEmpty()) return;
        QFile f(fn);
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            f.write(log->toPlainText().toUtf8());
            m_statusVar->setText(QStringLiteral("Лог сохранён"));
        } else {
            QMessageBox::warning(this, QStringLiteral("Ошибка"),
                                 QStringLiteral("Не удалось сохранить: %1").arg(f.errorString()));
        }
    }

    void showWarning(const QString &title, const QString &msg) {
        QMessageBox::warning(this, title, msg);
    }

    static QString findExe(const QString &name) {
        const QString appDir = QCoreApplication::applicationDirPath();
        const QString cwd = QDir::currentPath();
        const QStringList cand{appDir + "/bin/" + name, appDir + "/" + name,
                               cwd + "/bin/" + name, cwd + "/" + name};
        for (const QString &p : cand) {
            const QFileInfo fi(p);
            if (fi.isFile() && fi.isExecutable()) return p;
        }
        return {};
    }

    static QString ifaceIp(const QString &name) {
        const QNetworkInterface ni = QNetworkInterface::interfaceFromName(name);
        for (const QNetworkAddressEntry &e : ni.addressEntries())
            if (e.ip().protocol() == QAbstractSocket::IPv4Protocol)
                return e.ip().toString();
        return QStringLiteral("192.168.1.x");
    }

    static QString fmtTime(double sec) {
        const int h = int(sec) / 3600, m = (int(sec) % 3600) / 60, s = int(sec) % 60;
        return QString("%1:%2:%3").arg(h, 2, 10, QLatin1Char('0'))
               .arg(m, 2, 10, QLatin1Char('0')).arg(s, 2, 10, QLatin1Char('0'));
    }

    void runBinary(const QString &name, const QStringList &args, AttackCtx &c) {
        if (m_attackRunning) return;
        const QString path = findExe(name);
        if (path.isEmpty()) {
            c.log->append(QStringLiteral("Ошибка: бинарник %1 не найден").arg(name), "error");
            showWarning(QStringLiteral("Ошибка"),
                        QStringLiteral("Бинарник %1 не найден.\nПроверьте папку bin/.").arg(name));
            return;
        }
        c.log->append(QStringLiteral("Запуск: %1 %2").arg(path, args.join(' ')), "info");
        m_attackRunning = true;
        c.running = true;
        c.status->setText(QStringLiteral("Запущен..."));
        m_statusVar->setText(QStringLiteral("Атака выполняется..."));
        c.startBtn->setEnabled(false);
        c.stopBtn->setEnabled(true);

        AttackCtx *cp = &c;
        QProcess *proc = new QProcess(this);
        c.proc = proc;
        proc->setProcessChannelMode(QProcess::MergedChannels);
        connect(proc, &QProcess::readyReadStandardOutput, this, [this, proc, cp] {
            while (proc->canReadLine()) {
                const QString line = QString::fromUtf8(proc->readLine()).trimmed();
                if (!line.isEmpty()) {
                    cp->log->append(line, "info");
                    parseStats(line, *cp);
                }
            }
        });
        connect(proc, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
                this, [this, proc, cp](int rc, QProcess::ExitStatus st) {
            if (st == QProcess::CrashExit)
                cp->log->append(QStringLiteral("Атака остановлена пользователем"), "warning");
            else if (rc == 0)
                cp->status->setText(QStringLiteral("Завершено"));
            else {
                cp->log->append(QStringLiteral("Бинарник завершён с ошибкой (код %1)").arg(rc), "error");
                cp->status->setText(QStringLiteral("Ошибка"));
            }
            m_attackRunning = false;
            cp->running = false;
            cp->proc = nullptr;
            if (cp->timer) cp->timer->stop();
            m_statusVar->setText(QStringLiteral("Готов"));
            cp->startBtn->setEnabled(true);
            cp->stopBtn->setEnabled(false);
            proc->deleteLater();
        });
        proc->start(path, args);
        if (!proc->waitForStarted(3000)) {
            c.log->append(QStringLiteral("Ошибка: не удалось запустить процесс"), "error");
            c.status->setText(QStringLiteral("Ошибка"));
        } else {
            c.log->append(QStringLiteral("Процесс запущен (PID=%1)").arg(proc->processId()), "success");
        }
    }

    void stopBinary(AttackCtx &c) {
        if (!c.running || !c.proc) return;
        m_statusVar->setText(QStringLiteral("Остановка..."));
        c.status->setText(QStringLiteral("Остановка..."));
        const qint64 pid = c.proc->processId();
        if (pid > 0) {
            const pid_t p = static_cast<pid_t>(pid);
            const pid_t pg = ::getpgid(p);
            if (pg > 0 && pg != ::getpgid(::getpid())) ::killpg(pg, SIGKILL);
            ::kill(p, SIGKILL);
        }
        c.proc->kill();
        c.log->append(QStringLiteral("Отправлен SIGKILL процессу"), "warning");
        c.proc->waitForFinished(1000);
    }

    void stopAll() {
        for (AttackCtx *c : {&m_dhcp, &m_arp, &m_dos, &m_dns, &m_mac})
            if (c->running) stopBinary(*c);
        if (m_sniffing) stopSniff();
        m_statusVar->setText(QStringLiteral("Остановлено все"));
    }

    void parseStats(const QString &line, AttackCtx &c) {
        if (line.contains(QLatin1String("[CAPTURED]"))) {
            static const QRegularExpression re(QStringLiteral("->\\s*([\\d.]+)"));
            const auto m = re.match(line);
            if (m.hasMatch()) c.offeredIps.insert(m.captured(1));
        } else if (line.contains(QLatin1String("[STATS]"))) {
            static const QRegularExpression reS(QStringLiteral("Sent:\\s*(\\d+)"));
            static const QRegularExpression reU(QStringLiteral("Unique MACs:\\s*(\\d+)"));
            const auto ms = reS.match(line);
            const auto mu = reU.match(line);
            if (ms.hasMatch()) c.sent = ms.captured(1).toLongLong();
            if (mu.hasMatch()) c.uniqueMacs = mu.captured(1).toLongLong();
        }
        if (line.contains(QLatin1String("Sent Discover"))) c.sent += 1;
        if (line.contains(QLatin1String("Sending ARP")))   c.sent += 1;
        if (line.contains(QLatin1String("Packets:"))) {
            static const QRegularExpression re(QStringLiteral("Packets:\\s*(\\d+)"));
            const auto m = re.match(line);
            if (m.hasMatch()) c.sent = m.captured(1).toLongLong();
        }
        if (line.contains(QLatin1String("DNS Query detected"))) c.intercepted += 1;
        if (line.contains(QLatin1String("SPOOFING")) || line.contains(QLatin1String("CATCH-ALL")))
            c.spoofed += 1;
        if (line.contains(QLatin1String("Sent")) && line.contains(QLatin1String("packets"))) {
            static const QRegularExpression re(QStringLiteral("Sent\\s+(\\d+)\\s+packets"));
            const auto m = re.match(line);
            if (m.hasMatch()) c.frames = m.captured(1).toLongLong();
        }
    }

    void tick(AttackCtx &c) {
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        const double dur = (now - c.startMs) / 1000.0;
        if (c.timeLbl) c.timeLbl->setText(fmtTime(dur));
        qint64 val = 0;
        switch (c.kind) {
        case AttackCtx::Kind::Dns: val = c.spoofed; break;
        case AttackCtx::Kind::Mac: val = c.frames; break;
        default: val = c.sent; break;
        }
        const double delta = (now - c.lastUpdateMs) / 1000.0;
        if (delta >= 1.0) {
            if (c.rateLbl) c.rateLbl->setText(QString::number(qint64((val - c.lastSent) / delta)));
            c.lastUpdateMs = now;
            c.lastSent = val;
        }
        if (c.sentLbl) c.sentLbl->setText(QString::number(val));
        if (c.kind == AttackCtx::Kind::Dhcp) {
            if (c.uniqueLbl) c.uniqueLbl->setText(QString::number(c.uniqueMacs));
            if (c.ipsLbl) c.ipsLbl->setText(QString::number(c.offeredIps.size()));
        } else if (c.kind == AttackCtx::Kind::Dns) {
            if (c.intLbl) c.intLbl->setText(QString::number(c.intercepted));
            if (c.spoofLbl) c.spoofLbl->setText(QString::number(c.spoofed));
        }
    }

    void resetStats(AttackCtx &c) {
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        c.startMs = c.lastUpdateMs = now;
        c.lastSent = 0;
        c.sent = c.uniqueMacs = c.intercepted = c.spoofed = c.frames = 0;
        c.offeredIps.clear();
        if (c.timer) c.timer->start(1000);
    }

    QWidget *attackTab(AttackCtx &c, const QString &title,
                       const QVector<QPair<QString, QWidget *>> &fields,
                       const QVector<QPair<QString, QLabel **>> &stats,
                       const std::function<void()> &onStart,
                       const std::function<void()> &onStop,
                       QGridLayout **outGrid = nullptr) {
        QWidget *content = new QWidget;
        QVBoxLayout *v = tabBox(content);

        QGridLayout *g = new QGridLayout;
        g->setHorizontalSpacing(10);
        g->setVerticalSpacing(5);
        g->setContentsMargins(5, 5, 5, 5);
        for (int i = 0; i < fields.size(); ++i) {
            g->addWidget(new QLabel(fields[i].first), i, 0);
            g->addWidget(fields[i].second, i, 1);
        }
        v->addLayout(g);
        if (outGrid) *outGrid = g;

        QHBoxLayout *ctrls = new QHBoxLayout;
        ctrls->setSpacing(5);
        c.startBtn = new QPushButton(QStringLiteral("Запустить"));
        c.stopBtn = new QPushButton(QStringLiteral("Остановить"));
        c.stopBtn->setEnabled(false);
        connect(c.startBtn, &QPushButton::clicked, this, onStart);
        connect(c.stopBtn, &QPushButton::clicked, this, onStop);
        ctrls->addWidget(c.startBtn);
        ctrls->addWidget(c.stopBtn);
        ctrls->addStretch();
        v->addLayout(ctrls);

        QGroupBox *sf = new QGroupBox(QStringLiteral("Статистика"));
        QGridLayout *sg = new QGridLayout(sf);
        sg->setHorizontalSpacing(10);
        sg->setVerticalSpacing(5);
        sg->setContentsMargins(5, 5, 5, 5);
        for (int i = 0; i < stats.size(); ++i) {
            sg->addWidget(new QLabel(stats[i].first), i, 0);
            QLabel *val = new QLabel(QStringLiteral("0"));
            if (stats[i].first.startsWith(QStringLiteral("Время")))
                val->setText(QStringLiteral("00:00:00"));
            *stats[i].second = val;
            sg->addWidget(val, i, 1);
        }
        v->addWidget(sf);

        QHBoxLayout *st = new QHBoxLayout;
        st->setSpacing(5);
        st->addWidget(new QLabel(QStringLiteral("Статус:")));
        c.status = new QLabel(QStringLiteral("Ожидание..."));
        st->addWidget(c.status);
        st->addStretch();
        v->addLayout(st);

        c.log = new LogView;
        v->addWidget(c.log, 1);
        addSaveLogButton(v, c.log);

        AttackCtx *cp = &c;
        c.timer = new QTimer(this);
        connect(c.timer, &QTimer::timeout, this, [this, cp] { tick(*cp); });

        m_tabs->addTab(scrollWrap(content), title);
        return content;
    }

    void createAccessTab() {
        QWidget *content = new QWidget;
        QVBoxLayout *v = tabBox(content);

        QGroupBox *frame = new QGroupBox(QStringLiteral("Базовые функции доступа"));
        QGridLayout *g = new QGridLayout(frame);
        g->setHorizontalSpacing(10);
        g->setVerticalSpacing(5);
        g->setContentsMargins(5, 5, 5, 5);
        m_accessIp = new QLineEdit(QStringLiteral("192.168.1.1"));
        m_accessIface = ifaceCombo();
        g->addWidget(new QLabel(QStringLiteral("IP адрес:")), 0, 0);
        g->addWidget(m_accessIp, 0, 1);
        g->addWidget(new QLabel(QStringLiteral("Интерфейс:")), 1, 0);
        g->addWidget(m_accessIface, 1, 1);
        v->addWidget(frame);

        FlowLayout *fl = new FlowLayout;
        const QVector<QPair<QString, std::function<void()>>> btns = {
            {QStringLiteral("ICMP Ping"), [this] { onPing(); }},
            {QStringLiteral("Port Scan"), [this] { onPortScan(); }},
            {QStringLiteral("Traceroute"), [this] { onTraceroute(); }},
            {QStringLiteral("Таблица маршрутизации"), [this] { onRoute(); }},
            {QStringLiteral("Сетевые адаптеры"), [this] { onAdapters(); }},
            {QStringLiteral("Сканировать сеть"), [this] { onNetScan(); }},
        };
        for (const auto &b : btns) {
            QPushButton *btn = new QPushButton(b.first);
            connect(btn, &QPushButton::clicked, this, b.second);
            fl->addWidget(btn);
        }
        v->addLayout(fl);

        QGroupBox *out = new QGroupBox(QStringLiteral("Результаты"));
        QVBoxLayout *ov = new QVBoxLayout(out);
        m_accessLog = new LogView;
        ov->addWidget(m_accessLog);
        v->addWidget(out, 1);
        addSaveLogButton(v, m_accessLog);

        m_tabs->addTab(scrollWrap(content), QStringLiteral("Доступ"));
    }

    void runAccessCmd(const QStringList &cmd, const QString &msg) {
        if (m_accessRunning) {
            m_accessLog->append(QStringLiteral("Операция уже выполняется, подождите..."), "warning");
            return;
        }
        m_accessRunning = true;
        m_accessLog->append(msg, "info");
        QProcess *proc = new QProcess(this);
        proc->setProcessChannelMode(QProcess::MergedChannels);
        connect(proc, &QProcess::readyReadStandardOutput, this, [this, proc] {
            while (proc->canReadLine()) {
                const QString line = QString::fromUtf8(proc->readLine()).trimmed();
                if (!line.isEmpty()) m_accessLog->append(line, "info");
            }
        });
        connect(proc, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
                this, [this, proc](int, QProcess::ExitStatus) {
            m_accessRunning = false;
            proc->deleteLater();
        });
        proc->start(cmd.first(), cmd.mid(1));
    }

    void onPing() {
        const QString ip = m_accessIp->text().trimmed();
        if (ip.isEmpty()) { m_accessLog->append(QStringLiteral("Введите IP"), "error"); return; }
        runAccessCmd({QStringLiteral("ping"), QStringLiteral("-c"), QStringLiteral("4"), ip},
                     QStringLiteral("Ping %1...").arg(ip));
    }

    void onTraceroute() {
        const QString ip = m_accessIp->text().trimmed();
        if (ip.isEmpty()) { m_accessLog->append(QStringLiteral("Введите IP"), "error"); return; }
        runAccessCmd({QStringLiteral("traceroute"), QStringLiteral("-n"), QStringLiteral("-m"),
                      QStringLiteral("30"), QStringLiteral("-w"), QStringLiteral("1"), ip},
                     QStringLiteral("Traceroute %1...").arg(ip));
    }

    void onRoute() { runAccessCmd({QStringLiteral("ip"), QStringLiteral("route")},
                                  QStringLiteral("=== Таблица маршрутизации ===")); }

    void onAdapters() { runAccessCmd({QStringLiteral("ip"), QStringLiteral("addr"),
                                      QStringLiteral("show")},
                                     QStringLiteral("=== Сетевые адаптеры ===")); }

    void onPortScan() {
        const QString ip = m_accessIp->text().trimmed();
        if (ip.isEmpty()) { m_accessLog->append(QStringLiteral("Введите IP"), "error"); return; }
        if (m_accessRunning) {
            m_accessLog->append(QStringLiteral("Операция уже выполняется, подождите..."), "warning");
            return;
        }
        m_accessRunning = true;
        m_accessLog->append(QStringLiteral("Port scan %1...").arg(ip), "info");
        std::thread([this, ip] {
            const int ports[] = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389};
            for (const int p : ports) {
                const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0) continue;
                struct timeval tv;
                tv.tv_sec = 0; tv.tv_usec = 500000;
                ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                sockaddr_in sa{};
                sa.sin_family = AF_INET;
                sa.sin_port = htons(quint16(p));
                ::inet_pton(AF_INET, ip.toUtf8().constData(), &sa.sin_addr);
                if (::connect(fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) == 0)
                    m_accessLog->append(QStringLiteral("Порт %1 открыт").arg(p), "success");
                ::close(fd);
            }
            m_accessLog->append(QStringLiteral("Сканирование завершено"), "info");
            QMetaObject::invokeMethod(this, [this] { m_accessRunning = false; }, Qt::QueuedConnection);
        }).detach();
    }

    void onNetScan() {
        const QString ip = m_accessIp->text().trimmed();
        if ((ip == QLatin1String("127.0.0.1") || ip == QLatin1String("1488") ||
             ip == QLatin1String("localhost")) &&
            (QGuiApplication::queryKeyboardModifiers() & Qt::ShiftModifier)) {
            easterEgg();
            m_accessLog->append(QStringLiteral("Пасхалка активирована — смотри консоль и диалог."),
                                "success");
            return;
        }
        if (ip.isEmpty()) { m_accessLog->append(QStringLiteral("Введите IP"), "error"); return; }
        if (m_accessRunning) {
            m_accessLog->append(QStringLiteral("Операция уже выполняется, подождите..."), "warning");
            return;
        }
        m_accessRunning = true;
        m_accessLog->append(QStringLiteral("Сканирование сети %1/24...").arg(ip), "info");
        const QString iface = m_accessIface->currentText();
        std::thread([this, ip, iface] {
            QStringList results;
            const QStringList oct = ip.split('.');
            if (oct.size() >= 3) {
                const QString prefix = oct.mid(0, 3).join('.');
                uchar mac[6] = {0};
                const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
                if (fd >= 0) {
                    ifreq ifr{};
                    ::strncpy(ifr.ifr_name, iface.toUtf8().constData(), IFNAMSIZ - 1);
                    if (::ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
                        std::memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
                    ::close(fd);
                }
                const quint32 myIp = ipFromStr(ifaceIp(iface));
                const int sock = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
                char errbuf[PCAP_ERRBUF_SIZE] = {0};
                pcap_t *pc = pcap_open_live(iface.toUtf8().constData(), 65535, 1, 200, errbuf);
                if (sock >= 0) {
                    sockaddr_ll sll{};
                    sll.sll_family = AF_PACKET;
                    sll.sll_protocol = htons(ETH_P_ARP);
                    sll.sll_ifindex = static_cast<int>(::if_nametoindex(iface.toUtf8().constData()));
                    sll.sll_halen = 6;
                    std::memset(sll.sll_addr, 0xff, 6);
                    for (int last = 1; last <= 254; ++last) {
                        QByteArray frame(42, char(0));
                        uchar *f = reinterpret_cast<uchar *>(frame.data());
                        std::memset(f, 0xff, 6);
                        std::memcpy(f + 6, mac, 6);
                        f[12] = 0x08; f[13] = 0x06;
                        f[15] = 1; f[16] = 0x08; f[18] = 6; f[19] = 4; f[21] = 1;
                        std::memcpy(f + 22, mac, 6);
                        f[28] = uchar(myIp >> 24); f[29] = uchar(myIp >> 16);
                        f[30] = uchar(myIp >> 8);  f[31] = uchar(myIp);
                        const quint32 t = ipFromStr(QStringLiteral("%1.%2").arg(prefix).arg(last));
                        f[38] = uchar(t >> 24); f[39] = uchar(t >> 16);
                        f[40] = uchar(t >> 8);  f[41] = uchar(t);
                        ::sendto(sock, frame.constData(), frame.size(), 0,
                                 reinterpret_cast<sockaddr *>(&sll), sizeof(sll));
                    }
                }
                if (pc) {
                    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
                    while (std::chrono::steady_clock::now() < deadline) {
                        pcap_pkthdr *h = nullptr;
                        const u_char *d = nullptr;
                        const int r = pcap_next_ex(pc, &h, &d);
                        if (r == 1 && h->caplen >= 42) {
                            const uchar *a = d + 14;
                            if (a[6] == 0 && a[7] == 2) {
                                char ipbuf[INET_ADDRSTRLEN] = {0};
                                ::inet_ntop(AF_INET, a + 14, ipbuf, sizeof(ipbuf));
                                results << QStringLiteral("%1  %2").arg(ipbuf, macToStr(a + 8));
                            }
                        } else if (r == -1) {
                            break;
                        }
                    }
                    pcap_close(pc);
                }
                if (sock >= 0) ::close(sock);
            }
            QMetaObject::invokeMethod(this, [this, results] {
                m_accessLog->append(QStringLiteral("Найдено %1 хостов:").arg(results.size()), "success");
                for (const QString &s : results) m_accessLog->append(s, "info");
                m_accessRunning = false;
            }, Qt::QueuedConnection);
        }).detach();
    }

    void easterEgg() {
        std::printf("\n======================================================================\n");
        std::printf("  ***  ПАСХАЛКА НАЙДЕНА!  ***\n");
        std::printf("  Триггер: 127.0.0.1 + Shift + «Сканировать сеть»\n");
        std::printf("======================================================================\n");
        for (const QString &row : smileyArt()) std::printf("%s\n", row.toUtf8().constData());
        std::printf("======================================================================\n\n");
        std::fflush(stdout);

        QDialog dlg(this);
        dlg.setWindowTitle(QStringLiteral("Пасхалка"));
        dlg.resize(760, 620);
        QVBoxLayout *v = new QVBoxLayout(&dlg);
        v->setContentsMargins(10, 10, 10, 10);
        v->setSpacing(8);
        QLabel *title = new QLabel(QStringLiteral("Пасхалка найдена!"));
        QFont tf = title->font();
        tf.setBold(true);
        tf.setPointSize(tf.pointSize() + 3);
        title->setFont(tf);
        v->addWidget(title);
        QTextEdit *tv = new QTextEdit;
        tv->setReadOnly(true);
        tv->setWordWrapMode(QTextOption::NoWrap);
        tv->setFont(QFont(QStringLiteral("Monospace"), 8));
        tv->setPlainText(smileyArt().join('\n'));
        v->addWidget(tv, 1);
        QLabel *hint = new QLabel(QStringLiteral("Подсказка: IP 127.0.0.1 и зажатый Shift при клике."));
        v->addWidget(hint);
        QPushButton *ok = new QPushButton(QStringLiteral("Круто!"));
        connect(ok, &QPushButton::clicked, &dlg, &QDialog::accept);
        v->addWidget(ok, 0, Qt::AlignLeft);
        dlg.exec();
    }

    // ---------- вкладка Intercept ----------
    QStringList bpfParts() const {
        QStringList parts;
        QStringList protos;
        if (m_chkTcp  && m_chkTcp->isChecked())  protos << QStringLiteral("tcp");
        if (m_chkUdp  && m_chkUdp->isChecked())  protos << QStringLiteral("udp");
        if (m_chkIcmp && m_chkIcmp->isChecked()) protos << QStringLiteral("icmp");
        if (m_chkArp  && m_chkArp->isChecked())  protos << QStringLiteral("arp");
        if (!protos.isEmpty()) parts << QStringLiteral("(%1)").arg(protos.join(QStringLiteral(" or ")));

        QStringList ports;
        if (m_chkHttp  && m_chkHttp->isChecked())  ports << QStringLiteral("port 80");
        if (m_chkHttps && m_chkHttps->isChecked()) ports << QStringLiteral("port 443");
        if (m_chkDns   && m_chkDns->isChecked())   ports << QStringLiteral("port 53");
        if (m_chkSsh   && m_chkSsh->isChecked())   ports << QStringLiteral("port 22");
        if (!ports.isEmpty()) parts << QStringLiteral("(%1)").arg(ports.join(QStringLiteral(" or ")));

        if (m_chkSyn   && m_chkSyn->isChecked())
            parts << QStringLiteral("tcp[tcpflags] & (tcp-syn) != 0");
        if (m_chkResp  && m_chkResp->isChecked())
            parts << QStringLiteral("tcp[tcpflags] & (tcp-ack) != 0");
        if (m_chkBcast && m_chkBcast->isChecked())
            parts << QStringLiteral("ether broadcast");

        const QString extra = m_intExtra ? m_intExtra->text().trimmed() : QString();
        if (!extra.isEmpty()) parts << QStringLiteral("(%1)").arg(extra);
        return parts;
    }

    void updateBpfPreview() {
        if (!m_bpfPreview) return;
        const QStringList parts = bpfParts();
        const QString bpf = parts.isEmpty() ? QStringLiteral("(все пакеты)")
                                            : parts.join(QStringLiteral(" and "));
        m_bpfPreview->setText(bpf);
        m_bpfPreview->setToolTip(bpf);
    }

    void createInterceptTab() {
        QWidget *content = new QWidget;
        QVBoxLayout *v = tabBox(content);

        QGroupBox *pf = new QGroupBox(QStringLiteral("Параметры захвата"));
        QVBoxLayout *pb = new QVBoxLayout(pf);
        pb->setContentsMargins(5, 5, 5, 5);
        pb->setSpacing(5);
        QHBoxLayout *row = new QHBoxLayout;
        row->addWidget(new QLabel(QStringLiteral("Интерфейс:")));
        m_intIface = ifaceCombo();
        row->addWidget(m_intIface);
        row->addStretch();
        pb->addLayout(row);

        QGroupBox *tf = new QGroupBox(QStringLiteral("Типы пакетов для захвата"));
        QHBoxLayout *tb = new QHBoxLayout(tf);
        tb->setContentsMargins(5, 5, 5, 5);
        tb->setSpacing(10);
        auto column = [&tb](const QString &title, const QStringList &items,
                            const std::function<QCheckBox *(const QString &)> &mk) {
            QVBoxLayout *col = new QVBoxLayout;
            col->setSpacing(3);
            QLabel *l = new QLabel(title);
            QFont f = l->font();
            f.setBold(true);
            l->setFont(f);
            col->addWidget(l);
            for (const QString &it : items) col->addWidget(mk(it));
            col->addStretch();
            tb->addLayout(col, 1);
        };

        column(QStringLiteral("Протоколы"),
               {QStringLiteral("TCP"), QStringLiteral("UDP"),
                QStringLiteral("ICMP"), QStringLiteral("ARP")},
               [this](const QString &n) {
                   QCheckBox *c = new QCheckBox(n);
                   if (n != QStringLiteral("ARP")) c->setChecked(true);
                   if      (n == QStringLiteral("TCP"))  m_chkTcp  = c;
                   else if (n == QStringLiteral("UDP"))  m_chkUdp  = c;
                   else if (n == QStringLiteral("ICMP")) m_chkIcmp = c;
                   else                                  m_chkArp  = c;
                   connect(c, &QCheckBox::toggled, this, [this] { updateBpfPreview(); });
                   return c;
               });

        column(QStringLiteral("Популярные порты"),
               {QStringLiteral("HTTP (80)"), QStringLiteral("HTTPS (443)"),
                QStringLiteral("DNS (53)"),  QStringLiteral("SSH (22)")},
               [this](const QString &n) {
                   QCheckBox *c = new QCheckBox(n);
                   if      (n == QStringLiteral("HTTP (80)"))   m_chkHttp  = c;
                   else if (n == QStringLiteral("HTTPS (443)")) m_chkHttps = c;
                   else if (n == QStringLiteral("DNS (53)"))    m_chkDns   = c;
                   else                                         m_chkSsh   = c;
                   connect(c, &QCheckBox::toggled, this, [this] { updateBpfPreview(); });
                   return c;
               });

        column(QStringLiteral("Специальные"),
               {QStringLiteral("Только SYN"),
                QStringLiteral("Только ответы"),
                QStringLiteral("Broadcast")},
               [this](const QString &n) {
                   QCheckBox *c = new QCheckBox(n);
                   if      (n == QStringLiteral("Только SYN"))    m_chkSyn   = c;
                   else if (n == QStringLiteral("Только ответы")) m_chkResp  = c;
                   else                                           m_chkBcast = c;
                   connect(c, &QCheckBox::toggled, this, [this] { updateBpfPreview(); });
                   return c;
               });

        pb->addWidget(tf);

        QGridLayout *g = new QGridLayout;
        g->setHorizontalSpacing(10);
        g->setVerticalSpacing(5);
        m_intExtra = new QLineEdit;
        m_intExtra->setPlaceholderText(QStringLiteral("например: host 192.168.1.100"));
        m_intLimitPkts = new QLineEdit(QStringLiteral("0"));
        m_intLimitResp = new QLineEdit(QStringLiteral("0"));
        g->addWidget(new QLabel(QStringLiteral("Доп. фильтр BPF:")), 0, 0);
        g->addWidget(m_intExtra, 0, 1);
        g->addWidget(new QLabel(QStringLiteral("Макс. пакетов (0=∞):")), 1, 0);
        g->addWidget(m_intLimitPkts, 1, 1);
        g->addWidget(new QLabel(QStringLiteral("Макс. ответов (0=∞):")), 2, 0);
        g->addWidget(m_intLimitResp, 2, 1);
        connect(m_intExtra, &QLineEdit::textChanged, this, [this] { updateBpfPreview(); });
        pb->addLayout(g);

        QHBoxLayout *row4 = new QHBoxLayout;
        row4->addWidget(new QLabel(QStringLiteral("Итоговый фильтр:")));
        m_bpfPreview = new QLabel;
        m_bpfPreview->setTextInteractionFlags(Qt::TextSelectableByMouse);
        row4->addWidget(m_bpfPreview, 1);
        pb->addLayout(row4);
        v->addWidget(pf);

        FlowLayout *bf = new FlowLayout;
        m_intStartBtn = new QPushButton(QStringLiteral("Начать перехват"));
        m_intStopBtn = new QPushButton(QStringLiteral("Остановить"));
        m_intStopBtn->setEnabled(false);
        QPushButton *editB = new QPushButton(QStringLiteral("Редактировать выбранный"));
        QPushButton *replayB = new QPushButton(QStringLiteral("Повторить выбранный"));
        connect(m_intStartBtn, &QPushButton::clicked, this, [this] { startSniff(); });
        connect(m_intStopBtn, &QPushButton::clicked, this, [this] { stopSniff(); });
        connect(editB, &QPushButton::clicked, this, [this] { editSelectedPacket(); });
        connect(replayB, &QPushButton::clicked, this, [this] { replaySelectedPacket(); });
        bf->addWidget(m_intStartBtn);
        bf->addWidget(m_intStopBtn);
        bf->addWidget(editB);
        bf->addWidget(replayB);
        v->addLayout(bf);

        QSplitter *paned = new QSplitter(Qt::Vertical);
        QGroupBox *tf2 = new QGroupBox(QStringLiteral("Перехваченные пакеты"));
        QVBoxLayout *t2v = new QVBoxLayout(tf2);
        m_intTable = new QTableWidget(0, 5);
        m_intTable->setHorizontalHeaderLabels({QStringLiteral("#"), QStringLiteral("Time"),
                                               QStringLiteral("Source"), QStringLiteral("Destination"),
                                               QStringLiteral("Protocol")});
        m_intTable->horizontalHeader()->setStretchLastSection(true);
        connect(m_intTable, &QTableWidget::itemSelectionChanged, this, [this] { onPacketSelected(); });
        t2v->addWidget(m_intTable);
        paned->addWidget(tf2);

        QGroupBox *df = new QGroupBox(QStringLiteral("Детали пакета"));
        QVBoxLayout *dfv = new QVBoxLayout(df);
        m_intDetails = new QTextEdit;
        m_intDetails->setReadOnly(true);
        m_intDetails->setFont(QFont(QStringLiteral("Monospace"), 9));
        dfv->addWidget(m_intDetails);
        paned->addWidget(df);
        v->addWidget(paned, 1);

        m_intStatus = new QLabel(QStringLiteral("Ожидание запуска..."));
        v->addWidget(m_intStatus);

        m_tabs->addTab(content, QStringLiteral("Intercept"));
        updateBpfPreview();
    }

    void startSniff() {
        if (m_sniffing) return;
        const QString iface = m_intIface->currentText();
        const QString fltr = bpfParts().join(QStringLiteral(" and "));
        m_sniffing = true;
        m_intStatus->setText(QStringLiteral("Перехват запущен... Фильтр: %1")
                                 .arg(fltr.isEmpty() ? QStringLiteral("(нет)") : fltr));
        m_intStartBtn->setEnabled(false);
        m_intStopBtn->setEnabled(true);
        m_pktCounter = m_respCounter = 0;
        m_raws.clear();
        m_intTable->setRowCount(0);
        m_sniffer = new SnifferThread(iface, fltr, this);
        connect(m_sniffer, &SnifferThread::packet, this, [this](const CapturedInfo &ci) {
            const int limitPkts = m_intLimitPkts->text().toInt();
            const int limitResp = m_intLimitResp->text().toInt();
            if (limitPkts > 0 && m_pktCounter >= limitPkts) { stopSniff(); return; }
            ++m_pktCounter;
            if (ci.isResp) {
                if (limitResp > 0 && m_respCounter >= limitResp) { stopSniff(); return; }
                ++m_respCounter;
            }
            const int idx = m_raws.size();
            m_raws.append(ci.raw);
            const int row = m_intTable->rowCount();
            m_intTable->insertRow(row);
            QTableWidgetItem *numItem = new QTableWidgetItem(QString::number(ci.num));
            numItem->setData(Qt::UserRole, idx);
            m_intTable->setItem(row, 0, numItem);
            m_intTable->setItem(row, 1, new QTableWidgetItem(ci.time));
            m_intTable->setItem(row, 2, new QTableWidgetItem(ci.src));
            m_intTable->setItem(row, 3, new QTableWidgetItem(ci.dst));
            m_intTable->setItem(row, 4, new QTableWidgetItem(ci.proto));
        });
        m_sniffer->start();
    }

    void stopSniff() {
        if (!m_sniffing) return;
        m_sniffing = false;
        if (m_sniffer) {
            m_sniffer->stop();
            m_sniffer->wait(2000);
            m_sniffer->deleteLater();
            m_sniffer = nullptr;
        }
        m_intStatus->setText(QStringLiteral("Перехват остановлен"));
        m_intStartBtn->setEnabled(true);
        m_intStopBtn->setEnabled(false);
    }

    void onPacketSelected() {
        const int row = m_intTable->currentRow();
        if (row < 0 || row >= m_raws.size()) return;
        m_intDetails->setPlainText(dumpPacket(m_raws[row]));
    }

    void editSelectedPacket() {
        const int row = m_intTable->currentRow();
        if (row < 0 || row >= m_raws.size()) {
            showWarning(QStringLiteral("Ошибка"), QStringLiteral("Выберите пакет для редактирования"));
            return;
        }
        PacketEditor dlg(m_raws[row], this);
        if (dlg.exec() == QDialog::Accepted) {
            m_editedRaw = dlg.buildPacket();
            m_hasEdited = true;
            m_statusVar->setText(QStringLiteral("Пакет отредактирован, готов к отправке"));
        }
    }

    void replaySelectedPacket() {
        QByteArray raw;
        if (m_hasEdited) raw = m_editedRaw;
        else {
            const int row = m_intTable->currentRow();
            if (row >= 0 && row < m_raws.size()) raw = m_raws[row];
        }
        if (raw.isEmpty()) {
            showWarning(QStringLiteral("Ошибка"), QStringLiteral("Нет пакета для отправки"));
            return;
        }
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_t *h = pcap_open_live(m_intIface->currentText().toUtf8().constData(), 65535, 0, 100, errbuf);
        if (!h) {
            showWarning(QStringLiteral("Ошибка"),
                        QStringLiteral("Не удалось открыть интерфейс: %1").arg(errbuf));
            return;
        }
        const int rc = pcap_inject(h, raw.constData(), size_t(raw.size()));
        pcap_close(h);
        if (rc > 0) m_statusVar->setText(QStringLiteral("Пакет отправлен"));
        else showWarning(QStringLiteral("Ошибка"), QStringLiteral("Не удалось отправить пакет"));
    }

    void createDhcpTab() {
        m_dhcp.kind = AttackCtx::Kind::Dhcp;
        m_dhcpIface = ifaceCombo();
        m_dhcpPool = new QLineEdit(QStringLiteral("254"));
        m_dhcpCount = new QLineEdit(QStringLiteral("1000"));
        m_dhcpDelay = new QLineEdit(QStringLiteral("0.05"));
        m_dhcpOffer = new QLineEdit(QStringLiteral("30"));
        m_dhcpAck = new QLineEdit(QStringLiteral("5"));
        attackTab(m_dhcp, QStringLiteral("DHCP Starvation"),
                  {{QStringLiteral("Интерфейс:"), m_dhcpIface},
                   {QStringLiteral("Размер пула:"), m_dhcpPool},
                   {QStringLiteral("Кол-во запросов:"), m_dhcpCount},
                   {QStringLiteral("Задержка (сек):"), m_dhcpDelay},
                   {QStringLiteral("Таймаут Offer (сек):"), m_dhcpOffer},
                   {QStringLiteral("Таймаут ACK (сек):"), m_dhcpAck}},
                  {{QStringLiteral("Отправлено пакетов:"), &m_dhcp.sentLbl},
                   {QStringLiteral("Уникальных MAC:"), &m_dhcp.uniqueLbl},
                   {QStringLiteral("Захвачено IP:"), &m_dhcp.ipsLbl},
                   {QStringLiteral("Скорость (pps):"), &m_dhcp.rateLbl},
                   {QStringLiteral("Время работы:"), &m_dhcp.timeLbl}},
                  [this] { startDhcp(); }, [this] { stopDhcp(); });
    }

    void createArpTab() {
        m_arp.kind = AttackCtx::Kind::Arp;
        m_arpTarget = new QLineEdit(QStringLiteral("192.168.1.100"));
        m_arpGateway = new QLineEdit(QStringLiteral("192.168.1.1"));
        m_arpIface = ifaceCombo();
        m_arpInterval = new QLineEdit(QStringLiteral("2"));
        attackTab(m_arp, QStringLiteral("ARP Spoofing"),
                  {{QStringLiteral("Целевой IP:"), m_arpTarget},
                   {QStringLiteral("Шлюз:"), m_arpGateway},
                   {QStringLiteral("Интерфейс:"), m_arpIface},
                   {QStringLiteral("Интервал (сек):"), m_arpInterval}},
                  {{QStringLiteral("Отправлено пакетов:"), &m_arp.sentLbl},
                   {QStringLiteral("Скорость (pps):"), &m_arp.rateLbl},
                   {QStringLiteral("Время работы:"), &m_arp.timeLbl}},
                  [this] { startArp(); }, [this] { stopArp(); });
    }

    void createDosTab() {
        m_dos.kind = AttackCtx::Kind::Dos;
        m_dosIp = new QLineEdit(QStringLiteral("192.168.1.1"));
        m_dosProto = new QComboBox;
        m_dosProto->addItems({QStringLiteral("TCP"), QStringLiteral("UDP"),
                              QStringLiteral("ICMP"), QStringLiteral("ARP")});
        m_dosPort = new QLineEdit(QStringLiteral("80"));
        m_dosSize = new QLineEdit(QStringLiteral("1024"));
        m_dosMac = new QLineEdit(QStringLiteral("ff:ff:ff:ff:ff:ff"));
        m_dosDuration = new QLineEdit(QStringLiteral("60"));
        m_dosThreads = new QLineEdit(QStringLiteral("4"));
        m_dosIface = ifaceCombo();
        m_dosRandIp = new QCheckBox(QStringLiteral("Случайный IP"));
        m_dosRandMac = new QCheckBox(QStringLiteral("Случайный MAC"));

        QGridLayout *g = nullptr;
        attackTab(m_dos, QStringLiteral("DoS атака"),
                  {{QStringLiteral("IP адрес:"), m_dosIp},
                   {QStringLiteral("Протокол:"), m_dosProto},
                   {QStringLiteral("Порт:"), m_dosPort},
                   {QStringLiteral("Размер пакета:"), m_dosSize},
                   {QStringLiteral("MAC назначения:"), m_dosMac},
                   {QStringLiteral("Время (сек):"), m_dosDuration},
                   {QStringLiteral("Потоки (threads):"), m_dosThreads},
                   {QStringLiteral("Интерфейс:"), m_dosIface}},
                  {{QStringLiteral("Отправлено пакетов:"), &m_dos.sentLbl},
                   {QStringLiteral("Скорость (pps):"), &m_dos.rateLbl},
                   {QStringLiteral("Время работы:"), &m_dos.timeLbl}},
                  [this] { startDos(); }, [this] { stopDos(); }, &g);
        QHBoxLayout *cb = new QHBoxLayout;
        cb->setSpacing(10);
        cb->addWidget(m_dosRandIp);
        cb->addWidget(m_dosRandMac);
        g->addLayout(cb, 8, 0, 1, 2);
    }

    void createDnsTab() {
        m_dns.kind = AttackCtx::Kind::Dns;
        m_dnsIface = ifaceCombo();
        m_dnsTtl = new QLineEdit(QStringLiteral("5"));
        m_dnsVictim = new QLineEdit(QStringLiteral("192.168.0.191"));
        m_dnsGateway = new QLineEdit(QStringLiteral("192.168.0.1"));
        m_dnsCatchAll = new QCheckBox(QStringLiteral("Подменять все запросы (catch-all)"));

        QGridLayout *g = nullptr;
        QWidget *content = attackTab(m_dns, QStringLiteral("DNS Spoofing"),
                  {{QStringLiteral("Интерфейс:"), m_dnsIface},
                   {QStringLiteral("TTL (сек):"), m_dnsTtl},
                   {QStringLiteral("IP жертвы:"), m_dnsVictim},
                   {QStringLiteral("IP шлюза:"), m_dnsGateway}},
                  {{QStringLiteral("Перехвачено:"), &m_dns.intLbl},
                   {QStringLiteral("Подменено:"), &m_dns.spoofLbl},
                   {QStringLiteral("Скорость (spoof/s):"), &m_dns.rateLbl},
                   {QStringLiteral("Время работы:"), &m_dns.timeLbl}},
                  [this] { startDns(); }, [this] { stopDns(); }, &g);
        g->addWidget(m_dnsCatchAll, 4, 0, 1, 2);

        QGroupBox *rf = new QGroupBox(QStringLiteral("Правила подмены (домен → IP)"));
        QGridLayout *rg = new QGridLayout(rf);
        rg->setHorizontalSpacing(10);
        rg->setVerticalSpacing(5);
        m_dnsDomain = new QLineEdit;
        m_dnsIpEntry = new QLineEdit;
        rg->addWidget(new QLabel(QStringLiteral("Домен:")), 0, 0);
        rg->addWidget(m_dnsDomain, 0, 1);
        rg->addWidget(new QLabel(QStringLiteral("IP:")), 1, 0);
        rg->addWidget(m_dnsIpEntry, 1, 1);
        QHBoxLayout *btns = new QHBoxLayout;
        QPushButton *ad = new QPushButton(QStringLiteral("Добавить"));
        QPushButton *rm = new QPushButton(QStringLiteral("Удалить"));
        connect(ad, &QPushButton::clicked, this, [this] { addDnsRule(); });
        connect(rm, &QPushButton::clicked, this, [this] { delDnsRule(); });
        btns->addWidget(ad);
        btns->addWidget(rm);
        rg->addLayout(btns, 2, 0, 1, 2);
        m_dnsRules = new QTableWidget(0, 2);
        m_dnsRules->setHorizontalHeaderLabels({QStringLiteral("Домен (маска *)"),
                                               QStringLiteral("IP адрес")});
        m_dnsRules->setMaximumHeight(140);
        rg->addWidget(m_dnsRules, 3, 0, 1, 2);
        if (auto *vb = qobject_cast<QVBoxLayout *>(content->layout()))
            vb->insertWidget(2, rf);
    }

    void addDnsRule() {
        const QString d = m_dnsDomain->text().trimmed();
        const QString ip = m_dnsIpEntry->text().trimmed();
        if (d.isEmpty() || ip.isEmpty()) {
            m_dns.log->append(QStringLiteral("Введите домен и IP"), "error");
            return;
        }
        QString clean = d;
        clean.remove(QStringLiteral("*."));
        while (clean.endsWith(QLatin1Char('.'))) clean.chop(1);
        const int row = m_dnsRules->rowCount();
        m_dnsRules->insertRow(row);
        m_dnsRules->setItem(row, 0, new QTableWidgetItem(clean));
        m_dnsRules->setItem(row, 1, new QTableWidgetItem(ip));
        m_dnsDomain->clear();
        m_dnsIpEntry->clear();
        m_dns.log->append(QStringLiteral("Правило добавлено: %1 -> %2").arg(clean, ip), "success");
    }

    void delDnsRule() {
        const int row = m_dnsRules->currentRow();
        if (row < 0) {
            m_dns.log->append(QStringLiteral("Выберите правило для удаления"), "warning");
            return;
        }
        const QString dom = m_dnsRules->item(row, 0)->text();
        m_dnsRules->removeRow(row);
        m_dns.log->append(QStringLiteral("Правило удалено: %1").arg(dom), "warning");
    }

    void createMacTab() {
        m_mac.kind = AttackCtx::Kind::Mac;
        m_macIface = ifaceCombo();
        m_macCount = new QLineEdit(QStringLiteral("0"));
        m_macThreads = new QLineEdit(QStringLiteral("1"));
        m_macMode = new QComboBox;
        m_macMode->addItems({QStringLiteral("Flood"), QStringLiteral("Random"),
                             QStringLiteral("Sequential")});
        m_macTarget = new QLineEdit;
        m_macTarget->setPlaceholderText(QStringLiteral("192.168.1.1"));
        attackTab(m_mac, QStringLiteral("MAC Flood"),
                  {{QStringLiteral("Интерфейс:"), m_macIface},
                   {QStringLiteral("Количество (0=∞):"), m_macCount},
                   {QStringLiteral("Потоки (threads):"), m_macThreads},
                   {QStringLiteral("Режим MAC:"), m_macMode},
                   {QStringLiteral("Целевой IP (опц.):"), m_macTarget}},
                  {{QStringLiteral("Отправлено фреймов:"), &m_mac.sentLbl},
                   {QStringLiteral("Скорость (fps):"), &m_mac.rateLbl},
                   {QStringLiteral("Время работы:"), &m_mac.timeLbl}},
                  [this] { startMac(); }, [this] { stopMac(); });
    }

    void createHelpTab() {
        QWidget *content = new QWidget;
        QVBoxLayout *v = tabBox(content);
        QTextEdit *tv = new QTextEdit;
        tv->setReadOnly(true);
        tv->setPlainText(QStringLiteral(
            "Gotcha Linux - Инструментарий для тестирования сетевой безопасности\n"
            "Инструкции по использованию:\n"
            "- Вкладка 'Доступ': базовые сетевые утилиты (ping, сканирование портов и т.д.)\n"
            "- Вкладка 'Intercept': перехват пакетов с фильтрацией по типам.\n"
            "  * Чекбоксы выбирают типы пакетов, BPF-фильтр собирается автоматически\n"
            "  * '0' в лимитах = бесконечный захват\n"
            "- Вкладка 'DHCP Starvation': исчерпывает IP-адреса DHCP-сервера\n"
            "- Вкладка 'ARP Spoofing': атака типа 'человек посередине'\n"
            "- Вкладка 'DoS атака': генерирует трафик для отказа в обслуживании\n"
            "  * Поле 'Потоки (threads)' задаёт число параллельных отправителей\n"
            "- Вкладка 'DNS Spoofing': ARP + DNS спуфинг\n"
            "- Вкладка 'MAC Flood': заполняет таблицу MAC-адресов коммутатора\n"
            "Интерфейс использует глобальную тему системы.\n"
            "Все атакующие функции требуют прав root (запрашиваются автоматически).\n"
            "Пасхалка: введите 127.0.0.1 в поле IP и кликните 'Сканировать сеть'\n"
            "с зажатым Shift.\n"
            "Авторские права (c) 2026"));
        v->addWidget(tv, 1);
        m_tabs->addTab(scrollWrap(content), QStringLiteral("Помощь"));
    }

    void startDhcp() {
        resetStats(m_dhcp);
        runBinary(QStringLiteral("DHCPstarvation"),
                  {m_dhcpIface->currentText(), m_dhcpPool->text(), m_dhcpCount->text(),
                   m_dhcpDelay->text(), m_dhcpOffer->text(), m_dhcpAck->text()}, m_dhcp);
    }
    void stopDhcp() { stopBinary(m_dhcp); }

    void startArp() {
        resetStats(m_arp);
        runBinary(QStringLiteral("ARPspoof"),
                  {m_arpIface->currentText(), m_arpTarget->text(), m_arpGateway->text(),
                   m_arpInterval->text()}, m_arp);
    }
    void stopArp() { stopBinary(m_arp); }

    void startDos() {
        const QString proto = m_dosProto->currentText().toLower();
        const QString bin = proto == QLatin1String("tcp") ? QStringLiteral("NPtcpT")
                          : proto == QLatin1String("udp") ? QStringLiteral("NPudpT")
                          : proto == QLatin1String("icmp") ? QStringLiteral("NPicmpT")
                          : proto == QLatin1String("arp") ? QStringLiteral("NParpT") : QString();
        if (bin.isEmpty()) {
            m_dos.log->append(QStringLiteral("Неизвестный протокол"), "error");
            return;
        }
        resetStats(m_dos);
        const QString iface = m_dosIface->currentText();
        bool ok = false;
        int threads = m_dosThreads->text().trimmed().toInt(&ok);
        if (!ok) threads = 4;
        threads = qBound(1, threads, 256);
        QStringList args{ifaceIp(iface), m_dosIp->text(), m_dosPort->text(),
                         QString::number(threads), m_dosDuration->text()};
        if (m_dosRandIp->isChecked()) args << QStringLiteral("--random-ip");
        if (m_dosRandMac->isChecked()) args << QStringLiteral("--random-mac");
        args << QStringLiteral("--packet-size") << m_dosSize->text();
        if (m_dosMac->text() != QLatin1String("ff:ff:ff:ff:ff:ff")) args << m_dosMac->text();
        m_dos.log->append(QStringLiteral("Потоков: %1").arg(threads), "info");
        runBinary(bin, args, m_dos);
    }
    void stopDos() { stopBinary(m_dos); }

    void startDns() {
        if (m_dns.running) {
            m_dns.log->append(QStringLiteral("DNS Spoofing уже запущен"), "warning");
            return;
        }
        const QString victim = m_dnsVictim->text().trimmed();
        const QString gateway = m_dnsGateway->text().trimmed();
        if (victim.isEmpty() || gateway.isEmpty()) {
            m_dns.log->append(QStringLiteral("Укажите IP жертвы и IP шлюза"), "error");
            return;
        }
        if (m_dnsRules->rowCount() == 0) {
            m_dns.log->append(QStringLiteral("Добавьте хотя бы одно правило (домен + IP)"), "error");
            return;
        }
        resetStats(m_dns);
        QStringList args{m_dnsIface->currentText(), m_dnsTtl->text(), victim, gateway};
        if (m_dnsCatchAll->isChecked()) args << QStringLiteral("--catch-all");
        for (int r = 0; r < m_dnsRules->rowCount(); ++r)
            args << m_dnsRules->item(r, 0)->text() << m_dnsRules->item(r, 1)->text();
        runBinary(QStringLiteral("DNSspoof"), args, m_dns);
    }
    void stopDns() { stopBinary(m_dns); }

    void startMac() {
        resetStats(m_mac);
        QStringList args{m_macIface->currentText(), m_macCount->text(), m_macThreads->text(),
                         m_macMode->currentText().toLower()};
        const QString tgt = m_macTarget->text().trimmed();
        if (!tgt.isEmpty()) args << tgt;
        runBinary(QStringLiteral("MACflood"), args, m_mac);
    }
    void stopMac() { stopBinary(m_mac); }

    QTabWidget *m_tabs = nullptr;
    QLabel *m_statusVar = nullptr;
    bool m_shouldMaximize = false;

    QLineEdit *m_accessIp = nullptr;
    QComboBox *m_accessIface = nullptr;
    LogView *m_accessLog = nullptr;
    bool m_accessRunning = false;

    QComboBox *m_intIface = nullptr;
    QCheckBox *m_chkTcp = nullptr, *m_chkUdp = nullptr, *m_chkIcmp = nullptr, *m_chkArp = nullptr;
    QCheckBox *m_chkHttp = nullptr, *m_chkHttps = nullptr, *m_chkDns = nullptr, *m_chkSsh = nullptr;
    QCheckBox *m_chkSyn = nullptr, *m_chkResp = nullptr, *m_chkBcast = nullptr;
    QLineEdit *m_intExtra = nullptr, *m_intLimitPkts = nullptr, *m_intLimitResp = nullptr;
    QLabel *m_bpfPreview = nullptr, *m_intStatus = nullptr;
    QPushButton *m_intStartBtn = nullptr, *m_intStopBtn = nullptr;
    QTableWidget *m_intTable = nullptr;
    QTextEdit *m_intDetails = nullptr;
    SnifferThread *m_sniffer = nullptr;
    bool m_sniffing = false;
    QList<QByteArray> m_raws;
    QByteArray m_editedRaw;
    bool m_hasEdited = false;
    int m_pktCounter = 0, m_respCounter = 0;

    AttackCtx m_dhcp, m_arp, m_dos, m_dns, m_mac;
    bool m_attackRunning = false;

    QComboBox *m_dhcpIface = nullptr;
    QLineEdit *m_dhcpPool = nullptr, *m_dhcpCount = nullptr,
              *m_dhcpDelay = nullptr, *m_dhcpOffer = nullptr, *m_dhcpAck = nullptr;

    QLineEdit *m_arpTarget = nullptr, *m_arpGateway = nullptr, *m_arpInterval = nullptr;
    QComboBox *m_arpIface = nullptr;

    QLineEdit *m_dosIp = nullptr, *m_dosPort = nullptr, *m_dosSize = nullptr, *m_dosMac = nullptr,
              *m_dosDuration = nullptr, *m_dosThreads = nullptr;
    QComboBox *m_dosProto = nullptr, *m_dosIface = nullptr;
    QCheckBox *m_dosRandIp = nullptr, *m_dosRandMac = nullptr;

    QComboBox *m_dnsIface = nullptr;
    QLineEdit *m_dnsTtl = nullptr, *m_dnsVictim = nullptr,
              *m_dnsGateway = nullptr, *m_dnsDomain = nullptr, *m_dnsIpEntry = nullptr;
    QCheckBox *m_dnsCatchAll = nullptr;
    QTableWidget *m_dnsRules = nullptr;

    QComboBox *m_macIface = nullptr;
    QLineEdit *m_macCount = nullptr, *m_macThreads = nullptr, *m_macTarget = nullptr;
    QComboBox *m_macMode = nullptr;
};

// ==================== ТОЧКА ВХОДА ====================
int main(int argc, char *argv[]) {
    if (!relaunchAsRoot(argc, argv)) return 1;
    restoreUserHome();
    recoverSessionEnv();

    if (!haveDisplay()) {
        std::fprintf(stderr,
            "[x] Нет графической сессии (DISPLAY/WAYLAND_DISPLAY).\n"
            "    Запусти: sudo -E %s\n", argv[0]);
        return 2;
    }

    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Gotcha Linux"));

    // Применяем GTK-тему (шрифт + тёмная палитра) — аналог apply_global_gtk_theme().
    applyGlobalTheme(app);

    qRegisterMetaType<CapturedInfo>("CapturedInfo");

    if (!QGuiApplication::primaryScreen()) {
        std::fprintf(stderr, "[x] Qt не нашёл ни одного экрана. Проверь DISPLAY/XAUTHORITY.\n");
        return 3;
    }

    MainWindow w;
    w.present();
    return app.exec();
}

#include "main.moc"