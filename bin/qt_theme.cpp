//
// Created by alice on 15.07.2026.
//
#include <QApplication>
#include <QMainWindow>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QCheckBox>
#include <QTreeWidget>
#include <QTextEdit>
#include <QPlainTextEdit>
#include <QGroupBox>
#include <QStatusBar>
#include <QProcess>
#include <QThread>
#include <QTimer>
#include <QFileDialog>
#include <QMessageBox>
#include <QScrollBar>
#include <QHeaderView>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QTabWidget>
#include <QPalette>
#include <QStyleFactory>
#include <QTemporaryFile>
#include <QDateTime>

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>

#include <vector>
#include <map>
#include <string>
#include <cstring>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>

// ========== Вспомогательные функции ==========
std::vector<std::pair<std::string, std::string>> get_network_interfaces() {
    std::vector<std::pair<std::string, std::string>> ifaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) return ifaces;
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        if (d->name == nullptr) continue;
        std::string ip = "";
        for (pcap_addr_t *a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in*)a->addr;
                ip = inet_ntoa(sin->sin_addr);
                break;
            }
        }
        if (ip.empty()) continue;
        if (std::string(d->name) != "lo") {
            ifaces.emplace_back(d->name, ip);
        }
    }
    pcap_freealldevs(alldevs);
    return ifaces;
}

bool is_root() {
    return geteuid() == 0;
}

// ========== Класс для логирования ==========
class LogWidget : public QPlainTextEdit {
    Q_OBJECT
public:
    LogWidget(QWidget *parent = nullptr) : QPlainTextEdit(parent) {
        setReadOnly(true);
        setLineWrapMode(QPlainTextEdit::NoWrap);
        QFont font("Courier New", 10);
        setFont(font);
        document()->setMaximumBlockCount(1000);
    }
    void appendMessage(const QString &msg, const QString &color = "white") {
        QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
        QString formatted = QString("[%1] %2").arg(timestamp, msg);
        QTextCharFormat fmt;
        fmt.setForeground(QColor(color));
        QTextCursor cursor = textCursor();
        cursor.movePosition(QTextCursor::End);
        cursor.insertText(formatted + "\n", fmt);
        ensureCursorVisible();
    }
};

// ========== Диалог редактора пакетов ==========
class PacketEditorDialog : public QDialog {
    Q_OBJECT
public:
    PacketEditorDialog(const QByteArray &packetData, QWidget *parent = nullptr)
        : QDialog(parent), originalData(packetData) {
        setWindowTitle("Редактор пакета");
        setModal(true);
        resize(800, 700);

        QVBoxLayout *mainLayout = new QVBoxLayout(this);

        // Ethernet
        QGroupBox *ethGroup = new QGroupBox("Ethernet");
        QFormLayout *ethLayout = new QFormLayout;
        ethSrc = new QLineEdit;
        ethDst = new QLineEdit;
        ethLayout->addRow("Source MAC:", ethSrc);
        ethLayout->addRow("Dest MAC:", ethDst);
        ethGroup->setLayout(ethLayout);
        mainLayout->addWidget(ethGroup);

        // IP
        QGroupBox *ipGroup = new QGroupBox("IP");
        QFormLayout *ipLayout = new QFormLayout;
        ipSrc = new QLineEdit;
        ipDst = new QLineEdit;
        ipTtl = new QLineEdit;
        ipLayout->addRow("Source IP:", ipSrc);
        ipLayout->addRow("Dest IP:", ipDst);
        ipLayout->addRow("TTL:", ipTtl);
        ipGroup->setLayout(ipLayout);
        mainLayout->addWidget(ipGroup);

        // Transport
        QGroupBox *transGroup = new QGroupBox("Transport");
        QFormLayout *transLayout = new QFormLayout;
        protoCombo = new QComboBox;
        protoCombo->addItems({"TCP", "UDP", "ICMP", "RAW"});
        srcPort = new QLineEdit;
        dstPort = new QLineEdit;
        transLayout->addRow("Protocol:", protoCombo);
        transLayout->addRow("Source Port:", srcPort);
        transLayout->addRow("Dest Port:", dstPort);
        transGroup->setLayout(transLayout);
        mainLayout->addWidget(transGroup);

        // TCP flags
        QGroupBox *flagsGroup = new QGroupBox("TCP Flags");
        QHBoxLayout *flagsLayout = new QHBoxLayout;
        for (const QString &f : {"FIN","SYN","RST","PSH","ACK","URG","ECE","CWR"}) {
            QCheckBox *cb = new QCheckBox(f);
            tcpFlags[f] = cb;
            flagsLayout->addWidget(cb);
        }
        flagsGroup->setLayout(flagsLayout);
        mainLayout->addWidget(flagsGroup);

        // Payload
        QGroupBox *payloadGroup = new QGroupBox("Payload (hex)");
        QVBoxLayout *payLayout = new QVBoxLayout;
        payloadEdit = new QTextEdit;
        payLayout->addWidget(payloadEdit);
        payloadGroup->setLayout(payLayout);
        mainLayout->addWidget(payloadGroup);

        // Кнопки
        QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        connect(buttonBox, &QDialogButtonBox::accepted, this, &PacketEditorDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, this, &PacketEditorDialog::reject);
        mainLayout->addWidget(buttonBox);

        // Заполняем поля из пакета
        parsePacket(originalData);
    }

    QByteArray getEditedPacket() { return editedPacket; }

private slots:
    void accept() override {
        editedPacket = buildPacket();
        QDialog::accept();
    }

private:
    QByteArray originalData, editedPacket;
    QLineEdit *ethSrc, *ethDst, *ipSrc, *ipDst, *ipTtl, *srcPort, *dstPort;
    QComboBox *protoCombo;
    QTextEdit *payloadEdit;
    std::map<QString, QCheckBox*> tcpFlags;

    void parsePacket(const QByteArray &data) {
        if (data.size() < 14) return;
        const u_char *pkt = (const u_char*)data.data();

        struct ether_header *eth = (struct ether_header*)pkt;
        char mac[18];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                 eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        ethSrc->setText(mac);
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                 eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
        ethDst->setText(mac);

        if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;
        if (data.size() < 14 + sizeof(struct ip)) return;
        struct ip *ip = (struct ip*)(pkt + 14);
        ipSrc->setText(inet_ntoa(ip->ip_src));
        ipDst->setText(inet_ntoa(ip->ip_dst));
        ipTtl->setText(QString::number(ip->ip_ttl));

        if (ip->ip_p == IPPROTO_TCP && data.size() >= 14 + ip->ip_hl*4 + sizeof(struct tcphdr)) {
            protoCombo->setCurrentText("TCP");
            struct tcphdr *tcp = (struct tcphdr*)(pkt + 14 + ip->ip_hl*4);
            srcPort->setText(QString::number(ntohs(tcp->th_sport)));
            dstPort->setText(QString::number(ntohs(tcp->th_dport)));
            uint16_t fl = ntohs(tcp->th_flags);
            tcpFlags["FIN"]->setChecked(fl & TH_FIN);
            tcpFlags["SYN"]->setChecked(fl & TH_SYN);
            tcpFlags["RST"]->setChecked(fl & TH_RST);
            tcpFlags["PSH"]->setChecked(fl & TH_PUSH);
            tcpFlags["ACK"]->setChecked(fl & TH_ACK);
            tcpFlags["URG"]->setChecked(fl & TH_URG);
            tcpFlags["ECE"]->setChecked(fl & TH_ECE);
            tcpFlags["CWR"]->setChecked(fl & TH_CWR);
            int payload_len = data.size() - (14 + ip->ip_hl*4 + sizeof(struct tcphdr));
            if (payload_len > 0) {
                const u_char *payload = pkt + 14 + ip->ip_hl*4 + sizeof(struct tcphdr);
                QByteArray hex = QByteArray((const char*)payload, payload_len).toHex();
                payloadEdit->setText(hex);
            }
        } else if (ip->ip_p == IPPROTO_UDP && data.size() >= 14 + ip->ip_hl*4 + sizeof(struct udphdr)) {
            protoCombo->setCurrentText("UDP");
            struct udphdr *udp = (struct udphdr*)(pkt + 14 + ip->ip_hl*4);
            srcPort->setText(QString::number(ntohs(udp->uh_sport)));
            dstPort->setText(QString::number(ntohs(udp->uh_dport)));
        } else if (ip->ip_p == IPPROTO_ICMP) {
            protoCombo->setCurrentText("ICMP");
        }
    }

    QByteArray buildPacket() {
        // В реальном проекте здесь нужно собрать пакет из полей.
        // Для примера возвращаем оригинал (заглушка).
        return originalData;
    }
};

// ========== Класс основного окна ==========
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr) : QMainWindow(parent) {
        setWindowTitle("Gotcha Linux – Qt");
        resize(1200, 800);

        // Применяем тёмную тему
        applyDarkTheme();

        if (!is_root()) {
            QMessageBox::warning(this, "Предупреждение", "Некоторые функции требуют прав root.\nЗапустите программу с sudo.");
        }

        ifaceList = get_network_interfaces();

        QWidget *central = new QWidget(this);
        setCentralWidget(central);
        QVBoxLayout *mainLayout = new QVBoxLayout(central);

        QLabel *header = new QLabel("⚡ Gotcha Linux – Qt");
        QFont f = header->font();
        f.setPointSize(16);
        f.setBold(true);
        header->setFont(f);
        mainLayout->addWidget(header);

        tabWidget = new QTabWidget;
        mainLayout->addWidget(tabWidget);

        createAccessTab();
        createInterceptTab();
        createDhcpTab();
        createArpTab();
        createDosTab();
        createDnsTab();
        createMacTab();
        createSettingsTab();

        statusBar()->showMessage("Готов к работе");
    }

private:
    void applyDarkTheme() {
        qApp->setStyle(QStyleFactory::create("Fusion"));
        QPalette darkPalette;
        darkPalette.setColor(QPalette::Window, QColor(53,53,53));
        darkPalette.setColor(QPalette::WindowText, Qt::white);
        darkPalette.setColor(QPalette::Base, QColor(25,25,25));
        darkPalette.setColor(QPalette::AlternateBase, QColor(53,53,53));
        darkPalette.setColor(QPalette::ToolTipBase, Qt::white);
        darkPalette.setColor(QPalette::ToolTipText, Qt::white);
        darkPalette.setColor(QPalette::Text, Qt::white);
        darkPalette.setColor(QPalette::Button, QColor(53,53,53));
        darkPalette.setColor(QPalette::ButtonText, Qt::white);
        darkPalette.setColor(QPalette::BrightText, Qt::red);
        darkPalette.setColor(QPalette::Link, QColor(42,130,218));
        darkPalette.setColor(QPalette::Highlight, QColor(42,130,218));
        darkPalette.setColor(QPalette::HighlightedText, Qt::black);
        qApp->setPalette(darkPalette);
    }

private slots:
    void appendLog(LogWidget *log, const QString &msg, const QString &color = "white") {
        log->appendMessage(msg, color);
    }

    // ===== Доступ =====
    void onPing() {
        QString ip = accessIp->text().trimmed();
        if (ip.isEmpty()) return;
        appendLog(accessLog, "Ping " + ip + "...", "cyan");
        QProcess *proc = new QProcess(this);
        connect(proc, &QProcess::readyReadStandardOutput, [=]() {
            QByteArray out = proc->readAllStandardOutput();
            appendLog(accessLog, QString::fromLocal8Bit(out).trimmed(), "white");
        });
        connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), [=]() {
            proc->deleteLater();
        });
        proc->start("ping", {"-c", "4", ip});
    }

    void onPortScan() {
        QString ip = accessIp->text().trimmed();
        if (ip.isEmpty()) return;
        appendLog(accessLog, "Сканирование портов " + ip + "...", "cyan");
        QThread *thread = QThread::create([=]() {
            int ports[] = {21,22,23,25,53,80,110,143,443,993,995,3389};
            for (int port : ports) {
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) continue;
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                inet_pton(AF_INET, ip.toStdString().c_str(), &addr.sin_addr);
                struct timeval tv = {1, 0};
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                    emit appendLog(accessLog, QString("Порт %1 открыт").arg(port), "green");
                }
                close(sock);
            }
            emit appendLog(accessLog, "Сканирование завершено", "white");
        });
        connect(thread, &QThread::finished, thread, &QThread::deleteLater);
        thread->start();
    }

    void onTraceroute() {
        QString ip = accessIp->text().trimmed();
        if (ip.isEmpty()) return;
        appendLog(accessLog, "Traceroute к " + ip + "...", "cyan");
        QProcess *proc = new QProcess(this);
        connect(proc, &QProcess::readyReadStandardOutput, [=]() {
            QByteArray out = proc->readAllStandardOutput();
            appendLog(accessLog, QString::fromLocal8Bit(out).trimmed(), "white");
        });
        connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), [=]() {
            proc->deleteLater();
        });
        proc->start("traceroute", {"-n", "-m", "30", "-w", "1", ip});
    }

    void onRoute() {
        appendLog(accessLog, "=== ТАБЛИЦА МАРШРУТИЗАЦИИ ===", "cyan");
        QProcess *proc = new QProcess(this);
        connect(proc, &QProcess::readyReadStandardOutput, [=]() {
            QByteArray out = proc->readAllStandardOutput();
            appendLog(accessLog, QString::fromLocal8Bit(out).trimmed(), "white");
        });
        connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), [=]() {
            proc->deleteLater();
        });
        proc->start("route", {"-n"});
    }

    void onAdapters() {
        appendLog(accessLog, "=== СЕТЕВЫЕ АДАПТЕРЫ ===", "cyan");
        QProcess *proc = new QProcess(this);
        connect(proc, &QProcess::readyReadStandardOutput, [=]() {
            QByteArray out = proc->readAllStandardOutput();
            appendLog(accessLog, QString::fromLocal8Bit(out).trimmed(), "white");
        });
        connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), [=]() {
            proc->deleteLater();
        });
        proc->start("ip", {"addr", "show"});
    }

    void onNetScan() {
        QString ip = accessIp->text().trimmed();
        if (ip.isEmpty()) return;
        appendLog(accessLog, "Сканирование сети " + ip + "/24...", "cyan");
        QThread *thread = QThread::create([=]() {
            QProcess proc;
            proc.start("arp-scan", {"--localnet"});
            proc.waitForFinished();
            QByteArray out = proc.readAllStandardOutput();
            emit appendLog(accessLog, QString::fromLocal8Bit(out), "white");
        });
        connect(thread, &QThread::finished, thread, &QThread::deleteLater);
        thread->start();
    }

    // ===== Перехват =====
    void startSniff() {
        if (sniffRunning) return;
        QString iface = interceptIface->currentText().split(" ").first();
        QString filter = interceptFilter->text().trimmed();
        bool ok;
        int count = interceptCount->text().toInt(&ok);
        if (!ok || count <= 0) count = 10;

        sniffRunning = true;
        interceptStartBtn->setEnabled(false);
        interceptStopBtn->setEnabled(true);
        packetTree->clear();
        capturedPackets.clear();
        packetCounter = 0;

        appendLog(interceptLog, "Перехват запущен на " + iface + ", фильтр=" + filter + ", count=" + QString::number(count), "cyan");

        QThread *thread = QThread::create([=]() {
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t *handle = pcap_open_live(iface.toStdString().c_str(), 65536, 1, 1000, errbuf);
            if (!handle) {
                emit appendLog(interceptLog, "Ошибка pcap_open_live: " + QString(errbuf), "red");
                return;
            }
            if (!filter.isEmpty()) {
                struct bpf_program fp;
                if (pcap_compile(handle, &fp, filter.toStdString().c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
                    emit appendLog(interceptLog, "Ошибка фильтра: " + QString(pcap_geterr(handle)), "red");
                    pcap_close(handle);
                    return;
                }
                pcap_setfilter(handle, &fp);
                pcap_freecode(&fp);
            }

            int captured = 0;
            while (captured < count && sniffRunning) {
                struct pcap_pkthdr *header;
                const u_char *packet;
                int res = pcap_next_ex(handle, &header, &packet);
                if (res == 0) continue;
                if (res == -1) break;
                captured++;
                QString src, dst, proto, info;
                struct ether_header *eth = (struct ether_header*)packet;
                if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
                    struct ip *ip = (struct ip*)(packet + 14);
                    src = inet_ntoa(ip->ip_src);
                    dst = inet_ntoa(ip->ip_dst);
                    if (ip->ip_p == IPPROTO_TCP) {
                        proto = "TCP";
                        struct tcphdr *tcp = (struct tcphdr*)(packet + 14 + ip->ip_hl*4);
                        info = QString("Ports: %1->%2 Flags: %3")
                            .arg(ntohs(tcp->th_sport))
                            .arg(ntohs(tcp->th_dport))
                            .arg(ntohs(tcp->th_flags));
                    } else if (ip->ip_p == IPPROTO_UDP) {
                        proto = "UDP";
                        struct udphdr *udp = (struct udphdr*)(packet + 14 + ip->ip_hl*4);
                        info = QString("Ports: %1->%2")
                            .arg(ntohs(udp->uh_sport))
                            .arg(ntohs(udp->uh_dport));
                    } else if (ip->ip_p == IPPROTO_ICMP) {
                        proto = "ICMP";
                    } else {
                        proto = "IP";
                    }
                } else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
                    proto = "ARP";
                    src = dst = "N/A";
                } else {
                    proto = "Non-IP";
                }
                QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
                QByteArray packetData((const char*)packet, header->caplen);
                QMetaObject::invokeMethod(this, "addPacketToTree",
                    Qt::QueuedConnection,
                    Q_ARG(QString, QString::number(captured)),
                    Q_ARG(QString, timestamp),
                    Q_ARG(QString, src),
                    Q_ARG(QString, dst),
                    Q_ARG(QString, proto),
                    Q_ARG(QString, QString::number(header->caplen)),
                    Q_ARG(QString, info),
                    Q_ARG(QByteArray, packetData));
                QThread::msleep(10);
            }
            pcap_close(handle);
            QMetaObject::invokeMethod(this, "stopSniff", Qt::QueuedConnection);
        });
        connect(thread, &QThread::finished, thread, &QThread::deleteLater);
        thread->start();
    }

    void addPacketToTree(const QString &num, const QString &time, const QString &src,
                         const QString &dst, const QString &proto, const QString &len,
                         const QString &info, const QByteArray &data) {
        QTreeWidgetItem *item = new QTreeWidgetItem(packetTree);
        item->setText(0, num);
        item->setText(1, time);
        item->setText(2, src);
        item->setText(3, dst);
        item->setText(4, proto);
        item->setText(5, len);
        item->setText(6, info);
        capturedPackets[data] = item;
    }

    void stopSniff() {
        sniffRunning = false;
        interceptStartBtn->setEnabled(true);
        interceptStopBtn->setEnabled(false);
        appendLog(interceptLog, "Перехват остановлен", "yellow");
    }

    void captureSelected() {
        QTreeWidgetItem *item = packetTree->currentItem();
        if (!item) {
            appendLog(interceptLog, "Сначала выберите пакет", "yellow");
            return;
        }
        for (auto it = capturedPackets.begin(); it != capturedPackets.end(); ++it) {
            if (it->second == item) {
                capturedPacketData = it->first;
                capturedLabel->setText("Захвачен: " + item->text(4) + " пакет №" + item->text(0));
                appendLog(interceptLog, "Пакет захвачен", "green");
                return;
            }
        }
    }

    void editSelected() {
        QTreeWidgetItem *item = packetTree->currentItem();
        if (!item) {
            appendLog(interceptLog, "Сначала выберите пакет", "yellow");
            return;
        }
        QByteArray data;
        for (auto it = capturedPackets.begin(); it != capturedPackets.end(); ++it) {
            if (it->second == item) {
                data = it->first;
                break;
            }
        }
        if (data.isEmpty()) {
            appendLog(interceptLog, "Нет данных пакета", "red");
            return;
        }
        PacketEditorDialog dlg(data, this);
        if (dlg.exec() == QDialog::Accepted) {
            QByteArray edited = dlg.getEditedPacket();
            editedPacketData = edited;
            editedLabel->setText("Отредактирован: " + item->text(4) + " пакет №" + item->text(0));
            appendLog(interceptLog, "Пакет отредактирован", "green");
        }
    }

    void sendCaptured() {
        if (capturedPacketData.isEmpty()) {
            appendLog(interceptLog, "Нет захваченного пакета", "yellow");
            return;
        }
        QString iface = interceptIface->currentText().split(" ").first();
        sendPacket(capturedPacketData, iface);
        appendLog(interceptLog, "Захваченный пакет отправлен на " + iface, "green");
    }

    void sendEdited() {
        if (editedPacketData.isEmpty()) {
            appendLog(interceptLog, "Нет отредактированного пакета", "yellow");
            return;
        }
        QString iface = interceptIface->currentText().split(" ").first();
        sendPacket(editedPacketData, iface);
        appendLog(interceptLog, "Отредактированный пакет отправлен на " + iface, "green");
    }

    void sendPacket(const QByteArray &data, const QString &iface) {
        QThread::create([=]() {
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t *handle = pcap_open_live(iface.toStdString().c_str(), 65536, 1, 1000, errbuf);
            if (!handle) {
                emit appendLog(interceptLog, "Не удалось открыть интерфейс для отправки", "red");
                return;
            }
            if (pcap_sendpacket(handle, (const u_char*)data.data(), data.size()) != 0) {
                emit appendLog(interceptLog, "Ошибка отправки: " + QString(pcap_geterr(handle)), "red");
            }
            pcap_close(handle);
        })->start();
    }

    void clearPackets() {
        packetTree->clear();
        capturedPackets.clear();
        capturedPacketData.clear();
        editedPacketData.clear();
        capturedLabel->setText("Нет");
        editedLabel->setText("Нет");
        appendLog(interceptLog, "Список очищен", "white");
    }

    // ===== Запуск бинарников =====
    void runBinary(const QString &bin, const QStringList &args, LogWidget *log, QPushButton *startBtn, QPushButton *stopBtn) {
        if (attackRunning) return;
        QString binPath = binDir + "/" + bin;
        if (!QFile::exists(binPath)) {
            appendLog(log, "Ошибка: бинарник " + binPath + " не найден", "red");
            QMessageBox::warning(this, "Ошибка", "Бинарник " + binPath + " не найден.\nПроверьте папку bin/.");
            return;
        }
        if (!QFile::permissions(binPath).testFlag(QFile::ExeUser)) {
            QFile::setPermissions(binPath, QFile::permissions(binPath) | QFile::ExeUser);
        }

        appendLog(log, "Запуск: " + binPath + " " + args.join(" "), "cyan");
        attackRunning = true;
        startBtn->setEnabled(false);
        stopBtn->setEnabled(true);
        statusBar()->showMessage("Атака выполняется...");

        QProcess *proc = new QProcess(this);
        connect(proc, &QProcess::readyReadStandardOutput, [=]() {
            QByteArray out = proc->readAllStandardOutput();
            appendLog(log, QString::fromLocal8Bit(out).trimmed(), "white");
        });
        connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), [=](int exitCode, QProcess::ExitStatus status) {
            attackRunning = false;
            startBtn->setEnabled(true);
            stopBtn->setEnabled(false);
            statusBar()->showMessage("Готов");
            proc->deleteLater();
            if (exitCode == 0) {
                appendLog(log, "Завершено успешно", "green");
            } else {
                appendLog(log, "Завершено с ошибкой (код " + QString::number(exitCode) + ")", "red");
            }
        });
        proc->start(binPath, args);
        currentProcess = proc;
    }

    void stopBinary(LogWidget *log) {
        if (!attackRunning || !currentProcess) return;
        currentProcess->terminate();
        appendLog(log, "Отправлен SIGTERM", "yellow");
        statusBar()->showMessage("Остановка...");
        QTimer::singleShot(1000, [=]() {
            if (currentProcess && currentProcess->state() == QProcess::Running) {
                currentProcess->kill();
                appendLog(log, "Отправлен SIGKILL", "red");
            }
        });
    }

    // ===== Вкладки =====
    void createAccessTab() {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(tab);

        QGroupBox *params = new QGroupBox("Базовые функции доступа");
        QGridLayout *grid = new QGridLayout;
        grid->addWidget(new QLabel("IP адрес:"), 0, 0);
        accessIp = new QLineEdit("192.168.1.1");
        grid->addWidget(accessIp, 0, 1);
        grid->addWidget(new QLabel("Интерфейс:"), 1, 0);
        accessIface = new QComboBox;
        for (auto &p : ifaceList) accessIface->addItem(QString::fromStdString(p.first + " (" + p.second + ")"));
        grid->addWidget(accessIface, 1, 1);

        QHBoxLayout *btnLayout = new QHBoxLayout;
        QPushButton *pingBtn = new QPushButton("ICMP Ping");
        connect(pingBtn, &QPushButton::clicked, this, &MainWindow::onPing);
        btnLayout->addWidget(pingBtn);
        QPushButton *scanBtn = new QPushButton("Port Scan");
        connect(scanBtn, &QPushButton::clicked, this, &MainWindow::onPortScan);
        btnLayout->addWidget(scanBtn);
        QPushButton *traceBtn = new QPushButton("Traceroute");
        connect(traceBtn, &QPushButton::clicked, this, &MainWindow::onTraceroute);
        btnLayout->addWidget(traceBtn);
        QPushButton *routeBtn = new QPushButton("Таблица маршрутизации");
        connect(routeBtn, &QPushButton::clicked, this, &MainWindow::onRoute);
        btnLayout->addWidget(routeBtn);
        QPushButton *adapterBtn = new QPushButton("Сетевые адаптеры");
        connect(adapterBtn, &QPushButton::clicked, this, &MainWindow::onAdapters);
        btnLayout->addWidget(adapterBtn);
        QPushButton *netScanBtn = new QPushButton("Сканировать сеть");
        connect(netScanBtn, &QPushButton::clicked, this, &MainWindow::onNetScan);
        btnLayout->addWidget(netScanBtn);
        grid->addLayout(btnLayout, 2, 0, 1, 2);
        params->setLayout(grid);
        layout->addWidget(params);

        QGroupBox *outGroup = new QGroupBox("Результаты");
        QVBoxLayout *outLayout = new QVBoxLayout;
        accessLog = new LogWidget;
        outLayout->addWidget(accessLog);
        outGroup->setLayout(outLayout);
        layout->addWidget(outGroup);

        QPushButton *saveBtn = new QPushButton("Сохранить лог");
        connect(saveBtn, &QPushButton::clicked, [=]() {
            QString fileName = QFileDialog::getSaveFileName(this, "Сохранить лог", "log.txt", "*.txt");
            if (!fileName.isEmpty()) {
                QFile file(fileName);
                if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                    file.write(accessLog->toPlainText().toUtf8());
                    file.close();
                }
            }
        });
        layout->addWidget(saveBtn);

        tabWidget->addTab(tab, "Доступ");
    }

    void createInterceptTab() {
        QWidget *tab = new QWidget;
        QHBoxLayout *mainLayout = new QHBoxLayout(tab);

        QVBoxLayout *leftLayout = new QVBoxLayout;
        QGroupBox *params = new QGroupBox("Параметры перехвата");
        QGridLayout *grid = new QGridLayout;
        grid->addWidget(new QLabel("Интерфейс:"), 0, 0);
        interceptIface = new QComboBox;
        for (auto &p : ifaceList) interceptIface->addItem(QString::fromStdString(p.first + " (" + p.second + ")"));
        grid->addWidget(interceptIface, 0, 1);
        grid->addWidget(new QLabel("Фильтр:"), 1, 0);
        interceptFilter = new QLineEdit;
        grid->addWidget(interceptFilter, 1, 1);
        grid->addWidget(new QLabel("Кол-во пакетов:"), 2, 0);
        interceptCount = new QLineEdit("10");
        grid->addWidget(interceptCount, 2, 1);
        QHBoxLayout *btnLayout = new QHBoxLayout;
        interceptStartBtn = new QPushButton("Начать перехват");
        connect(interceptStartBtn, &QPushButton::clicked, this, &MainWindow::startSniff);
        btnLayout->addWidget(interceptStartBtn);
        interceptStopBtn = new QPushButton("Остановить");
        connect(interceptStopBtn, &QPushButton::clicked, this, &MainWindow::stopSniff);
        interceptStopBtn->setEnabled(false);
        btnLayout->addWidget(interceptStopBtn);
        QPushButton *captureBtn = new QPushButton("Захватить выбранный");
        connect(captureBtn, &QPushButton::clicked, this, &MainWindow::captureSelected);
        btnLayout->addWidget(captureBtn);
        QPushButton *editBtn = new QPushButton("Редактировать");
        connect(editBtn, &QPushButton::clicked, this, &MainWindow::editSelected);
        btnLayout->addWidget(editBtn);
        grid->addLayout(btnLayout, 3, 0, 1, 2);
        params->setLayout(grid);
        leftLayout->addWidget(params);

        QGroupBox *treeGroup = new QGroupBox("Перехваченные пакеты");
        QVBoxLayout *treeLayout = new QVBoxLayout;
        packetTree = new QTreeWidget;
        packetTree->setHeaderLabels({"№", "Время", "Источник", "Назначение", "Протокол", "Длина", "Информация"});
        packetTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
        treeLayout->addWidget(packetTree);
        treeGroup->setLayout(treeLayout);
        leftLayout->addWidget(treeGroup);
        mainLayout->addLayout(leftLayout, 2);

        QVBoxLayout *rightLayout = new QVBoxLayout;
        QGroupBox *controlGroup = new QGroupBox("Управление пакетами");
        QFormLayout *form = new QFormLayout;
        form->addRow("Захваченный:", capturedLabel = new QLabel("Нет"));
        form->addRow("Отредактированный:", editedLabel = new QLabel("Нет"));
        QPushButton *sendCapturedBtn = new QPushButton("Отправить захваченный");
        connect(sendCapturedBtn, &QPushButton::clicked, this, &MainWindow::sendCaptured);
        form->addRow(sendCapturedBtn);
        QPushButton *sendEditedBtn = new QPushButton("Отправить отредактированный");
        connect(sendEditedBtn, &QPushButton::clicked, this, &MainWindow::sendEdited);
        form->addRow(sendEditedBtn);
        QPushButton *clearBtn = new QPushButton("Очистить список");
        connect(clearBtn, &QPushButton::clicked, this, &MainWindow::clearPackets);
        form->addRow(clearBtn);
        controlGroup->setLayout(form);
        rightLayout->addWidget(controlGroup);

        QGroupBox *logGroup = new QGroupBox("Лог перехвата");
        QVBoxLayout *logLayout = new QVBoxLayout;
        interceptLog = new LogWidget;
        logLayout->addWidget(interceptLog);
        logGroup->setLayout(logLayout);
        rightLayout->addWidget(logGroup);
        mainLayout->addLayout(rightLayout, 1);

        tabWidget->addTab(tab, "Перехват");
    }

    void createDhcpTab() {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(tab);
        QGroupBox *params = new QGroupBox("Параметры DHCP Starvation");
        QGridLayout *grid = new QGridLayout;
        grid->addWidget(new QLabel("Интерфейс:"), 0, 0);
        dhcpIface = new QComboBox;
        for (auto &p : ifaceList) dhcpIface->addItem(QString::fromStdString(p.first + " (" + p.second + ")"));
        grid->addWidget(dhcpIface, 0, 1);
        grid->addWidget(new QLabel("Размер пула:"), 1, 0);
        dhcpPool = new QLineEdit("254");
        grid->addWidget(dhcpPool, 1, 1);
        grid->addWidget(new QLabel("Кол-во запросов:"), 2, 0);
        dhcpCount = new QLineEdit("1000");
        grid->addWidget(dhcpCount, 2, 1);
        grid->addWidget(new QLabel("Задержка (сек):"), 3, 0);
        dhcpDelay = new QLineEdit("0.05");
        grid->addWidget(dhcpDelay, 3, 1);
        params->setLayout(grid);
        layout->addWidget(params);

        QHBoxLayout *btnLayout = new QHBoxLayout;
        dhcpStartBtn = new QPushButton("Начать DHCP Starvation");
        connect(dhcpStartBtn, &QPushButton::clicked, [=]() {
            QStringList args = {dhcpIface->currentText().split(" ").first(),
                                dhcpCount->text(), dhcpDelay->text()};
            runBinary("dhcp_starvation", args, dhcpLog, dhcpStartBtn, dhcpStopBtn);
        });
        btnLayout->addWidget(dhcpStartBtn);
        dhcpStopBtn = new QPushButton("Остановить");
        dhcpStopBtn->setEnabled(false);
        connect(dhcpStopBtn, &QPushButton::clicked, [=]() {
            stopBinary(dhcpLog);
        });
        btnLayout->addWidget(dhcpStopBtn);
        layout->addLayout(btnLayout);

        QGroupBox *stats = new QGroupBox("Статистика");
        QFormLayout *statsLayout = new QFormLayout;
        statsLayout->addRow("Статус:", new QLabel("⏸ Ожидание..."));
        statsLayout->addRow("Отправлено:", new QLabel("0"));
        statsLayout->addRow("Скорость:", new QLabel("0"));
        stats->setLayout(statsLayout);
        layout->addWidget(stats);

        dhcpLog = new LogWidget;
        layout->addWidget(dhcpLog);

        tabWidget->addTab(tab, "DHCP Starvation");
    }

    void createArpTab() {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(tab);
        QGroupBox *params = new QGroupBox("Параметры ARP Spoofing");
        QGridLayout *grid = new QGridLayout;
        grid->addWidget(new QLabel("Интерфейс:"), 0, 0);
        arpIface = new QComboBox;
        for (auto &p : ifaceList) arpIface->addItem(QString::fromStdString(p.first + " (" + p.second + ")"));
        grid->addWidget(arpIface, 0, 1);
        grid->addWidget(new QLabel("IP цели:"), 1, 0);
        arpTarget = new QLineEdit("192.168.1.2");
        grid->addWidget(arpTarget, 1, 1);
        grid->addWidget(new QLabel("IP шлюза:"), 2, 0);
        arpGateway = new QLineEdit("192.168.1.1");
        grid->addWidget(arpGateway, 2, 1);
        grid->addWidget(new QLabel("Интервал (сек):"), 3, 0);
        arpInterval = new QLineEdit("2");
        grid->addWidget(arpInterval, 3, 1);
        params->setLayout(grid);
        layout->addWidget(params);

        QHBoxLayout *btnLayout = new QHBoxLayout;
        arpStartBtn = new QPushButton("Начать ARP Spoofing");
        connect(arpStartBtn, &QPushButton::clicked, [=]() {
            QStringList args = {arpIface->currentText().split(" ").first(),
                                arpTarget->text(), arpGateway->text(), arpInterval->text()};
            runBinary("ARPspoof", args, arpLog, arpStartBtn, arpStopBtn);
        });
        btnLayout->addWidget(arpStartBtn);
        arpStopBtn = new QPushButton("Остановить");
        arpStopBtn->setEnabled(false);
        connect(arpStopBtn, &QPushButton::clicked, [=]() {
            stopBinary(arpLog);
        });
        btnLayout->addWidget(arpStopBtn);
        layout->addLayout(btnLayout);

        arpLog = new LogWidget;
        layout->addWidget(arpLog);

        tabWidget->addTab(tab, "ARP Spoofing");
    }

    void createDosTab() {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(tab);
        QGroupBox *params = new QGroupBox("Параметры DoS атаки");
        QGridLayout *grid = new QGridLayout;
        grid->addWidget(new QLabel("IP адрес:"), 0, 0);
        dosIp = new QLineEdit("192.168.1.1");
        grid->addWidget(dosIp, 0, 1);
        grid->addWidget(new QLabel("Протокол:"), 1, 0);
        dosProto = new QComboBox;
        dosProto->addItems({"TCP","UDP","ICMP","ARP"});
        grid->addWidget(dosProto, 1, 1);
        grid->addWidget(new QLabel("Порт:"), 2, 0);
        dosPort = new QLineEdit("80");
        grid->addWidget(dosPort, 2, 1);
        grid->addWidget(new QLabel("Размер пакета:"), 3, 0);
        dosSize = new QLineEdit("1024");
        grid->addWidget(dosSize, 3, 1);
        grid->addWidget(new QLabel("MAC назначения:"), 4, 0);
        dosMac = new QLineEdit("ff:ff:ff:ff:ff:ff");
        grid->addWidget(dosMac, 4, 1);
        grid->addWidget(new QLabel("Время (сек):"), 5, 0);
        dosDuration = new QLineEdit("60");
        grid->addWidget(dosDuration, 5, 1);
        grid->addWidget(new QLabel("Интерфейс:"), 6, 0);
        dosIface = new QComboBox;
        for (auto &p : ifaceList) dosIface->addItem(QString::fromStdString(p.first + " (" + p.second + ")"));
        grid->addWidget(dosIface, 6, 1);
        params->setLayout(grid);
        layout->addWidget(params);

        QHBoxLayout *btnLayout = new QHBoxLayout;
        dosStartBtn = new QPushButton("Начать DoS атаку");
        connect(dosStartBtn, &QPushButton::clicked, [=]() {
            QString proto = dosProto->currentText().toLower();
            QString bin;
            if (proto == "tcp") bin = "NPtcpT";
            else if (proto == "udp") bin = "NPudpT";
            else if (proto == "icmp") bin = "NPicmpT";
            else bin = "NParpT";
            QString iface = dosIface->currentText().split(" ").first();
            QString srcIp = ifaceList[0].second.c_str();
            QStringList args = {srcIp, dosIp->text(), dosPort->text(), "4", dosDuration->text()};
            runBinary(bin, args, dosLog, dosStartBtn, dosStopBtn);
        });
        btnLayout->addWidget(dosStartBtn);
        dosStopBtn = new QPushButton("Остановить");
        dosStopBtn->setEnabled(false);
        connect(dosStopBtn, &QPushButton::clicked, [=]() {
            stopBinary(dosLog);
        });
        btnLayout->addWidget(dosStopBtn);
        layout->addLayout(btnLayout);

        dosLog = new LogWidget;
        layout->addWidget(dosLog);

        tabWidget->addTab(tab, "DoS атака");
    }

    void createDnsTab() {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(tab);
        QGroupBox *params = new QGroupBox("Параметры DNS Spoofing");
        QGridLayout *grid = new QGridLayout;
        grid->addWidget(new QLabel("Интерфейс:"), 0, 0);
        dnsIface = new QComboBox;
        for (auto &p : ifaceList) dnsIface->addItem(QString::fromStdString(p.first + " (" + p.second + ")"));
        grid->addWidget(dnsIface, 0, 1);
        grid->addWidget(new QLabel("TTL (сек):"), 1, 0);
        dnsTtl = new QLineEdit("5");
        grid->addWidget(dnsTtl, 1, 1);
        params->setLayout(grid);
        layout->addWidget(params);

        QGroupBox *rulesGroup = new QGroupBox("Правила подмены");
        QVBoxLayout *rulesLayout = new QVBoxLayout;
        dnsRulesTree = new QTreeWidget;
        dnsRulesTree->setHeaderLabels({"Домен", "IP"});
        rulesLayout->addWidget(dnsRulesTree);
        QHBoxLayout *addLayout = new QHBoxLayout;
        QLineEdit *domEdit = new QLineEdit;
        QLineEdit *ipEdit = new QLineEdit;
        addLayout->addWidget(new QLabel("Домен:"));
        addLayout->addWidget(domEdit);
        addLayout->addWidget(new QLabel("IP:"));
        addLayout->addWidget(ipEdit);
        QPushButton *addBtn = new QPushButton("Добавить");
        connect(addBtn, &QPushButton::clicked, [=]() {
            QString dom = domEdit->text().trimmed();
            QString ip = ipEdit->text().trimmed();
            if (dom.isEmpty() || ip.isEmpty()) return;
            QTreeWidgetItem *item = new QTreeWidgetItem(dnsRulesTree);
            item->setText(0, dom);
            item->setText(1, ip);
            domEdit->clear();
            ipEdit->clear();
        });
        addLayout->addWidget(addBtn);
        rulesLayout->addLayout(addLayout);
        rulesGroup->setLayout(rulesLayout);
        layout->addWidget(rulesGroup);

        QHBoxLayout *btnLayout = new QHBoxLayout;
        dnsStartBtn = new QPushButton("Начать DNS Spoofing");
        connect(dnsStartBtn, &QPushButton::clicked, [=]() {
            QTemporaryFile tempFile;
            if (!tempFile.open()) {
                appendLog(dnsLog, "Не удалось создать временный файл", "red");
                return;
            }
            for (int i = 0; i < dnsRulesTree->topLevelItemCount(); ++i) {
                QTreeWidgetItem *item = dnsRulesTree->topLevelItem(i);
                tempFile.write(QString("%1 %2\n").arg(item->text(1), item->text(0)).toUtf8());
            }
            tempFile.close();
            QStringList args = {"-i", dnsIface->currentText().split(" ").first(), "-f", tempFile.fileName()};
            runBinary("dnsspoof", args, dnsLog, dnsStartBtn, dnsStopBtn);
        });
        btnLayout->addWidget(dnsStartBtn);
        dnsStopBtn = new QPushButton("Остановить");
        dnsStopBtn->setEnabled(false);
        connect(dnsStopBtn, &QPushButton::clicked, [=]() {
            stopBinary(dnsLog);
        });
        btnLayout->addWidget(dnsStopBtn);
        layout->addLayout(btnLayout);

        dnsLog = new LogWidget;
        layout->addWidget(dnsLog);

        tabWidget->addTab(tab, "DNS Spoofing");
    }

    void createMacTab() {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(tab);
        QGroupBox *params = new QGroupBox("Параметры MAC flood");
        QGridLayout *grid = new QGridLayout;
        grid->addWidget(new QLabel("Интерфейс:"), 0, 0);
        macIface = new QComboBox;
        for (auto &p : ifaceList) macIface->addItem(QString::fromStdString(p.first + " (" + p.second + ")"));
        grid->addWidget(macIface, 0, 1);
        grid->addWidget(new QLabel("Время (сек):"), 1, 0);
        macDuration = new QLineEdit("60");
        grid->addWidget(macDuration, 1, 1);
        grid->addWidget(new QLabel("MAC назначения:"), 2, 0);
        macDst = new QLineEdit("ff:ff:ff:ff:ff:ff");
        grid->addWidget(macDst, 2, 1);
        params->setLayout(grid);
        layout->addWidget(params);

        QHBoxLayout *btnLayout = new QHBoxLayout;
        macStartBtn = new QPushButton("Начать MAC flood");
        connect(macStartBtn, &QPushButton::clicked, [=]() {
            appendLog(macLog, "Бинарник NPmac-aT не реализован для Linux", "red");
        });
        btnLayout->addWidget(macStartBtn);
        macStopBtn = new QPushButton("Остановить");
        macStopBtn->setEnabled(false);
        btnLayout->addWidget(macStopBtn);
        layout->addLayout(btnLayout);

        macLog = new LogWidget;
        layout->addWidget(macLog);

        tabWidget->addTab(tab, "MAC flood");
    }

    void createSettingsTab() {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(tab);
        QHBoxLayout *hbox = new QHBoxLayout;
        hbox->addWidget(new QLabel("Папка с бинарниками:"));
        binDirEdit = new QLineEdit(binDir);
        hbox->addWidget(binDirEdit);
        QPushButton *browseBtn = new QPushButton("Обзор...");
        connect(browseBtn, &QPushButton::clicked, [=]() {
            QString dir = QFileDialog::getExistingDirectory(this, "Выберите папку bin", binDir);
            if (!dir.isEmpty()) {
                binDir = dir;
                binDirEdit->setText(binDir);
            }
        });
        hbox->addWidget(browseBtn);
        layout->addLayout(hbox);

        QLabel *info = new QLabel("Требуемые бинарники: NPtcpT, NPudpT, NPicmpT, NParpT, ARPspoof, dnsspoof, dhcp_starvation");
        info->setWordWrap(true);
        layout->addWidget(info);

        tabWidget->addTab(tab, "Настройки");
    }

private:
    QTabWidget *tabWidget;
    std::vector<std::pair<std::string, std::string>> ifaceList;
    QString binDir = QDir::homePath() + "/Проекты/bin";
    bool attackRunning = false;
    QProcess *currentProcess = nullptr;

    QLineEdit *accessIp;
    QComboBox *accessIface;
    LogWidget *accessLog;

    QComboBox *interceptIface;
    QLineEdit *interceptFilter, *interceptCount;
    QPushButton *interceptStartBtn, *interceptStopBtn;
    QTreeWidget *packetTree;
    LogWidget *interceptLog;
    QLabel *capturedLabel, *editedLabel;
    QByteArray capturedPacketData, editedPacketData;
    std::map<QByteArray, QTreeWidgetItem*> capturedPackets;
    int packetCounter = 0;
    bool sniffRunning = false;

    QComboBox *dhcpIface;
    QLineEdit *dhcpPool, *dhcpCount, *dhcpDelay;
    QPushButton *dhcpStartBtn, *dhcpStopBtn;
    LogWidget *dhcpLog;

    QComboBox *arpIface;
    QLineEdit *arpTarget, *arpGateway, *arpInterval;
    QPushButton *arpStartBtn, *arpStopBtn;
    LogWidget *arpLog;

    QLineEdit *dosIp, *dosPort, *dosSize, *dosMac, *dosDuration;
    QComboBox *dosProto, *dosIface;
    QPushButton *dosStartBtn, *dosStopBtn;
    LogWidget *dosLog;

    QComboBox *dnsIface;
    QLineEdit *dnsTtl;
    QTreeWidget *dnsRulesTree;
    QPushButton *dnsStartBtn, *dnsStopBtn;
    LogWidget *dnsLog;

    QComboBox *macIface;
    QLineEdit *macDuration, *macDst;
    QPushButton *macStartBtn, *macStopBtn;
    LogWidget *macLog;

    QLineEdit *binDirEdit;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    MainWindow w;
    w.show();
    return app.exec();
}

#include "main.moc"