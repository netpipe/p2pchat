#include <QtWidgets>
#include <QtNetwork>
#include <QCryptographicHash>
#include <QUuid>

static const quint16 BROADCAST_PORT = 45454;
static const char *DISCOVERY_MAGIC = "QT_P2P_CHAT";

struct ChatEntry {
    qint64 ts;
    QString sender;
    QString text;
};

class ChatApp : public QWidget {
    Q_OBJECT
public:
    ChatApp() {
        nodeId = QUuid::createUuid().toString(QUuid::WithoutBraces);
        listenPort = 50000 + (QRandomGenerator::global()->generate() % 10000);

        qDebug() << "[NODE]" << nodeId << "listening on" << listenPort;

        setupUi();
        setupUdp();
        setupTcp();

        broadcastTimer.start(3000);
        connect(&broadcastTimer, &QTimer::timeout, this, &ChatApp::broadcastPresence);
    }

private:
    QString nodeId;
    quint16 listenPort;

    QTextEdit *chatView;
    QLineEdit *input;
    QPushButton *sendBtn;
    QListWidget *peersList;

    QUdpSocket udp;
    QTcpServer tcpServer;
    QSet<QString> knownPeers;
    QSet<QSslSocket*> sockets;

    QVector<ChatEntry> chatLog;
    QTimer broadcastTimer;

    /* ---------- UI ---------- */
    void setupUi() {
        chatView = new QTextEdit;
        chatView->setReadOnly(true);
        input = new QLineEdit;
        sendBtn = new QPushButton("Send");
        peersList = new QListWidget;

        QVBoxLayout *left = new QVBoxLayout;
        left->addWidget(chatView);
        left->addWidget(input);
        left->addWidget(sendBtn);

        QVBoxLayout *right = new QVBoxLayout;
        right->addWidget(new QLabel("Peers"));
        right->addWidget(peersList);

        QHBoxLayout *root = new QHBoxLayout(this);
        root->addLayout(left, 3);
        root->addLayout(right, 1);

        connect(sendBtn, &QPushButton::clicked, this, &ChatApp::sendMessage);
        connect(peersList, &QListWidget::itemDoubleClicked, this,
                [&](QListWidgetItem *it){ connectToPeer(it->text()); });
    }

    /* ---------- UDP DISCOVERY ---------- */
    void setupUdp() {
        udp.bind(BROADCAST_PORT, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint);
        connect(&udp, &QUdpSocket::readyRead, this, &ChatApp::readBroadcast);
    }

    void broadcastPresence() {
        QByteArray msg = QByteArray(DISCOVERY_MAGIC) + ":" +
                         nodeId.toUtf8() + ":" +
                         QByteArray::number(listenPort);
        udp.writeDatagram(msg, QHostAddress::Broadcast, BROADCAST_PORT);
        qDebug() << "[UDP] broadcast";
    }

    void readBroadcast() {
        while (udp.hasPendingDatagrams()) {
            QByteArray d;
            d.resize(udp.pendingDatagramSize());
            QHostAddress sender;
            udp.readDatagram(d.data(), d.size(), &sender);

            auto parts = QString::fromUtf8(d).split(":");
            if (parts.size() != 3) return;
            if (parts[0] != DISCOVERY_MAGIC) return;
            if (parts[1] == nodeId) return;

            QString peer = sender.toString() + ":" + parts[2];
            if (!knownPeers.contains(peer)) {
                knownPeers.insert(peer);
                peersList->addItem(peer);
                qDebug() << "[DISCOVERY]" << peer;
            }
        }
    }

    /* ---------- TCP / TLS ---------- */
    void setupTcp() {
        connect(&tcpServer, &QTcpServer::newConnection, this, &ChatApp::acceptPeer);
        tcpServer.listen(QHostAddress::Any, listenPort);
    }

    void acceptPeer() {
        QTcpSocket *plain = tcpServer.nextPendingConnection();
        if (!plain)
            return;

        QSslSocket *sock = new QSslSocket(this);

        if (!sock->setSocketDescriptor(plain->socketDescriptor())) {
            qDebug() << "[ERROR] Failed to adopt socket";
            plain->deleteLater();
            sock->deleteLater();
            return;
        }

        plain->deleteLater(); // 🔑 THIS IS CRITICAL

        setupSsl(sock);

        connect(sock, &QSslSocket::encrypted, this, [=]{
            qDebug() << "[TLS] inbound encrypted";
            sockets.insert(sock);
            requestSync(sock);
        });

        connect(sock, &QSslSocket::readyRead, this, [=]{
            readSocket(sock);
        });

        connect(sock, &QSslSocket::disconnected, this, [=]{
            qDebug() << "[TLS] peer disconnected";
            sockets.remove(sock);
            sock->deleteLater();
        });

        sock->startServerEncryption();
    }


    void connectToPeer(const QString &peer) {
        auto parts = peer.split(":");
        if (parts.size() != 2) return;

        QSslSocket *sock = new QSslSocket(this);
        setupSsl(sock);

        connect(sock, &QSslSocket::encrypted, this, [=]{
            qDebug() << "[TLS] connected to" << peer;
            sockets.insert(sock);
            requestSync(sock);
        });

        connect(sock, &QSslSocket::readyRead, this, [=]{ readSocket(sock); });
        sock->connectToHostEncrypted(parts[0], parts[1].toUShort());
    }

    void setupSsl(QSslSocket *sock) {
        QSslConfiguration c = sock->sslConfiguration();
        c.setPeerVerifyMode(QSslSocket::VerifyNone);
        c.setProtocol(QSsl::TlsV1_2OrLater);
        sock->setSslConfiguration(c);

        connect(sock, SIGNAL(sslErrors(const QList<QSslError>&)),
                sock, SLOT(ignoreSslErrors()));
    }

    /* ---------- CHAT + SYNC ---------- */
    QByteArray computeHash(const QVector<ChatEntry> &log) {
        QCryptographicHash h(QCryptographicHash::Sha256);
        for (auto &e : log)
            h.addData(QString::number(e.ts).toUtf8() + e.sender.toUtf8() + e.text.toUtf8());
        return h.result();
    }

    void requestSync(QSslSocket *sock) {
        qDebug() << "[SYNC] requesting log";
        sock->write("SYNCREQ\n");
    }

    void readSocket(QSslSocket *sock) {
        while (sock->canReadLine()) {
            QByteArray line = sock->readLine().trimmed();

            if (line == "SYNCREQ") {
                qDebug() << "[SYNC] sending log";
                sock->write("SYNCRESP\n");
                for (auto &e : chatLog) {
                    QJsonObject o;
                    o["ts"] = QString::number(e.ts);
                    o["sender"] = e.sender;
                    o["text"] = e.text;
                    sock->write(QJsonDocument(o).toJson(QJsonDocument::Compact) + "\n");
                }
                sock->write("END\n");
            }
            else if (line == "SYNCRESP") {
                QVector<ChatEntry> newLog;
                while (sock->canReadLine()) {
                    QByteArray l = sock->readLine().trimmed();
                    if (l == "END") break;
                    QJsonObject o = QJsonDocument::fromJson(l).object();
                    newLog.push_back({
                        o["ts"].toString().toLongLong(),
                        o["sender"].toString(),
                        o["text"].toString()
                    });
                }
                chatLog = newLog;
                chatView->clear();
                for (auto &e : chatLog)
                    chatView->append(e.sender + ": " + e.text);
                qDebug() << "[SYNC] log accepted, entries:" << chatLog.size();
            }
            else if (line.startsWith("CHAT:")) {
                auto parts = QString::fromUtf8(line.mid(5)).split("|");
                ChatEntry e { parts[0].toLongLong(), parts[1], parts[2] };
                chatLog.push_back(e);
                chatView->append(e.sender + ": " + e.text);
            }
        }
    }

    void sendMessage() {
        ChatEntry e;
        e.ts = QDateTime::currentMSecsSinceEpoch();
        e.sender = nodeId.left(6);
        e.text = input->text();
        input->clear();

        chatLog.push_back(e);
        chatView->append(e.sender + ": " + e.text);

        QByteArray msg = "CHAT:" +
                         QByteArray::number(e.ts) + "|" +
                         e.sender.toUtf8() + "|" +
                         e.text.toUtf8() + "\n";

        for (auto s : sockets)
            s->write(msg);
    }
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    ChatApp w;
    w.resize(800, 500);
    w.show();
    return app.exec();
}

#include "main.moc"
