#include <QtWidgets>
#include <QtNetwork>
#include <QSslSocket>
#include <QCryptographicHash>
#include <QUuid>

#define BROADCAST_PORT 45454
#define HASH_SYNC_INTERVAL_MS (10 * 60 * 1000)

struct ChatEntry {
    qint64 timestamp;
    QString sender;
    QString text;
};

struct PeerInfo {
    QString nodeId;
    QString address; // ip:port
};

class ChatApp : public QWidget {
    Q_OBJECT

public:
    ChatApp() {
        nodeId = QUuid::createUuid().toString(QUuid::WithoutBraces);
        setWindowTitle("Qt P2P Chat (node " + nodeId.left(8) + ")");

        peersList = new QListWidget;
        chatView = new QTextEdit;
        chatView->setReadOnly(true);
        messageEdit = new QLineEdit;
        ipEdit = new QLineEdit;
        ipEdit->setPlaceholderText("ip:port");

        QPushButton *connectBtn = new QPushButton("Connect");
        QPushButton *sendBtn = new QPushButton("Send");

        QVBoxLayout *layout = new QVBoxLayout(this);
        layout->addWidget(new QLabel("Known Peers"));
        layout->addWidget(peersList);
        layout->addWidget(ipEdit);
        layout->addWidget(connectBtn);
        layout->addWidget(chatView);
        layout->addWidget(messageEdit);
        layout->addWidget(sendBtn);


        connect(peersList, &QListWidget::itemDoubleClicked, this,
                [=](QListWidgetItem *item) {
                    ipEdit->setText(item->text());
                    connectToPeer();
                });

        udpSocket = new QUdpSocket(this);
        udpSocket->bind(QHostAddress::AnyIPv4, BROADCAST_PORT,
                        QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint);
        connect(udpSocket, &QUdpSocket::readyRead,
                this, &ChatApp::readBroadcast);

        broadcastTimer = new QTimer(this);
        connect(broadcastTimer, &QTimer::timeout,
                this, &ChatApp::sendBroadcast);
        broadcastTimer->start(3000);

        tcpServer = new QTcpServer(this);
        tcpServer->listen(QHostAddress::Any, 0); // dynamic port
        chatPort = tcpServer->serverPort();
        connect(tcpServer, &QTcpServer::newConnection,
                this, &ChatApp::incomingConnection);

        connect(connectBtn, &QPushButton::clicked,
                this, &ChatApp::connectToPeer);
        connect(sendBtn, &QPushButton::clicked,
                this, &ChatApp::sendMessage);

        hashSyncTimer = new QTimer(this);
        connect(hashSyncTimer, &QTimer::timeout,
                this, &ChatApp::hashSync);
        hashSyncTimer->start(HASH_SYNC_INTERVAL_MS);

        chatView->append("[NodeID: " + nodeId + "]");
        chatView->append("[Listening on port " + QString::number(chatPort) + "]");
    }

private slots:
    void sendBroadcast() {
        QByteArray msg = "QT_P2P_CHAT:" +
                         nodeId.toUtf8() + ":" +
                         QByteArray::number(chatPort);

        udpSocket->writeDatagram(msg,
                                 QHostAddress::Broadcast,
                                 BROADCAST_PORT);
    }

    void readBroadcast() {
        while (udpSocket->hasPendingDatagrams()) {
            QHostAddress sender;
            QByteArray d;
            d.resize(udpSocket->pendingDatagramSize());
            udpSocket->readDatagram(d.data(), d.size(), &sender);

            QString data = QString::fromUtf8(d);
            auto parts = data.split(":");
            if (parts.size() != 3) continue;

            QString peerNodeId = parts[1];
            quint16 port = parts[2].toUShort();

            if (peerNodeId == nodeId)
                continue; // ignore self

            QString addr = sender.toString() + ":" + QString::number(port);
            if (!knownPeers.contains(addr)) {
                knownPeers.insert(addr);
                peerIds[addr] = peerNodeId;
                peersList->addItem(addr);
            }
        }
    }

    void incomingConnection() {
        QTcpSocket *plain = tcpServer->nextPendingConnection();
        QSslSocket *ssl = new QSslSocket(this);
        ssl->setSocketDescriptor(plain->socketDescriptor());
        plain->deleteLater();

        setupSsl(ssl);
        ssl->startServerEncryption();
        attachSocket(ssl);
    }

    void connectToPeer() {
        if (ipEdit->text().isEmpty()) return;

        auto parts = ipEdit->text().split(":");
        if (parts.size() != 2) return;

        QSslSocket *ssl = new QSslSocket(this);
        setupSsl(ssl);
        ssl->connectToHostEncrypted(parts[0], parts[1].toUShort());
        attachSocket(ssl);
    }

    void sendMessage() {
        if (sockets.isEmpty() || messageEdit->text().isEmpty()) return;

        ChatEntry e;
        e.timestamp = QDateTime::currentSecsSinceEpoch();
        e.sender = "me";
        e.text = messageEdit->text();
        chatLog.append(e);

        for (auto *s : sockets)
            s->write(e.text.toUtf8());

        chatView->append("Me: " + e.text);
        messageEdit->clear();
    }

    void hashSync() {
        auto hash = computeChatHash();
        auto slices = splitHash(hash);

        for (auto *s : sockets) {
            for (int i = 0; i < slices.size(); ++i) {
                s->write("HASHVOTE:" +
                         QByteArray::number(i) + ":" +
                         slices[i].toHex());
            }
        }

        QTimer::singleShot(3000, this, &ChatApp::evaluateConsensus);
    }

private:
    void setupSsl(QSslSocket *sock) {
        QSslConfiguration conf = sock->sslConfiguration();
        conf.setPeerVerifyMode(QSslSocket::VerifyNone);
        conf.setProtocol(QSsl::TlsV1_2OrLater);
        sock->setSslConfiguration(conf);

        connect(sock, SIGNAL(sslErrors(const QList<QSslError>&)),
                sock, SLOT(ignoreSslErrors()));
    }


    void attachSocket(QSslSocket *sock) {
        connect(sock, &QSslSocket::encrypted, this, [=]() {
            sockets.insert(sock);
            chatView->append("[Connected: " +
                             sock->peerAddress().toString() + "]");
            sharePeers(sock);
        });


        connect(sock, &QSslSocket::readyRead, this, [=]() {
            QByteArray data = sock->readAll();

            if (data.startsWith("PEERS:")) {
                auto list = QString::fromUtf8(data.mid(6))
                                .split(",", QString::SkipEmptyParts);
                for (auto &e : list) {
                    auto p = e.split("@");
                    if (p.size() != 2) continue;
                    if (p[0] == nodeId) continue;
                    if (!knownPeers.contains(p[1])) {
                        knownPeers.insert(p[1]);
                        peerIds[p[1]] = p[0];
                        peersList->addItem(p[1]);
                    }
                }
                return;
            }

            if (data.startsWith("HASHVOTE:")) {
                auto parts = data.split(':');
                if (parts.size() == 3)
                    hashVotes[parts[1].toInt()]
                             [QByteArray::fromHex(parts[2])]++;
                return;
            }

            ChatEntry e;
            e.timestamp = QDateTime::currentSecsSinceEpoch();
            e.sender = "peer";
            e.text = QString::fromUtf8(data);
            chatLog.append(e);

            chatView->append("Peer: " + e.text);
        });

        connect(sock, &QSslSocket::disconnected, this, [=]() {
            sockets.remove(sock);
            sock->deleteLater();
        });
    }

    void sharePeers(QSslSocket *sock) {
        QStringList list;
        for (auto it = knownPeers.begin(); it != knownPeers.end(); ++it) {
            list << peerIds[*it] + "@" + *it;
            if (list.size() >= 10) break;
        }
        sock->write("PEERS:" + list.join(",").toUtf8());
    }

    QByteArray computeChatHash() {
        QCryptographicHash h(QCryptographicHash::Sha256);
        for (auto &e : chatLog) {
            h.addData(QByteArray::number(e.timestamp));
            h.addData("|");
            h.addData(e.sender.toUtf8());
            h.addData("|");
            h.addData(e.text.toUtf8());
            h.addData("\n");
        }
        return h.result();
    }

    QVector<QByteArray> splitHash(const QByteArray &h) {
        return { h.mid(0,11), h.mid(11,11), h.mid(22) };
    }

    void evaluateConsensus() {
        auto local = splitHash(computeChatHash());
        int matches = 0;

        for (int i = 0; i < 3; ++i) {
            if (hashVotes[i].isEmpty()) continue;
            QByteArray winner;
            int best = 0;
            for (auto it = hashVotes[i].begin();
                 it != hashVotes[i].end(); ++it) {
                if (it.value() > best) {
                    best = it.value();
                    winner = it.key();
                }
            }
            if (winner == local[i]) matches++;
        }

        chatView->append(matches >= 2
            ? "[Hash consensus OK]"
            : "[WARNING] Chat log desync]");

        hashVotes.clear();
    }

    // UI
    QListWidget *peersList;
    QTextEdit *chatView;
    QLineEdit *messageEdit;
    QLineEdit *ipEdit;

    // Network
    QUdpSocket *udpSocket;
    QTcpServer *tcpServer;
    QTimer *broadcastTimer;
    QTimer *hashSyncTimer;

    // State
    QString nodeId;
    quint16 chatPort;
    QVector<ChatEntry> chatLog;
    QSet<QString> knownPeers;
    QMap<QString, QString> peerIds; // addr -> nodeId
    QSet<QSslSocket*> sockets;
    QMap<int, QMap<QByteArray, int>> hashVotes;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    ChatApp w;
    w.resize(460, 650);
    w.show();
    return app.exec();
}

#include "main.moc"
