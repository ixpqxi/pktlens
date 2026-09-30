#ifndef PACP_CAPTURE_CONTROLLER_H
#define PACP_CAPTURE_CONTROLLER_H

#include "capture.h"
#include "packet.h"

#include <QObject>
#include <QString>

#include <atomic>
#include <memory>

using PacketPtr = std::shared_ptr<PacketRecord>;
Q_DECLARE_METATYPE(PacketPtr)

class CaptureController final : public QObject
{
    Q_OBJECT

public:
    explicit CaptureController(QObject *parent = nullptr);
    ~CaptureController() override;

    int deviceCount() const;
    QString deviceDescription(int index) const;
    QString deviceAddress(int index) const;
    QString deviceNetmask(int index) const;
    QString initializationError() const;

    bool start(int deviceIndex, const QString &filter, QString *error);
    void stop();
    bool isRunning() const;
    QString lastError() const;

    quint64 takeDroppedCount();
    void packetDelivered();

signals:
    void packetReady(PacketPtr packet);

private:
    static void captureCallback(const struct pcap_pkthdr *header,
                                const guint8 *data,
                                gpointer userData);
    void receivePacket(const struct pcap_pkthdr *header, const guint8 *data);
    const CaptureDevice *deviceAt(int index) const;

    static constexpr int MaxPendingPackets = 2000;

    GPtrArray *devices_ = nullptr;
    CaptureSession *session_ = nullptr;
    QString initializationError_;
    std::atomic<quint64> nextPacketId_{0};
    std::atomic<quint64> droppedPackets_{0};
    std::atomic<int> pendingPackets_{0};
    std::atomic<bool> acceptingPackets_{false};
};

#endif
