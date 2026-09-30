#include "capture_controller.h"

#include <QByteArray>
#include <QMetaType>

CaptureController::CaptureController(QObject *parent)
    : QObject(parent)
{
    GError *error = nullptr;

    qRegisterMetaType<PacketPtr>("PacketPtr");
    devices_ = capture_list_devices(&error);
    if (error != nullptr) {
        initializationError_ = QString::fromUtf8(error->message);
        g_clear_error(&error);
    }
    session_ = capture_session_new(&CaptureController::captureCallback, this);
}

CaptureController::~CaptureController()
{
    acceptingPackets_.store(false, std::memory_order_release);
    capture_session_free(session_);
    capture_devices_free(devices_);
}

int CaptureController::deviceCount() const
{
    return devices_ != nullptr ? static_cast<int>(devices_->len) : 0;
}

const CaptureDevice *CaptureController::deviceAt(int index) const
{
    if (devices_ == nullptr || index < 0 ||
        static_cast<guint>(index) >= devices_->len) {
        return nullptr;
    }
    return static_cast<const CaptureDevice *>(
        g_ptr_array_index(devices_, static_cast<guint>(index)));
}

QString CaptureController::deviceDescription(int index) const
{
    const CaptureDevice *device = deviceAt(index);
    return device != nullptr
        ? QString::fromUtf8(device->description)
        : QString();
}

QString CaptureController::deviceAddress(int index) const
{
    const CaptureDevice *device = deviceAt(index);
    return device != nullptr ? QString::fromUtf8(device->address) : QString();
}

QString CaptureController::deviceNetmask(int index) const
{
    const CaptureDevice *device = deviceAt(index);
    return device != nullptr ? QString::fromUtf8(device->netmask) : QString();
}

QString CaptureController::initializationError() const
{
    return initializationError_;
}

bool CaptureController::start(int deviceIndex,
                              const QString &filter,
                              QString *error)
{
    const CaptureDevice *device = deviceAt(deviceIndex);
    QByteArray encodedFilter;
    GError *captureError = nullptr;

    if (session_ == nullptr || device == nullptr) {
        if (error != nullptr) {
            *error = initializationError_.isEmpty()
                ? QStringLiteral("No capture device is selected.")
                : initializationError_;
        }
        return false;
    }

    encodedFilter = filter.toUtf8();
    acceptingPackets_.store(true, std::memory_order_release);
    if (!capture_session_start(session_,
                               device,
                               encodedFilter.constData(),
                               &captureError)) {
        acceptingPackets_.store(false, std::memory_order_release);
        if (error != nullptr) {
            *error = captureError != nullptr
                ? QString::fromUtf8(captureError->message)
                : QStringLiteral("Unable to start capture.");
        }
        g_clear_error(&captureError);
        return false;
    }
    return true;
}

void CaptureController::stop()
{
    acceptingPackets_.store(false, std::memory_order_release);
    capture_session_stop(session_);
}

bool CaptureController::isRunning() const
{
    return capture_session_is_running(session_) != FALSE;
}

QString CaptureController::lastError() const
{
    return session_ != nullptr
        ? QString::fromUtf8(capture_session_get_error(session_))
        : QString();
}

quint64 CaptureController::takeDroppedCount()
{
    return droppedPackets_.exchange(0, std::memory_order_acq_rel);
}

void CaptureController::packetDelivered()
{
    pendingPackets_.fetch_sub(1, std::memory_order_acq_rel);
}

void CaptureController::captureCallback(const struct pcap_pkthdr *header,
                                        const guint8 *data,
                                        gpointer userData)
{
    auto *controller = static_cast<CaptureController *>(userData);
    if (controller != nullptr) {
        controller->receivePacket(header, data);
    }
}

void CaptureController::receivePacket(const struct pcap_pkthdr *header,
                                      const guint8 *data)
{
    PacketRecord *record;
    int pending;

    if (header == nullptr || data == nullptr ||
        !acceptingPackets_.load(std::memory_order_acquire)) {
        return;
    }

    pending = pendingPackets_.fetch_add(1, std::memory_order_acq_rel);
    if (pending >= MaxPendingPackets) {
        pendingPackets_.fetch_sub(1, std::memory_order_acq_rel);
        droppedPackets_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    record = packet_record_new(
        nextPacketId_.fetch_add(1, std::memory_order_relaxed) + 1,
        static_cast<gint64>(header->ts.tv_sec),
        static_cast<gint64>(header->ts.tv_usec),
        header->len,
        header->caplen,
        data);
    if (record == nullptr) {
        pendingPackets_.fetch_sub(1, std::memory_order_acq_rel);
        droppedPackets_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    emit packetReady(PacketPtr(record, &packet_record_free));
}
