#ifndef PACP_PACKET_TABLE_MODEL_H
#define PACP_PACKET_TABLE_MODEL_H

#include "capture_controller.h"

#include <QAbstractTableModel>

#include <deque>

class PacketTableModel final : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        NumberColumn,
        SourceColumn,
        DestinationColumn,
        ProtocolColumn,
        ColumnCount
    };

    explicit PacketTableModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index,
                  int role = Qt::DisplayRole) const override;
    QVariant headerData(int section,
                        Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;

    void appendPacket(PacketPtr packet);
    void clear();
    PacketPtr packetAt(int row) const;

private:
    static constexpr int MaxStoredPackets = 10000;
    std::deque<PacketPtr> packets_;
};

#endif
