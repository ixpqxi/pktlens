#include "packet_table_model.h"

#include <QBrush>
#include <QColor>

PacketTableModel::PacketTableModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

int PacketTableModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : static_cast<int>(packets_.size());
}

int PacketTableModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant PacketTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 ||
        index.row() >= static_cast<int>(packets_.size())) {
        return {};
    }

    const PacketPtr &packet = packets_[static_cast<std::size_t>(index.row())];
    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case NumberColumn:
            return QVariant::fromValue<qulonglong>(
                packet_record_get_id(packet.get()));
        case SourceColumn:
            return QString::fromUtf8(packet_record_get_source(packet.get()));
        case DestinationColumn:
            return QString::fromUtf8(
                packet_record_get_destination(packet.get()));
        case ProtocolColumn:
            return QString::fromUtf8(packet_record_get_protocol(packet.get()));
        default:
            return {};
        }
    }

    if (role == Qt::TextAlignmentRole) {
        return index.column() == NumberColumn
            ? QVariant(Qt::AlignCenter)
            : QVariant(Qt::AlignVCenter | Qt::AlignLeft);
    }
    if (role == Qt::ToolTipRole) {
        const char *warning = packet_record_get_warning(packet.get());
        return warning[0] != '\0' ? QString::fromUtf8(warning) : QVariant();
    }
    if (role == Qt::ForegroundRole &&
        packet_record_get_warning(packet.get())[0] != '\0') {
        return QBrush(QColor(QStringLiteral("#9A3412")));
    }
    return {};
}

QVariant PacketTableModel::headerData(int section,
                                      Qt::Orientation orientation,
                                      int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QAbstractTableModel::headerData(section, orientation, role);
    }

    switch (section) {
    case NumberColumn:
        return QStringLiteral("No.");
    case SourceColumn:
        return QStringLiteral("Source");
    case DestinationColumn:
        return QStringLiteral("Destination");
    case ProtocolColumn:
        return QStringLiteral("Protocol");
    default:
        return {};
    }
}

void PacketTableModel::appendPacket(PacketPtr packet)
{
    if (!packet) {
        return;
    }

    if (packets_.size() >= MaxStoredPackets) {
        beginRemoveRows(QModelIndex(), 0, 0);
        packets_.pop_front();
        endRemoveRows();
    }

    const int row = static_cast<int>(packets_.size());
    beginInsertRows(QModelIndex(), row, row);
    packets_.push_back(std::move(packet));
    endInsertRows();
}

void PacketTableModel::clear()
{
    if (packets_.empty()) {
        return;
    }
    beginResetModel();
    packets_.clear();
    endResetModel();
}

PacketPtr PacketTableModel::packetAt(int row) const
{
    if (row < 0 || row >= static_cast<int>(packets_.size())) {
        return {};
    }
    return packets_[static_cast<std::size_t>(row)];
}
