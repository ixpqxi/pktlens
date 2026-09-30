#ifndef PACP_MAIN_WINDOW_H
#define PACP_MAIN_WINDOW_H

#include "capture_controller.h"
#include "packet_table_model.h"

#include <QMainWindow>

class QCheckBox;
class QComboBox;
class QCloseEvent;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QSortFilterProxyModel;
class QTableView;
class QToolButton;
class QTimer;

class MainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override = default;

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    void buildUi();
    void applyStyle();
    void setCaptureUiState(bool active);
    void updateDeviceStatus();
    void showPacket(const QModelIndex &proxyIndex);
    void onCaptureToggled(bool active);
    void onPacketReady(PacketPtr packet);
    void onStatusTick();
    void clearPackets();

    CaptureController *capture_ = nullptr;
    PacketTableModel *packetModel_ = nullptr;
    QSortFilterProxyModel *sortModel_ = nullptr;

    QComboBox *deviceCombo_ = nullptr;
    QLineEdit *filterEdit_ = nullptr;
    QToolButton *captureButton_ = nullptr;
    QToolButton *clearButton_ = nullptr;
    QCheckBox *autoScroll_ = nullptr;
    QTableView *packetTable_ = nullptr;
    QPlainTextEdit *detailsView_ = nullptr;
    QLabel *deviceStatus_ = nullptr;
    QLabel *packetStatus_ = nullptr;
    QLabel *dropStatus_ = nullptr;
    QTimer *statusTimer_ = nullptr;
};

#endif
