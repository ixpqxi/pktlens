#include "main_window.h"

#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QFontDatabase>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QStatusBar>
#include <QStyle>
#include <QTableView>
#include <QTimer>
#include <QToolBar>
#include <QToolButton>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      capture_(new CaptureController(this)),
      packetModel_(new PacketTableModel(this)),
      sortModel_(new QSortFilterProxyModel(this))
{
    buildUi();
    applyStyle();

    for (int i = 0; i < capture_->deviceCount(); ++i) {
        deviceCombo_->addItem(capture_->deviceDescription(i));
    }
    if (deviceCombo_->count() > 0) {
        deviceCombo_->setCurrentIndex(0);
    }

    connect(deviceCombo_,
            &QComboBox::currentIndexChanged,
            this,
            [this](int) { updateDeviceStatus(); });
    connect(captureButton_,
            &QToolButton::toggled,
            this,
            &MainWindow::onCaptureToggled);
    connect(clearButton_,
            &QToolButton::clicked,
            this,
            &MainWindow::clearPackets);
    connect(packetTable_->selectionModel(),
            &QItemSelectionModel::currentChanged,
            this,
            [this](const QModelIndex &current, const QModelIndex &) {
                showPacket(current);
            });
    connect(capture_,
            &CaptureController::packetReady,
            this,
            &MainWindow::onPacketReady,
            Qt::QueuedConnection);

    statusTimer_ = new QTimer(this);
    statusTimer_->setInterval(250);
    connect(statusTimer_, &QTimer::timeout, this, &MainWindow::onStatusTick);
    statusTimer_->start();

    updateDeviceStatus();
    if (!capture_->initializationError().isEmpty()) {
        statusBar()->showMessage(capture_->initializationError());
    }
}

void MainWindow::buildUi()
{
    auto *toolbar = addToolBar(QStringLiteral("Capture"));
    toolbar->setMovable(false);
    toolbar->setIconSize(QSize(18, 18));
    toolbar->addWidget(new QLabel(QStringLiteral("Interface: "), toolbar));

    deviceCombo_ = new QComboBox(toolbar);
    deviceCombo_->setMinimumWidth(280);
    deviceCombo_->setToolTip(QStringLiteral("Network interface to capture"));
    toolbar->addWidget(deviceCombo_);
    toolbar->addSeparator();

    toolbar->addWidget(new QLabel(QStringLiteral("Filter: "), toolbar));
    filterEdit_ = new QLineEdit(toolbar);
    filterEdit_->setPlaceholderText(QStringLiteral("BPF expression, e.g. tcp port 443"));
    filterEdit_->setMinimumWidth(250);
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setToolTip(QStringLiteral("Berkeley Packet Filter expression"));
    toolbar->addWidget(filterEdit_);
    toolbar->addSeparator();

    captureButton_ = new QToolButton(toolbar);
    captureButton_->setCheckable(true);
    captureButton_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    captureButton_->setToolTip(QStringLiteral("Start or stop packet capture"));
    toolbar->addWidget(captureButton_);

    clearButton_ = new QToolButton(toolbar);
    clearButton_->setText(QStringLiteral("Clear"));
    clearButton_->setIcon(style()->standardIcon(QStyle::SP_DialogDiscardButton));
    clearButton_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    clearButton_->setToolTip(QStringLiteral("Remove all displayed packets"));
    toolbar->addWidget(clearButton_);

    autoScroll_ = new QCheckBox(QStringLiteral("Auto-scroll"), toolbar);
    autoScroll_->setChecked(true);
    toolbar->addWidget(autoScroll_);

    sortModel_->setSourceModel(packetModel_);
    sortModel_->setSortRole(Qt::DisplayRole);
    sortModel_->setDynamicSortFilter(false);

    packetTable_ = new QTableView(this);
    packetTable_->setModel(sortModel_);
    packetTable_->setAlternatingRowColors(true);
    packetTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    packetTable_->setSortingEnabled(true);
    packetTable_->setShowGrid(false);
    packetTable_->setWordWrap(false);
    packetTable_->verticalHeader()->setVisible(false);
    packetTable_->verticalHeader()->setDefaultSectionSize(28);
    packetTable_->horizontalHeader()->setStretchLastSection(true);
    packetTable_->horizontalHeader()->setSectionResizeMode(
        PacketTableModel::NumberColumn, QHeaderView::ResizeToContents);
    packetTable_->horizontalHeader()->setSectionResizeMode(
        PacketTableModel::SourceColumn, QHeaderView::Interactive);
    packetTable_->horizontalHeader()->setSectionResizeMode(
        PacketTableModel::DestinationColumn, QHeaderView::Interactive);
    packetTable_->horizontalHeader()->setSectionResizeMode(
        PacketTableModel::ProtocolColumn, QHeaderView::Stretch);
    packetTable_->setColumnWidth(PacketTableModel::SourceColumn, 170);
    packetTable_->setColumnWidth(PacketTableModel::DestinationColumn, 170);

    detailsView_ = new QPlainTextEdit(this);
    detailsView_->setReadOnly(true);
    detailsView_->setLineWrapMode(QPlainTextEdit::NoWrap);
    detailsView_->setPlaceholderText(
        QStringLiteral("Select a packet to inspect its decoded fields."));
    detailsView_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

    auto *splitter = new QSplitter(Qt::Vertical, this);
    splitter->addWidget(packetTable_);
    splitter->addWidget(detailsView_);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    splitter->setSizes({390, 260});
    setCentralWidget(splitter);

    deviceStatus_ = new QLabel(statusBar());
    packetStatus_ = new QLabel(statusBar());
    dropStatus_ = new QLabel(statusBar());
    statusBar()->addWidget(deviceStatus_, 1);
    statusBar()->addPermanentWidget(packetStatus_);
    statusBar()->addPermanentWidget(dropStatus_);

    setCaptureUiState(false);
    setWindowTitle(QStringLiteral("PACP Packet Capture"));
    resize(1060, 700);
}

void MainWindow::applyStyle()
{
    setStyleSheet(QStringLiteral(
        "QMainWindow { background: #F4F6F8; }"
        "QToolBar { background: #FFFFFF; border: 0; border-bottom: 1px solid #D6DDE2; "
        "spacing: 6px; padding: 6px; }"
        "QLabel { color: #344054; }"
        "QComboBox, QLineEdit { min-height: 27px; padding: 2px 7px; "
        "border: 1px solid #C9D1D9; border-radius: 4px; background: #FFFFFF; }"
        "QComboBox:focus, QLineEdit:focus { border: 1px solid #167C80; }"
        "QToolButton { min-height: 27px; padding: 4px 9px; border: 1px solid #C9D1D9; "
        "border-radius: 4px; background: #FFFFFF; color: #24323A; }"
        "QToolButton:hover { background: #EEF4F4; }"
        "QToolButton[captureActive=\"true\"] { background: #B42318; border-color: #B42318; "
        "color: #FFFFFF; }"
        "QTableView { background: #FFFFFF; alternate-background-color: #F7FAFA; "
        "border: 1px solid #D6DDE2; selection-background-color: #D8EFEC; "
        "selection-color: #102A2B; }"
        "QHeaderView::section { background: #EEF1F3; color: #344054; padding: 6px; "
        "border: 0; border-right: 1px solid #D6DDE2; border-bottom: 1px solid #D6DDE2; }"
        "QPlainTextEdit { background: #172126; color: #E2ECEE; border: 1px solid #0D171B; "
        "selection-background-color: #2D6265; padding: 8px; }"
        "QStatusBar { background: #FFFFFF; color: #475467; border-top: 1px solid #D6DDE2; }"
        "QSplitter::handle { background: #D6DDE2; }"
        "QCheckBox { color: #344054; padding: 2px; }"));
}

void MainWindow::setCaptureUiState(bool active)
{
    captureButton_->setText(active ? QStringLiteral("Stop")
                                   : QStringLiteral("Start"));
    captureButton_->setIcon(style()->standardIcon(
        active ? QStyle::SP_MediaStop : QStyle::SP_MediaPlay));
    captureButton_->setProperty("captureActive", active);
    captureButton_->style()->unpolish(captureButton_);
    captureButton_->style()->polish(captureButton_);
    deviceCombo_->setEnabled(!active);
    filterEdit_->setEnabled(!active);
}

void MainWindow::updateDeviceStatus()
{
    const int index = deviceCombo_->currentIndex();
    if (index < 0 || index >= capture_->deviceCount()) {
        deviceStatus_->setText(QStringLiteral("No capture device available"));
        return;
    }
    deviceStatus_->setText(QStringLiteral("%1  |  Address: %2  |  Netmask: %3")
                               .arg(capture_->deviceDescription(index))
                               .arg(capture_->deviceAddress(index))
                               .arg(capture_->deviceNetmask(index)));
}

void MainWindow::showPacket(const QModelIndex &proxyIndex)
{
    if (!proxyIndex.isValid()) {
        detailsView_->clear();
        return;
    }
    const QModelIndex sourceIndex = sortModel_->mapToSource(proxyIndex);
    const PacketPtr packet = packetModel_->packetAt(sourceIndex.row());
    if (!packet) {
        detailsView_->clear();
        return;
    }
    gchar *details = packet_record_format_details(packet.get());
    detailsView_->setPlainText(details != nullptr
                                   ? QString::fromUtf8(details)
                                   : QString());
    g_free(details);
}

void MainWindow::onCaptureToggled(bool active)
{
    if (active) {
        QString error;
        if (!capture_->start(deviceCombo_->currentIndex(),
                             filterEdit_->text(),
                             &error)) {
            {
                const QSignalBlocker blocker(captureButton_);
                captureButton_->setChecked(false);
            }
            setCaptureUiState(false);
            statusBar()->showMessage(error, 6000);
            return;
        }
        setCaptureUiState(true);
        statusBar()->showMessage(QStringLiteral("Capturing packets..."));
    } else {
        capture_->stop();
        setCaptureUiState(false);
        statusBar()->showMessage(QStringLiteral("Capture stopped"));
    }
}

void MainWindow::onPacketReady(PacketPtr packet)
{
    capture_->packetDelivered();
    packetModel_->appendPacket(std::move(packet));
    packetStatus_->setText(
        QStringLiteral("Packets: %1").arg(packetModel_->rowCount()));
    if (autoScroll_->isChecked()) {
        packetTable_->scrollToBottom();
    }
}

void MainWindow::onStatusTick()
{
    const quint64 dropped = capture_->takeDroppedCount();
    if (dropped > 0) {
        dropStatus_->setText(QStringLiteral("Dropped: %1")
                                 .arg(dropped));
    } else {
        dropStatus_->setText(QStringLiteral("Dropped: 0"));
    }
    packetStatus_->setText(
        QStringLiteral("Packets: %1").arg(packetModel_->rowCount()));

    if (captureButton_->isChecked() && !capture_->isRunning()) {
        const QString error = capture_->lastError();
        capture_->stop();
        {
            const QSignalBlocker blocker(captureButton_);
            captureButton_->setChecked(false);
        }
        setCaptureUiState(false);
        statusBar()->showMessage(
            error.isEmpty() ? QStringLiteral("Capture stopped")
                            : QStringLiteral("Capture stopped: %1").arg(error),
            6000);
    }
}

void MainWindow::clearPackets()
{
    packetModel_->clear();
    detailsView_->clear();
    packetStatus_->setText(QStringLiteral("Packets: 0"));
    statusBar()->showMessage(QStringLiteral("Packet list cleared"), 3000);
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (statusTimer_ != nullptr) {
        statusTimer_->stop();
    }
    capture_->stop();
    event->accept();
}
