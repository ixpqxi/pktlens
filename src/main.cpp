#include "main_window.h"

#include <QApplication>
#include <QStyleFactory>

int main(int argc, char **argv)
{
    QApplication application(argc, argv);
    application.setApplicationName(QStringLiteral("PACP"));
    application.setApplicationVersion(QStringLiteral("2.0"));
    application.setOrganizationName(QStringLiteral("PACP"));
    application.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));

    MainWindow window;
    window.show();
    return application.exec();
}
