#include "MyWinshark.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MyWinshark w;
    w.show();
    return a.exec();
}
