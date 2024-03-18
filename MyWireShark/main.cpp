#include "MyWireShark.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MyWireShark w;
    w.show();
    return a.exec();
}
