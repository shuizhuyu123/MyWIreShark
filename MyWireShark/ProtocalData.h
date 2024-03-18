#pragma once

#include <QObject>
#include <QMetaType>
#include <QQueue>
struct ProtocolItem {
    QStringList data;
    QVector<ProtocolItem> children;

    ProtocolItem(QStringList list) { data = list; }
};

struct ProtocolData {
    QByteArray content;
    QVector<ProtocolItem> items;
};

Q_DECLARE_METATYPE(ProtocolData)
